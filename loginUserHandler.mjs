/**
 * Login User Handler
 * Authenticates user credentials via AWS Cognito and returns JWT tokens.
 */

import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  AdminGetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { eq } from "drizzle-orm";
import { db } from "/opt/nodejs/db/connection.mjs";
import { surveyUsers, USER_STATUS } from "/opt/nodejs/db/index.mjs";
import {
  CustomError,
  CognitoError,
  DatabaseError,
} from "/opt/nodejs/utils/error.mjs";
import { wrapHandler } from "/opt/nodejs/utils/lambdaWrapper.mjs";
import MiddlewareExecutor from "/opt/nodejs/utils/middleware.mjs";
import { requestSanitizeMiddleware } from "/opt/nodejs/utils/middleware/requestValidationMiddleware.mjs";

/**
 * @typedef {Object} LoginUserPayload
 * @property {string} email
 * @property {string} password
 */

/**
 * @typedef {Object} CognitoTokens
 * @property {string} accessToken - JWT access token for API authentication
 * @property {string} idToken - JWT ID token containing user claims
 * @property {string} refreshToken - Refresh token to obtain new access tokens
 * @property {number} expiresIn - Token expiration time in seconds
 */

/**
 * @typedef {Object} LoginUserResponse
 * @property {CognitoTokens & { userId: string }} data
 * @property {string} message
 * @property {{ requestId: string }} extras
 */

/**
 * @param {import("../../types/global").ApiGatewayEvent} event
 * @param {import("../../types/global").LambdaContext} context
 * @returns {Promise<LoginUserResponse>}
 */
async function handler(event, context) {
  const { logger } = context;

  // ---- Middleware Execution (sanitization etc) ----
  await new MiddlewareExecutor(logger)
    .use(requestSanitizeMiddleware({ ignoreFields: ["password"] }))
    .execute(event, context);

  const { email, password } = event.parsedBody;

  logger.info("Starting User Login", { email });

  
  let dbUser;
  try {
    const database = await db;
    [dbUser] = await database
      .select({ userId: surveyUsers.userId, userStatus: surveyUsers.userStatus, role: surveyUsers.role })
      .from(surveyUsers)
      .where(eq(surveyUsers.email, email))
      .limit(1);

    if (!dbUser) {
     
      logger.error("Login attempted for email not found in RDS", { email });
      throw new CustomError("Invalid email or password", {
        code: "INVALID_CREDENTIALS",
        details: { email }
      });
    }

    if (dbUser.userStatus !== USER_STATUS.ACTIVE) {
      logger.error("User attempted to login with inactive account", { email, status: dbUser.userStatus });
      throw new CustomError(`Your account is currently ${dbUser.userStatus.toLowerCase()}. Please contact support.`, {
        code: "FORBIDDEN",
        details: { email }
      });
    }
  } catch (error) {
    if (error instanceof CustomError) throw error;
    logger.error("Database query failed during login", { error: error.message, email });
    throw new DatabaseError("Failed to fetch user data during login", {
      code: "DB_READ_ERROR",
      meta: { email, error }
    });
  }

  // ---- Cognito Authentication (only reached if DB validation passed) ----
  const tokens = await authenticateWithCognito({ email, password }, context);

  // user already MFA enabled
  if (tokens.challengeRequired) {
    
    logger.info("MFA Challenge Required", {
      email,
      challengeName: tokens.challengeName,
    });
    return {
      data: {
        challengeRequired: true,
        challengeName: tokens.challengeName,
        session: tokens.session,
      },
      message: "MFA Verification required",
      extras: {
        requestId: context.awsRequestId,
      },
    };
  }

  const mfaSetupRequired = await checkMfaSetupRequired(
    { email, role: dbUser.role },
    context
  );

  logger.info("Login Successful", { email, userId: dbUser.userId, mfaSetupRequired });

  return {
    data: {
      ...tokens,
      userId: dbUser.userId,
      mfaSetupRequired,
    },
    message: "Login successful",
    extras: {
      requestId: context.awsRequestId,
    },
  };
}

/**
 * Checks whether MFA setup is required for the authenticated user role.
 * @param {{ email: string, role: string }} userInfo
 * @param {import("../../types/global").LambdaContext} context
 * @returns {Promise<boolean>}
 */
async function checkMfaSetupRequired({ email, role }, context) {
  const { logger } = context;
  const MFA_REQUIRED_ROLES = ["SUPER_ADMIN", "ORG_ADMIN"];

  if (!role || !MFA_REQUIRED_ROLES.includes(role)) {
    return false;
  }

  try {
    const cognitoClient = new CognitoIdentityProviderClient({});
    const cognitoUser = await cognitoClient.send(
      new AdminGetUserCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: email,
      })
    );

    const userMfaSettings = cognitoUser.UserMFASettingList || [];
    const hasSoftwareTokenMfa = userMfaSettings.includes("SOFTWARE_TOKEN_MFA");

    return !hasSoftwareTokenMfa;
  } catch (error) {
    logger.error("Failed to fetch MFA status", {
      email,
      error: error.message,
    });

    throw new CognitoError("Failed to verify MFA status", {
      code: "COGNITO_MFA_CHECK_FAILED",
      raw: error,
      meta: { email },
    });
  }
}

/**
 * Authenticates user with AWS Cognito
 * @param {LoginUserPayload} credentials
 * @param {import("../../types/global").LambdaContext} context
 * @returns {Promise<CognitoTokens>}
 */
async function authenticateWithCognito({ email, password }, context) {
  const { logger } = context;

  const cognitoClient = new CognitoIdentityProviderClient({});

  logger.info("Calling Cognito InitiateAuth", { email });

  try {
    const response = await cognitoClient.send(
      new InitiateAuthCommand({
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: process.env.COGNITO_CLIENT_ID,
        AuthParameters: {
          USERNAME: email,
          PASSWORD: password,
        },
      })
    );

    logger.info("Cognito Authentication Success", { email });

    if (response.ChallengeName === "SOFTWARE_TOKEN_MFA") {
      
      return {
        challengeRequired: true,
        challengeName: response.ChallengeName,
        session: response.Session,
      };
    }

    return {
      challengeRequired: false,
      accessToken: response.AuthenticationResult.AccessToken,
      idToken: response.AuthenticationResult.IdToken,
      refreshToken: response.AuthenticationResult.RefreshToken,
      expiresIn: response.AuthenticationResult.ExpiresIn,
    };
  } catch (error) {
    logger.error("Cognito Authentication Failed", { error: error.message, email });

    // Handle specific Cognito errors
    if (error.name === "NotAuthorizedException") {
      throw new CustomError("Invalid email or password", {
        code: "INVALID_CREDENTIALS",
        details: { email },
      });
    }

    if (error.name === "UserNotConfirmedException") {
      throw new CustomError("Email not verified. Please verify your email first.", {
        code: "EMAIL_NOT_VERIFIED",
        details: { email },
      });
    }

    if (error.name === "UserNotFoundException") {
      throw new CustomError("Invalid email or password", {
        code: "INVALID_CREDENTIALS",
        details: { email },
      });
    }

    if (error.name === "TooManyRequestsException") {
      throw new CustomError("Too many login attempts. Please try again later.", {
        code: "RATE_LIMIT_EXCEEDED",
        details: { email },
      });
    }

    if (error.name === "InvalidParameterException") {
      throw new CustomError("Invalid login parameters", {
        code: "INVALID_PARAMETERS",
        details: { email },
      });
    }

    // Generic Cognito error
    throw new CognitoError("Authentication failed", {
      code: "COGNITO_AUTH_ERROR",
      raw: error,
      meta: { email },
    });
  }
}

// Wrapped export for Lambda
export const loginUser = wrapHandler(handler);
