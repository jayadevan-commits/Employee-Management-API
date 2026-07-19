/**
 * Login MFA Verify Handler
 * Verifies SOFTWARE_TOKEN_MFA challenge during login and returns Cognito tokens.
 */

import {
  CognitoIdentityProviderClient,
  RespondToAuthChallengeCommand,
} from "@aws-sdk/client-cognito-identity-provider";

import {
  CustomError,
  CognitoError,
} from "/opt/nodejs/utils/error.mjs";

import { wrapHandler } from "/opt/nodejs/utils/lambdaWrapper.mjs";
import MiddlewareExecutor from "/opt/nodejs/utils/middleware.mjs";
import { requestSanitizeMiddleware } from "/opt/nodejs/utils/middleware/requestValidationMiddleware.mjs";

/**
 * @typedef {Object} LoginMfaVerifyPayload
 * @property {string} email
 * @property {string} otp
 * @property {string} session
 */

/**
 * @param {import("../../types/global").ApiGatewayEvent} event
 * @param {import("../../types/global").LambdaContext} context
 */
async function handler(event, context) {
  const { logger } = context;

  await new MiddlewareExecutor(logger)
    .use(requestSanitizeMiddleware())
    .execute(event, context);

  const { email, otp, session } = event.parsedBody;

  logger.info("Starting MFA Login Verification", {
    email,
  });

  const tokens = await verifyMfaChallenge(
    {
      email,
      otp,
      session,
    },
    context
  );

  logger.info("MFA Login Verification Successful", {
    email,
  });

  return {
    data: tokens,
    message: "MFA verification successful",
    extras: {
      requestId: context.awsRequestId,
    },
  };
}

/**
 * Verifies SOFTWARE_TOKEN_MFA challenge with Cognito.
 *
 * @param {LoginMfaVerifyPayload} payload
 * @param {import("../../types/global").LambdaContext} context
 */
async function verifyMfaChallenge(
  { email, otp, session },
  context
) {
  const { logger } = context;

  const cognitoClient = new CognitoIdentityProviderClient({});

  try {
    const response = await cognitoClient.send(
      new RespondToAuthChallengeCommand({
        ClientId: process.env.COGNITO_CLIENT_ID,
        ChallengeName: "SOFTWARE_TOKEN_MFA",
        Session: session,
        ChallengeResponses: {
          USERNAME: email,
          SOFTWARE_TOKEN_MFA_CODE: otp,
        },
      })
    );

    logger.info("Cognito MFA Challenge Verified", {
      email,
    });

    return {
      accessToken: response.AuthenticationResult.AccessToken,
      idToken: response.AuthenticationResult.IdToken,
      refreshToken: response.AuthenticationResult.RefreshToken,
      expiresIn: response.AuthenticationResult.ExpiresIn,
    };
  } catch (error) {
    logger.error("MFA Verification Failed", {
      email,
      error: error.message,
    });

    if (error.name === "CodeMismatchException") {
      throw new CustomError("Invalid verification code", {
        code: "INVALID_OTP",
        details: { email },
      });
    }

    if (error.name === "ExpiredCodeException") {
      throw new CustomError(
        "Verification code expired. Please login again.",
        {
          code: "OTP_EXPIRED",
          details: { email },
        }
      );
    }

    if (error.name === "NotAuthorizedException") {
      throw new CustomError(
        "Session expired. Please login again.",
        {
          code: "SESSION_EXPIRED",
          details: { email },
        }
      );
    }

    if (error.name === "InvalidParameterException") {
      throw new CustomError(
        "Invalid MFA verification request",
        {
          code: "INVALID_PARAMETERS",
          details: { email },
        }
      );
    }

    throw new CognitoError(
      "MFA verification failed",
      {
        code: "COGNITO_MFA_VERIFY_ERROR",
        raw: error,
        meta: { email },
      }
    );
  }
}

export const loginMfaVerify = wrapHandler(handler);