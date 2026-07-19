/**
 * MFA Setup Handler
 * Generates Cognito Software Token Secret for MFA enrollment.
 */

import {
    CognitoIdentityProviderClient,
    AssociateSoftwareTokenCommand,
} from "@aws-sdk/client-cognito-identity-provider";

import {
    CustomError,
    CognitoError,
} from "/opt/nodejs/utils/error.mjs";

import {
    wrapHandler,
    safeAwait,
} from "/opt/nodejs/utils/lambdaWrapper.mjs";

import { ROLES } from "/opt/nodejs/utils/rbac.mjs";


/**
 * @param {import("../../types/global").ApiGatewayEvent} event
 * @param {import("../../types/global").LambdaContext} context
 * @param {import("../../types/global").AuthorisedUser} user
 */
async function handler(event, context, user) {
    const { logger } = context;

    if (!user) {
        throw new CustomError("Unauthorized", {
            code: "UNAUTHORIZED",
        });
    }

    logger.info("Starting MFA setup", {
        userId: user.userId,
    });


    const secretCode = await generateMfaSecret(event,context);
    logger.info("MFA secret generated successfully", {
        userId: user.userId,
    });

    return {
        data: {
            secretCode,
        },
        message: "MFA setup initialized successfully",
        extras: {
            requestId: context.awsRequestId,
        },
    };
}

async function generateMfaSecret(event, context) {
    const { logger } = context;

    const authorizationHeader =
        event.headers?.authorization ||
        event.headers?.Authorization;

    const accessToken = authorizationHeader?.replace("Bearer ","" );

    if (!accessToken) {
        throw new CustomError(
            "Access token is required",
            {
                code: "ACCESS_TOKEN_REQUIRED",
            }
        );
    }

    const cognitoClient = new CognitoIdentityProviderClient({});

    const [error, response] = await safeAwait(() =>
        cognitoClient.send(
            new AssociateSoftwareTokenCommand({
                AccessToken: accessToken,
            })
        )
    );

    if (error) {
        logger.error(
            "Failed to associate software token",
            {
                error,
            }
        );

        throw new CognitoError(
            "Failed to initialize MFA setup",
            {
                code: "MFA_SETUP_ERROR",
                raw: error,
            }
        );
    }

    return response.SecretCode;
}

export const setupMfa = wrapHandler(handler);