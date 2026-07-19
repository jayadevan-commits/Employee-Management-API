// handler.js

module.exports.getUserMeTest = async (event) => {
    try {
        const claims = event.requestContext?.authorizer?.claims || {};

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: "Authenticated successfully",
                user: {
                    sub: claims.sub,
                    email: claims.email,
                    username: claims["cognito:username"]
                }
            })
        };
    } catch (error) {
        console.error("Error:", error);

        return {
            statusCode: 500,
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: "Internal Server Error"
            })
        };
    }
};