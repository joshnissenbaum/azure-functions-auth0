import jwt from "express-jwt";
const jwksRsa = require("jwks-rsa");
import ArgumentError from "./errors/ArgumentError";

module.exports = options => {
    if (!options || !(options instanceof Object)) {
        throw new ArgumentError("The options must be an object.");
    }

    if (!options.clientId || options.clientId.length === 0) {
        throw new ArgumentError("The Auth0 Client ID has to be provided.");
    }

    if (!options.clientSecret || options.clientSecret.length === 0) {
        throw new ArgumentError("The Auth0 Client Secret has to be provided.");
    }

    if (!options.domain || options.domain.length === 0) {
        throw new ArgumentError("The Auth0 Domain has to be provided.");
    }

    const middleware = jwt({
        secret: jwksRsa.expressJwtSecret({
            cache: true,
            rateLimit: true,
            jwksRequestsPerMinute: 5,
            jwksUri: `https://maddocks.au.auth0.com/.well-known/jwks.json`
        }),
        audience: options.clientId,
        issuer: "https://" + options.domain + "/"
    });

    return next => {
        return (context, req) => {
            middleware(req, null, err => {
                if (err) {
                    context.res = {
                        status: err.status || 500,
                        body: {
                            message: err.message
                        }
                    };

                    return context.done();
                }

                return next(context, req);
            });
        };
    };
};
