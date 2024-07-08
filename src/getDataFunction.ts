import middy from '@middy/core';
import {Configuration} from './tokenValidation/configuration.js';
import {TokenValidationMiddleware} from './tokenValidation/tokenValidationMiddleware.js';

/*
 * The lambda contains normal API logic, which runs after token validation and can use claims
 */
const lambda = async (event: any, context: any) => {

    console.log(event.claims);

    return {
        status: 200,
        body: JSON.stringify({
            message: 'API successfully validated the JWT and verified x509 certificate trust',
        }),
    };
};

/*
 * Insert a middleware class to run before the lambda, to do the token validation work
 */
const handler = middy(lambda).use(new TokenValidationMiddleware(new Configuration()))
export {handler};
