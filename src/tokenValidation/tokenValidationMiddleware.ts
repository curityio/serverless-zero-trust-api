import middy from '@middy/core';
import {Configuration} from './configuration';
import {TokenValidator} from './tokenValidator';
import {TrustChainValidator} from './trustChainValidator';

/*
 * Implement cross cutting concerns for token validation and error handling here
 */
export class TokenValidationMiddleware implements middy.MiddlewareObj<any, any> {

    private readonly _trustChainValidator: TrustChainValidator;
    private readonly _tokenValidator: TokenValidator;

    public constructor(configuration: Configuration) {
        this._trustChainValidator = new TrustChainValidator(configuration);
        this._tokenValidator = new TokenValidator(configuration);
        this._setupCallbacks();
    }

    public async before(request: any): Promise<void> {

        try {

            const [accessTokenJwt, header] = this._tokenValidator.parseToken(request.event.headers.Authorization);

            const tokenSigningPublicKey = await this._trustChainValidator.validate(header);

            request.event.claims = await this._tokenValidator.validate(accessTokenJwt, tokenSigningPublicKey);

        } catch (e) {

            if (e instanceof Error) {
                console.log(`SERVER-ERROR-LOG: ${e.message}`);
            }

            request.response = {
                status: 401,
                body: JSON.stringify({
                    code: 'unauthorized',
                    message: 'Missing, invalid or expired access token',
                }),
            };
        }
    }

    private _setupCallbacks() {
        this.before = this.before.bind(this);
    }
}
