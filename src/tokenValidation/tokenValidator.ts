import {KeyObject} from 'crypto';
import {JWSHeaderParameters, KeyLike, JWTPayload, jwtVerify, decodeProtectedHeader} from 'jose';
import {Configuration} from './configuration.js';

export class TokenValidator {

    private readonly _configuration: Configuration;

    public constructor(configuration: Configuration) {
        this._configuration = configuration;
    }

    /*
     * Read the JWT and its header details
     */
    public parseToken(authorizationHeader: string): [string, JWSHeaderParameters]  {

        const accessTokenJwt = this.getAccessToken(authorizationHeader);
        const header = decodeProtectedHeader(accessTokenJwt) as JWSHeaderParameters;
        return [accessTokenJwt, header];
    }

    /*
     * Validate a JWT that contains embedded token signing details
     */
    public async validate(accessTokenJwt: string, tokenSigningPublicKey: KeyObject | KeyLike | Uint8Array): Promise<JWTPayload> {

        try {

            const options = {
                algorithms: [this._configuration.algorithm],
                issuer: this._configuration.issuer,
                audience: this._configuration.audience,
            };
            
            const result = await jwtVerify(accessTokenJwt, tokenSigningPublicKey, options);
            return result.payload;
         
        } catch (e) {
         
            let message = 'JWT verification failed';
            if (e instanceof Error) {
               message += `: ${e.message}`;
            }

            if (typeof e === 'string') {
               message += `: ${e}`;
            }

            throw new Error(message);
        }
    }

    /*
     * The cloud system should be configured to pass the authorization header through to the lambda
     */
    private getAccessToken(authorizationHeader: string) {

        if (authorizationHeader && authorizationHeader.toLowerCase().startsWith('bearer ')) {
            return authorizationHeader.substring(7, authorizationHeader.length);
        }
        
        throw new Error('No valid authorization header was provided');
    }
}
