import {KeyObject} from 'crypto';
import {JWSHeaderParameters} from 'jose/types';
import {KeyLike} from 'jose/jwk/parse'
import {JWTPayload, jwtVerify} from 'jose/jwt/verify';
import {decodeProtectedHeader} from 'jose/util/decode_protected_header';
import {Configuration} from './configuration';

export class TokenValidator {

    private readonly _configuration: Configuration;

    public constructor(configuration: Configuration) {
        this._configuration = configuration;
    }

    /*
     * Read the JWT and its header details
     */
    public parseToken(authorizationHeader: string): [string, JWSHeaderParameters]  {

        const accessTokenJwt = this._getAccessToken(authorizationHeader);
        const header = decodeProtectedHeader(accessTokenJwt) as JWSHeaderParameters;
        return [accessTokenJwt, header];
    }

    /*
     * Validate a JWT that contains embedded token signing details
     */
    public async validate(accessTokenJwt: string, tokenSigningPublicKey: KeyObject | KeyLike): Promise<JWTPayload> {

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
    private _getAccessToken(authorizationHeader: string) {

        if (authorizationHeader && authorizationHeader.toLowerCase().startsWith('bearer ')) {
            return authorizationHeader.substring(7, authorizationHeader.length);
        }
        
        throw new Error('No valid authorization header was provided');
    }
}
