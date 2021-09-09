import crypto from 'crypto';
import fs from 'fs-extra'
import parseJwk, {JWK, KeyLike} from 'jose/jwk/parse';
import {JWSHeaderParameters} from 'jose/types';
import {asn1, md, pki} from 'node-forge';
import {Configuration} from './configuration';

export class TrustChainValidator {

    private readonly _configuration: Configuration;

    public constructor(configuration: Configuration) {
        this._configuration = configuration;
    }

    /*
     * Demonstrates self contained JWT trust checks, though typically a real API would only use one of these
     */
    public async validate(jwtHeader: JWSHeaderParameters): Promise<crypto.KeyObject | KeyLike> {

        const jwk = jwtHeader.jwk as JWK;
        if (jwk && jwk.x5c) {

            // If there is a jwk with an x5c field then verify the JWT's trust chain using the API's trust store
            return await this._validateJwkTrust(jwtHeader);

        } else if (jwtHeader.x5c) {

            // If there is an x5c field then verify the JWT's trust chain using the API's trust store
            return await this._validateX5cTrust(jwtHeader);

        } else {

            // If there is only an x5t field then use a token signing certificate deployed with the API
            return await this._validateX5tTrust(jwtHeader);
        }
    }

    /*
     * Check that the x5c chain in the JWT satisfies the API's trust chain
     */
    private async _validateX5cTrust(jwtHeader: JWSHeaderParameters): Promise<crypto.KeyObject> {

        const pemCerts = this._getReceivedCertChain(jwtHeader.x5c);
        const trustStore = await this._getWhitelistedCertificateIssuers();

        try {
            
            const receivedCertChain = pemCerts.map((pem) => pki.certificateFromPem(pem));
            const result = pki.verifyCertificateChain(trustStore, receivedCertChain) as any;
            
            // An error result may be returned
            // https://github.com/digitalbazaar/forge/blob/c900522e4198f17d3caad734304b375c0e237c87/js/x509.js#L2903
            if (result.error) {
                throw this._getCertificateChainVerificationError(result);
            }

            return crypto.createPublicKey(pemCerts[0]);
        
        } catch (e) {

            // Alternatively an error may be thrown
            throw this._getCertificateChainVerificationError(e);
        }
    }

    /*
     * Check that the x5c chain in the JWT's jwk field satisfies the API's trust chain
     */
    private async _validateJwkTrust(jwtHeader: JWSHeaderParameters): Promise<KeyLike> {

        let jwk: JWK = jwtHeader.jwk as JWK;
        const pemCerts = this._getReceivedCertChain(jwk.x5c);
        const trustStore = await this._getWhitelistedCertificateIssuers();

        try {
            
            const receivedCertChain = pemCerts.map((pem) => pki.certificateFromPem(pem));
            const result = pki.verifyCertificateChain(trustStore, receivedCertChain) as any;
            
            // An error result may be returned
            // https://github.com/digitalbazaar/forge/blob/c900522e4198f17d3caad734304b375c0e237c87/js/x509.js#L2903
            if (result.error) {
                throw this._getCertificateChainVerificationError(result);
            }

            return parseJwk(jwk);
        
        } catch (e) {

            // Alternatively an error may be thrown
            throw this._getCertificateChainVerificationError(e);
        }
    }

    /*
     * The API stores trusted token signing certificates so just needs to load the correct file
     * In this model the API also needs to be able to deal with token signing certificate renewal
     */
    private async _validateX5tTrust(jwtHeader: JWSHeaderParameters): Promise<crypto.KeyObject> {

        if (jwtHeader.kid) {
        
            const pem = await this._loadCertificateForKid(jwtHeader.kid);
            if (pem) {

                const cert = pki.certificateFromPem(pem);
                const certX5tThumbprint = this._getCertificateX5tThumbprint(cert);

                if (jwtHeader.x5t === certX5tThumbprint) {
                    return crypto.createPublicKey(pem);
                }
            }
        }

        throw new Error(`Unable to find a token signing certificate for kid:${jwtHeader.kid} and x5t:${jwtHeader.x5t}`);
    }

    /*
     * Get certificate details from the JWT header
     */
    private _getReceivedCertChain(x5c?: string[]): string[] {

        if (!x5c) {
            throw new Error('The access token JWT header does not contain an x5c field');
        }
        
        return x5c.map((der) => this._derToPem(der));
    }

    /*
     * Load a DER certificate into the PEM format
     */
    private _derToPem(der: string): string {

        var prefix = '-----BEGIN CERTIFICATE-----\n';
        var postfix = '-----END CERTIFICATE-----';
        return prefix + der.match(/.{0,64}/g)!.join('\n') + postfix;
    }

    /*
     * Set up a trust store with whitelisted certificate authorities deployed with the API
     */
    private async _getWhitelistedCertificateIssuers(): Promise<pki.CAStore> {

        const inter = await this._loadCertificate(`${this._configuration.deployedCertificatesLocation}/intermediate.pem`);
        const root  = await this._loadCertificate(`${this._configuration.deployedCertificatesLocation}/root.pem`);

        const certs: string[] = [];
        if (inter && root) {
            certs.push(inter, root);
        }

        return pki.createCaStore(certs);
    }

    /*
     * For the code example this always loads the only signing certificate
     */
    private async _loadCertificateForKid(kid: string): Promise<string | null> {
        
        const path = `${this._configuration.deployedCertificatesLocation}/signing.pem`;
        return await this._loadCertificate(path);
    }

    /*
     * Load a single certificate file from disk
     */
    private async _loadCertificate(path: string): Promise<string | null> {

        if (await fs.pathExists(path)) {

            const buffer = await fs.readFile(path);
            return buffer.toString();
        }

        return null;
    }

    /*
     * Calculate the x5t thumbprint for a certificate according to the standards
     * https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7
     */
    private _getCertificateX5tThumbprint(cert: pki.Certificate): string {
    
        const derBytes = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
        const hexThumbprint = md.sha1.create().update(derBytes).digest().toHex();
        const base64 = Buffer.from(hexThumbprint, 'hex').toString('base64');
        return this._urlEncode(base64);
    }

    /*
     * A simple URL encode routine
     */
    private _urlEncode(input: string) {
        return input.replace('+', '-').replace('/', '_').replace(/=+$/, '');
    }

    /*
     * Collect any PKI error details
     */
    private _getCertificateChainVerificationError(errorData: any) {
        
        const parts = [];
        parts.push('x5c certificate chain verification failed');
        
        if (errorData.error) {
            parts.push(errorData.error);
        }
        if (errorData.message) {
            parts.push(errorData.message);
        }
        
        const logMessage = parts.join(' : ');
        throw new Error(logMessage);
    }
}
