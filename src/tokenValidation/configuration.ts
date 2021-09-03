/*
 * Configuration relevant to the x5c scenario
 */
export class Configuration {
    
    public issuer = 'https://login.curity.local/oauth/v2/oauth-anonymous';
    public audience = 'api.example.com';
    public algorithm = 'RS256';
    public deployedCertificatesLocation = './certs';
}
