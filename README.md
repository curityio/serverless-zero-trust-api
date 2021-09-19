# A Serverless API that Validates JWTs

[![Quality](https://img.shields.io/badge/quality-experiment-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

Some Serverless / Cloud Native APIs are recreated on every API request and cannot cache token signing keys.\
This code example shows how to do token validation using public key details embedded in the JWT header.

## Example API

The sample uses a trivial lambda function that returns a hard coded response.\
Every call to the lambda validates a JWT, as part of a [Zero Trust Architecture](https://curity.io/solutions/zero-trust).

```yaml
functions:
  getDataFunction:
    handler: dist/getDataFunction.handler
    events:
      - http: 
          path: /data
          method: get
```

## Prerequisites

- Run the `createCerts.sh` script, which uses OpenSSL to create a local certificate trust chain for testing.

## Run the Lambda

Run the lambda via the following commands, to execute the certificate chain handling code:

- npm install
- npm run build
- npm start

This will result in an error response because the access token in `data/request.json` is untrusted:

```
SERVER-ERROR-LOG: x5c certificate chain verification failed : forge.pki.UnknownCertificateAuthority : Certificate is not trusted.
{
    "status": 401,
    "body": "{\"code\":\"unauthorized\",\"message\":\"Missing, invalid or expired access token\"}"
}
```

## Get a Valid Access Token

Follow the [Code Example Walkthrough](https://curity.io/resources/learn/serverless-zero-trust-api) to configure the Curity Identity Server.\
Run the `setup.sh` script to renew the access token in `data/request.json`.\
Then run the lambda again, which will output the token claims to the console, then return a success lambda response:

```
{
  jti: 'b075a8ec-9555-480f-b0bf-aa5fc3dc4f88',
  delegationId: '7b4f1bce-59da-47d1-98e2-660c9e5008a6',
  exp: 1630088873,
  nbf: 1630088573,
  scope: 'read',
  iss: 'https://login.curity.local/oauth/v2/oauth-anonymous',
  sub: '607ad1f66f06563478c433dd15825eabb5ddfd8ad67cbbf60d5ec0c97164f173',
  aud: 'api.example.com',
  iat: 1630088573,
  purpose: 'access_token'
}
{
    "status": 200,
    "body": "{\"message\":\"API successfully validated the JWT and verified x509 certificate trust\"}"
}
```

## Security Behavior

The code example provides the following main classes:

- `TrustChainValidator` shows how to verify trust of the token signing X509 details contained in the JWT
- `TokenValidator` shows how to continue with standard JWT validation

Three scenarios are covered:

-  Validating the full trust chain received in the `x5c` array field of the JWT header
-  Validating the full trust chain received in the `jwk` object field of the JWT header
-  Identifying a certificate from the `x5t` thumpbrint in the JWT header

## Libraries

- The [Node Forge](https://github.com/digitalbazaar/forge) PKI library is used to verify X509 certificate details
- The [Jose](https://github.com/panva/jose) library is then used to validate the JWT

## Further Information

Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.
