#!/bin/bash

mkdir -p .tmp
RESPONSE_FILE=.tmp/response.txt
TOKEN_ENDPOINT=https://login.curity.local/oauth/v2/oauth-token
INTROSPECT_ENDPOINT=https://login.curity.local/oauth/v2/oauth-introspect
CLIENT_ID=test-client
CLIENT_SECRET=Password1
INTROSPECT_CLIENT_ID=introspect-client
INTROSPECT_CLIENT_SECRET=Password1

#
# Authenticate via the client credentials grant
#
HTTP_STATUS=$(curl -s -X POST $TOKEN_ENDPOINT \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "scope=read" \
    -o $RESPONSE_FILE -w '%{http_code}')
if [ "$HTTP_STATUS" != '200'  ]; then
  echo "*** Problem encountered authenticating to get an opaque access token, status: $HTTP_STATUS"
  exit
fi
JSON=$(tail -n 1 $RESPONSE_FILE)
REF_TOKEN=$(jq -r .access_token <<< "$JSON")
echo 'Successfully authenticated and received a JWT'

#
# Introspect the token to get the JWT
#
HTTP_STATUS=$(curl -s -X POST $INTROSPECT_ENDPOINT \
    -u "$INTROSPECT_CLIENT_ID:$INTROSPECT_CLIENT_SECRET" \
    -H "Accept: application/jwt" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=$REF_TOKEN" \
    -o $RESPONSE_FILE -w '%{http_code}')
if [ "$HTTP_STATUS" != '200'  ]; then
  echo "*** Problem encountered introspecting the opaque access token, status: $HTTP_STATUS"
  exit
fi
JWT=$(tail -n 1 $RESPONSE_FILE)
echo 'Successfully introspected the access token to get a JWT ...'

#
# Create the input to the lambda function - install the jo tool via 'brew install jo' if required
#
AUTH_HEADER="Bearer $JWT"
jo -p httpMethod='GET' headers="$(jo Authorization="Bearer $JWT")" > ./data/request.json
echo "Execute 'npm start' to send the JWT to the lambda function"