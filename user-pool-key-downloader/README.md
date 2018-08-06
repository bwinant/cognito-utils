If you want to decode and validate Cognito User Pool ID and Access tokens yourself, you will need the JWKS signing keys for the user pool. Luckily, AWS makes these available at:

`https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json`

The `jwks.json` file will contain information necessary to reconstruct 2 RSA public keys - one for the Cognito id token and another for the Cognito access token. 

To feed the keys into a crypto library, they need to be converted to a well known format. This script will download the keys from AWS, convert them to PKCS#1 format, then save them to a JSON file in the format:

```
{
    "$accessTokenKey": "$rsaPublicKey",
    "idTokenKey": "$rsaPublicKey"
}
``` 

_Note_: the key order will be indeterminate

To run `download-jwks`:
```
npm install
node ./download-jwks.js -r <AWS region> -u <Cognito User Pool ID> -o <output file>
 ``` 

You can extract and verify the RSA public keys by:

- List the key ids: `cat <output file> | jq -r  'to_entries[] | "\(.key)"'`
- Verify a RSA public key: `cat <output file> | jq -r -j '.["$keyId"]' | openssl rsa -inform PEM -pubin -text -noout`


See https://aws.amazon.com/premiumsupport/knowledge-center/decode-verify-cognito-json-token/ for more information    