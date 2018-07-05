'use strict';

const https = require('https');
const fs = require('fs');
const jwkToPem = require('jwk-to-pem');

// Downloads specified JSON Web Keys from AWS and converts them to PEM PKCS#1
const downloadKeys = (region, userPoolId, callback) => {
    const jwksUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
    console.log(`Downloading keys from ${jwksUrl}`);

    https
        .get(jwksUrl, (res) => {
            if (res.statusCode !== 200) {
                callback(new Error(res.statusCode))
            }

            let buffer = '';

            res.setEncoding('utf-8');
            res.on('data', (chunk) => {
                buffer += chunk;
            });
            res.on('end', () => {
                const json = JSON.parse(buffer);
                const pems = {};

                // Convert each key to PEM
                json['keys'].forEach(key => {
                    const key_id = key.kid;
                    const modulus = key.n;
                    const exponent = key.e;
                    const key_type = key.kty;
                    const jwk = {kty: key_type, n: modulus, e: exponent};

                    console.log(`Converting ${key_type} key ${key_id}`);
                    pems[key_id] = jwkToPem(jwk);
                });

                callback(null, pems);
            });
        })
        .on('error', (err) => {
            callback(err);
        });
};


if (process.argv.length !== 5) {
    console.log('Usage: node download-jwks.js <AWS region> <Cognito User Pool ID> <output file>');
    process.exit(1);
}

const region = process.argv[2];
const userPoolId = process.argv[3];
const keyFile = process.argv[4];

downloadKeys(region, userPoolId, (err, keys) => {
    if (err != null) {
       console.log(err);
    }
    else {
        console.log(`Saving keys to ${keyFile}`);
        fs.writeFileSync(keyFile, JSON.stringify(keys));
    }
});
