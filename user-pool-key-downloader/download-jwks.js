'use strict';

const https = require('https');
const fs = require('fs');
const jwkToPem = require('jwk-to-pem');
const ArgumentParser = require('argparse').ArgumentParser;


// Downloads specified JSON Web Keys from AWS and converts them to PEM PKCS#1
const downloadKeys = (region, userPoolId) => {
    const jwksUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
    console.log(`Downloading keys from ${jwksUrl}`);

    return new Promise((resolve, reject) => {
        https
            .get(jwksUrl, (res) => {
                if (res.statusCode !== 200) {
                    reject(new Error(res.statusCode))
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

                    resolve(pems);
                });
            })
            .on('error', (err) => {
                reject(err);
            });
    });

};

// -------------------------------------------------------------------------------------------------------------------- //

const parser = new ArgumentParser( { addHelp: true } );
parser.addArgument(['-r', '--region'], { dest: 'region', required: true, metavar: '<AWS region>', help: 'AWS region' });
parser.addArgument(['-u', '--user-pool-id'], { dest: 'userPoolId', required: true, metavar: '<Cognito user pool id>', help: 'Cognito user pool id' });

const args = parser.parseArgs();
const outputFile = args.outputFile || args.userPoolId + '.keys';

downloadKeys(args.region, args.userPoolId)
    .then(keys => {
        console.log(`Saving keys to ${outputFile}`);
        fs.writeFileSync(outputFile, JSON.stringify(keys, null, 2));
    })
    .catch(err => console.log(err));
