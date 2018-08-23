package com.github.bwinant.cognito.spring;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.bwinant.jwk.Jwk;
import com.github.bwinant.jwk.JwkException;
import com.github.bwinant.jwk.JwkStore;

/**
 * JSON Web Key store that loads the Cognito User Pool .well-known/jwks.json file directly from AWS or from a local file.
 */
public class CognitoJwkStore implements JwkStore
{
    private static final String KEY_ALGORITHM = "RSA";

    private final KeyFactory keyFactory;
    private final ObjectMapper objectMapper;
    private final Map<String, PublicKey> keys;

    public CognitoJwkStore()
    {
        try
        {
            keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        }
        catch (NoSuchAlgorithmException e)
        {
            // This cannot happen, RSA must be supported by JVM for it to be Java spec compliant
            throw new RuntimeException(e);
        }

        objectMapper = new ObjectMapper();
        keys = new HashMap<>();
    }

    @Override
    public Set<String> getKeyIds()
    {
        return Collections.unmodifiableSet(keys.keySet());
    }

    @Override
    public PublicKey getKey(String keyId)
    {
        return keys.get(keyId);
    }

    public void load(String region, String userPoolId) throws IOException, JwkException
    {
        String url = "https://cognito-idp." + region + ".amazonaws.com/" + userPoolId + "/.well-known/jwks.json";
        load(new URL(url));
    }

    public void load(URL url) throws IOException, JwkException
    {
        URLConnection conn = url.openConnection();
        try (InputStream in = conn.getInputStream())
        {
            load(in);
        }
    }

    public void load(File file) throws IOException, JwkException
    {
        try (FileInputStream in = new FileInputStream(file))
        {
            load(in);
        }
    }

    public void load(String resource) throws IOException, JwkException
    {
        try (InputStream in = getClass().getResourceAsStream(resource))
        {
            load(in);
        }
    }

    public void load(InputStream in) throws IOException, JwkException
    {
        CognitoKeys cognitoKeys = objectMapper.readValue(in, CognitoKeys.class);
        for (Jwk jwk : cognitoKeys)
        {
            PublicKey publicKey = getPublicKey(jwk);
            keys.put(jwk.getKid(), publicKey);
        }
    }

    private PublicKey getPublicKey(Jwk jwk) throws JwkException
    {
        if (!jwk.getKty().equalsIgnoreCase(KEY_ALGORITHM))
        {
            throw new JwkException("Invalid key type " + jwk.getKty());
        }

        try
        {
            BigInteger mod = new BigInteger(1, base64Decode(jwk.getN()));
            BigInteger exp = new BigInteger(1, base64Decode(jwk.getE()));
            return keyFactory.generatePublic(new RSAPublicKeySpec(mod, exp));
        }
        catch (InvalidKeySpecException e)
        {
            throw new JwkException("Unable to build public key for JWK " + jwk.getKid(), e);
        }
    }

    private byte[] base64Decode(String val)
    {
        return Base64.getUrlDecoder().decode(val);
    }

    private static class CognitoKeys implements Iterable<Jwk>
    {
        public Jwk[] keys;

        @Override
        public Iterator<Jwk> iterator()
        {
            return Arrays.asList(keys).iterator();
        }
    }
}
