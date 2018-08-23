package com.github.bwinant.cognito.spring;

import java.security.Key;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import com.github.bwinant.jwk.JwkStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * Validates id and access tokens returned by Cognito User Pool authentication
 */
public class CognitoTokenValidator
{
    private final JwkStore jwkStore;
    private final JwtParser parser;
    private final Set<String> tokenTypes;

    /**
     * Constructs a new CognitoTokenValidator with a specified signing key source
     *
     * @param jwkStore source for JSON Web Keys to use to validate tokens
     */
    public CognitoTokenValidator(JwkStore jwkStore)
    {
        this.jwkStore = jwkStore;
        this.parser = Jwts.parser().setSigningKeyResolver(new KeyResolverImpl());

        this.tokenTypes = new HashSet<>();
        this.tokenTypes.add("access");
        this.tokenTypes.add("id");
    }

    /**
     * Sets the Cognito User Pool tokens supported. Possible values are "id" or "access".
     * By default all tokens issues by the Cognito User Pool are supported
     *
     * @param type the token type supported
     */
    public void setTokenTypes(Set<String> type)
    {
        tokenTypes.clear();
        tokenTypes.addAll(type);
    }

    public CognitoUserDetails validate(String token) throws InvalidTokenException
    {
        try
        {
            Jws<Claims> claims = parser.parseClaimsJws(token);
            Claims body = claims.getBody();

            // Reject the token if type is not supported
            // If we only want access tokens, then an id token is invalid (and vice versa)
            String type = body.get("token_use", String.class);
            if (!tokenTypes.contains(type))
            {
                throw new InvalidTokenException("Unsupported token type " + type);
            }

            String userPoolId = getUserPoolId(body);
            UUID sub = UUID.fromString(body.getSubject());
            String username = body.get("cognito:username", String.class);

            return new CognitoUserDetails(userPoolId, sub, username, body);
        }
        catch (IllegalArgumentException | UnsupportedJwtException | MalformedJwtException | SignatureException | ExpiredJwtException e)
        {
            throw new InvalidTokenException("Invalid token", e);
        }
    }

    private String getUserPoolId(Claims body)
    {
        String iss = body.getIssuer();
        int idx = iss.lastIndexOf('/');
        return iss.substring(idx + 1);
    }

    private class KeyResolverImpl extends SigningKeyResolverAdapter
    {
        @Override
        public Key resolveSigningKey(JwsHeader header, Claims claims)
        {
            return jwkStore.getKey(header.getKeyId());
        }

        @Override
        public Key resolveSigningKey(JwsHeader header, String plaintext)
        {
            return jwkStore.getKey(header.getKeyId());
        }
    }
}

