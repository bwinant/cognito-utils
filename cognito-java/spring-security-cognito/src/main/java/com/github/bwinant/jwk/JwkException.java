package com.github.bwinant.jwk;

/**
 * Thrown when an invalid JSON Web Key is encountered.
 */
public class JwkException extends Exception
{
    public JwkException(String message)
    {
        super(message);
    }

    public JwkException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
