package com.github.bwinant.cognito.spring;

/**
 * Thrown when an invalid Cognito User Pool id or access token is encountered.
 */
public class InvalidTokenException extends Exception
{
    public InvalidTokenException(String message)
    {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
