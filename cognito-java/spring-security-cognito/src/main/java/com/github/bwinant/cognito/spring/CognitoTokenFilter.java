package com.github.bwinant.cognito.spring;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * Looks for Cognito User Pool id or access token in the HTTP Authorization header
 */
public class CognitoTokenFilter extends AbstractPreAuthenticatedProcessingFilter
{
    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request)
    {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || authHeader.isEmpty())
        {
            return null;
        }

        if (authHeader.startsWith("Bearer "))
        {
            return authHeader.substring(7);
        }

        return authHeader;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request)
    {
        // Have to return something non-null for Spring Security PreAuthentication process to work
        return "_cognito";
    }
}
