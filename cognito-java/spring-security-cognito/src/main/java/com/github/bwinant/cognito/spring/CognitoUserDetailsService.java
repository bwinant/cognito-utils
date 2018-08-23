package com.github.bwinant.cognito.spring;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class CognitoUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken>
{
    private final CognitoTokenValidator tokenValidator;

    public CognitoUserDetailsService(CognitoTokenValidator tokenValidator)
    {
        this.tokenValidator = tokenValidator;
    }

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken preAuthToken) throws UsernameNotFoundException
    {
        String token = (String) preAuthToken.getPrincipal();

        try
        {
            CognitoUserDetails userDetails = tokenValidator.validate(token);
            userDetails.addAuthority(new SimpleGrantedAuthority("ROLE_USER"));
            return userDetails;
        }
        catch (InvalidTokenException e)
        {
            throw new BadCredentialsException("Cannot authenticate request", e);
        }
    }
}
