package com.github.bwinant.examples.cognito;

import com.github.bwinant.cognito.spring.CognitoUserDetails;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/example")
public class ExampleController
{
    /**
     * Authenticate against a Cognito User Pool, then GET /example/authtest with the id or access token in the Authorization header
     */
    @RequestMapping(value = "/authtest", method = RequestMethod.GET)
    public UserDetails testAuthentication(@AuthenticationPrincipal CognitoUserDetails userDetails)
    {
        return userDetails;
    }
}
