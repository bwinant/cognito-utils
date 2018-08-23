package com.github.bwinant.examples.cognito;

import java.io.IOException;

import com.github.bwinant.cognito.spring.CognitoJwkStore;
import com.github.bwinant.cognito.spring.CognitoTokenValidator;
import com.github.bwinant.cognito.spring.CognitoUserDetailsService;
import com.github.bwinant.jwk.JwkException;
import com.github.bwinant.jwk.JwkStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;

@SpringBootApplication(scanBasePackages = "com.github.bwinant.examples.cognito")
public class Application
{
    // Create a JwkStore bean, loading the signing keys however you need to
    @Bean
    public JwkStore jwkStore(@Value("${aws.region}") String region,
                             @Value("${aws.cognito.userpool.id}") String userPoolId)
        throws IOException, JwkException
    {
        CognitoJwkStore jwkStore = new CognitoJwkStore();
        jwkStore.load(region, userPoolId);
        return jwkStore;
    }

    // CognitoTokenValidator could be autowired
    @Bean
    public CognitoTokenValidator tokenValidator(JwkStore jwkStore)
    {
        return new CognitoTokenValidator(jwkStore);
    }

    // CognitoUserDetailsService could be autowired
    @Bean
    public AuthenticationUserDetailsService<?> userDetailsService(CognitoTokenValidator tokenValidator)
    {
        return new CognitoUserDetailsService(tokenValidator);
    }

    public static void main(String[] args)
    {
        SpringApplication springApp = new SpringApplication(Application.class);
        springApp.setHeadless(true);
        springApp.run(args);
    }
}