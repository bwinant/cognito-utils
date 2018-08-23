package com.github.bwinant.examples.cognito;

import javax.servlet.Filter;

import com.github.bwinant.cognito.spring.CognitoTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter
{
    @Autowired
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        // Configure security per your own requirements, but the important part
        // is to include the addFilterAt part and inject the Cognito token filter in the right spot in the filter chain
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
            .and()
            .addFilterAt(tokenFilter(), AbstractPreAuthenticatedProcessingFilter.class)
            .requestMatchers().antMatchers("/example/**")
            .and()
            .authorizeRequests().antMatchers("/example/**").hasRole("USER");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
    {
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider()
    {
        PreAuthenticatedAuthenticationProvider preAuthProvider = new PreAuthenticatedAuthenticationProvider();
        preAuthProvider.setPreAuthenticatedUserDetailsService(userDetailsService);
        return preAuthProvider;
    }

    @Bean
    public Filter tokenFilter() throws Exception
    {
        // The filter bean must be defined in WebSecurityConfigurerAdapter since setAuthenticationManager will be called
        // during the bean initialization process
        CognitoTokenFilter filter = new CognitoTokenFilter();
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }
}