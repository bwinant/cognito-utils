package com.github.bwinant.cognito.spring;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Spring Security UserDetails implementation populated from data found in the JWT claims object found inside Cognito User Pool access/id tokens.
 */
public class CognitoUserDetails implements UserDetails
{
    private final String userPoolId;
    private final UUID sub;
    private final String username;
    private final Map<String, Object> attributes;
    private final Set<GrantedAuthority> authorities;

    /**
     * Construct a new CognitoUserDetails
     *
     * @param userPoolId    the id of the Cognito User Pool the user authenticated against
     * @param sub           the user's sub attribute in Cognito
     * @param username      the user's Cognito username
     * @param attributes    other optional user attributes
     */
    public CognitoUserDetails(String userPoolId, UUID sub, String username, Map<String, Object> attributes)
    {
        this.userPoolId = userPoolId;
        this.sub = sub;
        this.username = username;
        this.attributes = attributes != null ? attributes : Collections.emptyMap();
        this.authorities = new HashSet<>();
    }

    /**
     * The Cognito User Pool the user authenticated against
     *
     * @return the Cognito User Pool id
     */
    public String getUserPoolId()
    {
        return userPoolId;
    }

    /**
     * The user's sub attribute in the Cognito User Pool
     *
     * @return the user's sub attribute
     */
    public UUID getSub()
    {
        return sub;
    }

    /**
     * If authentication was performed with an id token, then this will return user attributes such as email or preferred_username
     *
     * @param name the attribute name
     * @param type the attribute type (usually String)
     * @param <T>  type parameter
     *
     * @return the attribute value
     */
    public <T> T getAttribute(String name, Class<T> type)
    {
        Object value = attributes.get(name);
        return type.cast(value);
    }

    @Override
    public String getUsername()
    {
        return username;
    }

    @Override
    public String getPassword()
    {
        return null;
    }

    @Override
    public boolean isAccountNonExpired()
    {
        return true;
    }

    @Override
    public boolean isAccountNonLocked()
    {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired()
    {
        return true;
    }

    @Override
    public boolean isEnabled()
    {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities()
    {
        return authorities;
    }

    public void addAuthority(GrantedAuthority authority)
    {
        authorities.add(authority);
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        final CognitoUserDetails cud = (CognitoUserDetails) o;
        return sub.equals(cud.getSub());
    }

    @Override
    public int hashCode()
    {
        return username.hashCode();
    }

    @Override
    public String toString()
    {
        return username;
    }
}
