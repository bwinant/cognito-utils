package com.github.bwinant.cognito;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminCreateUserResult;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeRequest;
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeResult;
import com.amazonaws.services.cognitoidp.model.AdminUpdateUserAttributesRequest;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.AuthenticationResultType;
import com.amazonaws.services.cognitoidp.model.ListUsersRequest;
import com.amazonaws.services.cognitoidp.model.ListUsersResult;
import com.amazonaws.services.cognitoidp.model.MessageActionType;
import com.amazonaws.services.cognitoidp.model.UserStatusType;
import com.amazonaws.services.cognitoidp.model.UserType;

/**
 * Some useful methods for managing users in a Cognito User Pool
 */
public class UserManager
{
    private static final int LIMIT = 60;

    private final AWSCognitoIdentityProvider cognito;
    private final String userPoolId;
    private final String clientId;

    /**
     * Create a new UserManager that manages a specific User Pool.
     * For this class to work, clientId should specify an App Client that allows ADMIN_NO_SRP_AUTH
     *
     * @param cognito       a properly configured AWSCognitoIdentityProvider instance
     * @param userPoolId    the Cognito User Pool id
     * @param clientId      the Cognito User Pool App Client id
     */
    public UserManager(AWSCognitoIdentityProvider cognito, String userPoolId, String clientId)
    {
        this.cognito = cognito;
        this.userPoolId = userPoolId;
        this.clientId = clientId;
    }

    /**
     * Creates a user in Cognito and automates the new password required challenge process to setup the user with a specified password.
     *
     * @param username      the Cognito username
     * @param password      the desired user password
     * @param attributes    the user's attributes
     *
     * @return
     *
     * @throws com.amazonaws.services.cognitoidp.model.UsernameExistsException if username already exists
     * @throws RuntimeException if an unexpected state was encountered during the password setting process
     */
    public UserType createUser(String username, String password, Map<String, String> attributes)
    {
        List<AttributeType> attrList = new ArrayList<>(attributes.size());
        for (Map.Entry<String, String> entry : attributes.entrySet())
        {
            // preferred_username cannot be set at user creation time if preferred_username is also a user pool alias
            if (!entry.getKey().equals("preferred_username"))
            {
                 attrList.add(attribute(entry.getKey(), entry.getValue()));
            }
        }

        // Generate a temporary password - this only needs to be reasonably secure - it won't exist past this method
        String tempPassword = generatePassword(12);

        // Create user and suppress any confirmation notifications - will be in NEW_PASSWORD_REQUIRED state
        AdminCreateUserResult createUserResult = cognito.adminCreateUser(
            new AdminCreateUserRequest()
                .withUserPoolId(userPoolId)
                .withUsername(username)
                .withUserAttributes(attrList)
                .withTemporaryPassword(tempPassword)
                .withMessageAction(MessageActionType.SUPPRESS)
        );

        // Login as new user with temp password
        AdminInitiateAuthResult authResult = authenticate(username, tempPassword);
        AuthenticationResultType art = authResult.getAuthenticationResult();
        String challenge = authResult.getChallengeName();

        // We should get a change password auth challenge
        if (art == null && challenge != null && challenge.equals("NEW_PASSWORD_REQUIRED"))
        {
            Map<String, String> challengeResponses = new HashMap<>();
            challengeResponses.put("USERNAME", username);
            challengeResponses.put("NEW_PASSWORD", password);

            AdminRespondToAuthChallengeResult challengeResult = cognito.adminRespondToAuthChallenge(
                new AdminRespondToAuthChallengeRequest()
                    .withUserPoolId(userPoolId)
                    .withClientId(clientId)
                    .withChallengeName("NEW_PASSWORD_REQUIRED")
                    .withSession(authResult.getSession())
                    .withChallengeResponses(challengeResponses)
            );

            // Prep return value
            UserType user = createUserResult.getUser();
            user.setUserStatus(UserStatusType.CONFIRMED);

            // Challenge result should indicate user is logged in
            if (challengeResult.getAuthenticationResult() != null)
            {
                // Now set preferred username - it can't be set at creation time if it is used as a user pool alias
                String preferredUsername = attributes.get("preferred_username");
                if (preferredUsername != null)
                {
                    AttributeType prefUsernameAttr = attribute("preferred_username", preferredUsername);
                    updateUser(username, Collections.singletonList(prefUsernameAttr));
                    user.getAttributes().add(prefUsernameAttr);
                }
            }
            else
            {
                throw new RuntimeException("Unexpected response from adminRespondToAuthChallenge: " + challengeResult);
            }

            return user;
        }
        else
        {
            throw new RuntimeException("Unexpected response from adminInitiateAuth. Authentication result: " + art + ", Challenge: " + challenge);
        }
    }

    /**
     * Updates a user's attributes.
     *
     * @param username    a username
     * @param attributes  list of attributes to update
     */
    public void updateUser(String username, List<AttributeType> attributes)
    {
        cognito.adminUpdateUserAttributes(
            new AdminUpdateUserAttributesRequest()
                .withUserPoolId(userPoolId)
                .withUsername(username)
                .withUserAttributes(attributes)
        );
    }

    /**
     * Authenticate a user against Cognito.
     *
     * @param username  a username
     * @param password  a password
     *
     * @return the authentication result
     *
     * @throws com.amazonaws.services.cognitoidp.model.NotAuthorizedException if username/password is incorrect
     */
    public AdminInitiateAuthResult authenticate(String username, String password)
    {
        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);

        return cognito.adminInitiateAuth(
            new AdminInitiateAuthRequest()
                .withUserPoolId(userPoolId)
                .withClientId(clientId)
                .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .withAuthParameters(authParams)
        );
    }

    /**
     * Search for users.
     *
     * @param filterName    the Cognito user attribute to search on
     * @param filterValue   the value of the Cognito user attribute to look for
     * @param attributes    optional list of Cognito user attributes to return; if not specified, all attributes are returned
     *
     * @return list of users
     */
    public List<UserType> searchUsers(String filterName, String filterValue, List<String> attributes)
    {
        String filterExpression = filterName + " = \"" + filterValue + "\"";
        return listUsers(filterExpression, attributes, -1);
    }

    /**
     * Return all Cognito users, up to an optional max limit.
     * If limit is less than or equal to 0, all users are returned
     *
     * @param limit        the number of users to return
     * @param attributes   optional list of Cognito user attributes to return; if not specified, all attributes are returned
     *
     * @return list of users
     */
    public List<UserType> listUsers(int limit, List<String> attributes)
    {
        List<UserType> users = listUsers(null, attributes, limit);
        if (users.size() > limit && limit > 0)
        {
            users = users.subList(0, limit);
        }
        return users;
    }

    private List<UserType> listUsers(String filterExpression, List<String> attributes, int limit)
    {
        ListUsersRequest request = new ListUsersRequest()
            .withUserPoolId(userPoolId)
            .withLimit(LIMIT);

        if (filterExpression != null)
        {
            request.withFilter(filterExpression);
        }

        if (attributes != null && !attributes.isEmpty())
        {
            request.withAttributesToGet(attributes);
        }

        List<UserType> users = new ArrayList<>();

        String paginationToken = null;
        do
        {
            request.withPaginationToken(paginationToken);

            ListUsersResult result = cognito.listUsers(request);
            paginationToken = result.getPaginationToken();

            users.addAll(result.getUsers());
        }
        while (paginationToken != null && (users.size() < limit || limit <= 0));

        return users;
    }

    private AttributeType attribute(String name, String value)
    {
        return new AttributeType().withName(name).withValue(value);
    }

    private String generatePassword(int length)
    {
        final String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        final Random random = ThreadLocalRandom.current();

        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < length; i++)
        {
            int idx = random.nextInt(chars.length());
            char ch = chars.charAt(idx);

            if (random.nextBoolean())
            {
                ch = Character.toUpperCase(ch);
            }

            buf.append(ch);
        }
        return buf.toString();
    }
}
