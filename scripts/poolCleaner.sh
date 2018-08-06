#!/usr/bin/env bash

PROFILE=
REGION=
USER_POOL_ID=
IDENTITY_POOL_ID=
LIMIT=60

function usage() {
    echo "Usage: $0 -r <region> -u <user pool id> -i <identity pool id>" 1>&2
    exit 1
}

function userPoolDelete {
    local users=("$@")

    for username in ${users}
    do
        echo "Deleting user $username"
        aws cognito-idp admin-delete-user --profile ${PROFILE} --region ${REGION} --user-pool-id ${USER_POOL_ID} --username ${username}
    done
}

function identityPoolDelete {
    local identities=("$@")

    for identityId in ${identities}
    do
        echo "Deleting identity $identityId"
        # TODO: identity-ids-to-delete takes a list - this can be optimized
        aws cognito-identity delete-identities --profile ${PROFILE} --region ${REGION} --identity-ids-to-delete ${identityId}
    done
}

while getopts "hr:u:i:" arg; do
    case "${arg}" in
        h) usage
            ;;
        r)
            REGION=${OPTARG}
            ;;
        u)
            USER_POOL_ID=${OPTARG}
            ;;
        i)
            IDENTITY_POOL_ID=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ ! -z "${USER_POOL_ID}" ]; then
    echo "Cleaning user pool ${USER_POOL_ID}"
    RESULT=$(aws cognito-idp list-users --profile ${PROFILE} --region ${REGION} --user-pool-id ${USER_POOL_ID} --limit ${LIMIT})
    PAGINATION_TOKEN=$(echo ${RESULT} | jq -r ".PaginationToken")
    USERS=$(echo ${RESULT} | jq -r ".Users[].Username")
    userPoolDelete "${USERS[@]}"

    while [ "${PAGINATION_TOKEN}" != "null" ]; do
        RESULT=$(aws cognito-idp list-users --profile ${PROFILE} --region ${REGION} --user-pool-id ${USER_POOL_ID} --limit ${LIMIT} --pagination-token ${PAGINATION_TOKEN})
        PAGINATION_TOKEN=$(echo ${RESULT} | jq -r ".PaginationToken")
        USERS=$(echo ${RESULT} | jq -r ".Users[].Username")
        userPoolDelete "${USERS[@]}"
    done
fi

if [ ! -z "${IDENTITY_POOL_ID}" ]; then
    echo "Cleaning identity pool ${IDENTITY_POOL_ID}}"

    RESULT=$(aws cognito-identity list-identities --profile ${PROFILE} --region ${REGION} --identity-pool-id ${IDENTITY_POOL_ID} --max-results ${LIMIT})
    PAGINATION_TOKEN=$(echo ${RESULT} | jq -r ".PaginationToken")
    IDENTITIES=$(echo ${RESULT} | jq -r ".Identities[].IdentityId")
    identityPoolDelete "${IDENTITIES[@]}"

    while [ "${PAGINATION_TOKEN}" != "null" ]; do
        RESULT=$(aws cognito-identity list-identities --profile ${PROFILE} --region ${REGION} --identity-pool-id ${IDENTITY_POOL_ID} --max-results ${LIMIT} --pagination-token ${PAGINATION_TOKEN})
        PAGINATION_TOKEN=$(echo ${RESULT} | jq -r ".PaginationToken")
        IDENTITIES=$(echo ${RESULT} | jq -r ".Identities[].IdentityId")
        identityPoolDelete "${IDENTITIES[@]}"
    done
fi