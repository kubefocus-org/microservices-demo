#!/bin/bash

if [ "$#" -ne 1 ]; then
    printf "Invalid number of arguments" >&2
    printf "./create_registry_secret.sh <GITLAB_DEPLOY_TOKEN>" >&2
    exit 1;
fi

secret_gen_string='{"auths":{"https://registry.gitlab.com":{"username":"{{USER}}","password":"{{TOKEN}}","email":"{{EMAIL}}","auth":"{{SECRET}}"}}}'

gitlab_user=ninakka
gitlab_token=$1 
gitlab_email=ninakka@novusbee.com
gitlab_secret=$(echo -n "$gitlab_user:$gitlab_token" | base64 -w 0)

echo -n $secret_gen_string \
    | sed "s/{{USER}}/$gitlab_user/" \
    | sed "s/{{TOKEN}}/$gitlab_token/" \
    | sed "s/{{EMAIL}}/$gitlab_email/" \
    | sed "s/{{SECRET}}/$gitlab_secret/" \
    | base64 -w 0
