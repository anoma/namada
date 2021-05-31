#!/bin/bash

# This script is used to sign the drone configuration file (.drone.yml). More info at https://readme.drone.io/signature/

PROFILE=$1
DRONE_URL=${2:-ci.heliax.dev}

if [ $# -eq 0 ]; then
    echo "No arguments provided. AWS Profile is mandatory."
    exit 1
fi

TOKEN=$(aws ssm get-parameter --name "drone_machine_secret" --with-decryption --region eu-west-1 --profile $1 | jq -r '.Parameter.Value')

export DRONE_TOKEN=$TOKEN
export DRONE_SERVER=https://$DRONE_URL

drone sign --save heliaxdev/anoma-prototype