#!/bin/bash

# This script is to update all AWS (or default cloud provider) enviroment variables with GCP values
# It's used to run tests against GCP

# Iterate over all environment variables
for var in $(env | cut -d= -f1); do
    # Check if the variable ends with 'DEV', 'LVE', or 'STG'
    if [[ $var == PANGEA*DEV || $var == PANGEA*LVE || $var == PANGEA*STG ]]; then
        # Construct the name of the corresponding 'GCP' variable
        gcp_var="${var}_GCP"

        # Check if the 'GCP' variable is not set or empty
        if [ -z "$(eval "echo \${$gcp_var}")" ]; then
            echo "Error: The 'GCP' variable for '$var' is not set or empty."
            exit 1
        fi

        echo "Updating '$var'..."
        # Replace the value of the current variable with the value of the 'GCP' variable
        export "$var=$(eval "echo \${$gcp_var}")"
    fi
done
