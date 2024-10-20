#!/usr/bin/env bash

# This bash file is to run all .py examples files in a folder.
# It should be run from an example folder containing a `pyproject.toml`.

set -e

skip_items=("cli.py")

# Find all .py files in the current directory and its subdirectories.
find . -type f -name '*.py' | while read -r file; do
    # Check if the file is not empty.
    if [ -s "$file" ]; then
        # Check if the file or directory should be skipped
        skip=false
        echo -e "Checking $file"
        for skip_item in "${skip_items[@]}"; do
            if [[ "$file" == *"$skip_item"* ]]; then
                echo "Skipping $file"
                skip=true
                break
            fi
        done

        # Run the file if it should not be skipped
        if [ "$skip" = false ]; then
            # Run the file using poetry.
            echo -e "\n\nRunning file: $file\n"
            poetry run python "$file"
        fi
    else
        echo "Skipping empty file: $file"
    fi
done
