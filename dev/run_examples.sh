#!/bin/bash

# This bash file is to run all .py examples files in a folder.
# It should be run from the root folder example where there is a .toml file
# This script first will run `poetry lock` and `poetry install` to update example folder installation
# Then will search for `*.py` files inside root folder and subdirectories and it will run them with `poetry run python <file.py>`

poetry lock
poetry install

# Find all .py files in the current directory and its subdirectories
find . -type f -name '*.py' | while read -r file; do
    # Check if the file is not empty
    if [ -s "$file" ]; then
        # Run the file using poetry
        echo -e "\n\nRunning file: $file\n"
        poetry run python "$file"
    else
        echo "Skipping empty file: $file"
    fi
done
