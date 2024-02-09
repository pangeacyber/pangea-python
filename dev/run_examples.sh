#!/usr/bin/env bash

# This bash file is to run all .py examples files in a folder.
# It should be run from an example folder containing a `pyproject.toml`.

set -e

# Find all .py files in the current directory and its subdirectories.
find . -type f -name '*.py' | while read -r file; do
    # Check if the file is not empty.
    if [ -s "$file" ]; then
        # Run the file using poetry.
        echo -e "\n\nRunning file: $file\n"
        poetry run python "$file"
    else
        echo "Skipping empty file: $file"
    fi
done
