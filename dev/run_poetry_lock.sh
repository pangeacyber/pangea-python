#!/bin/bash

# Loop through each subdirectory
for dir in */ ; do
    # Check if pyproject.toml exists in the subdirectory
    if [[ -f "$dir/pyproject.toml" ]]; then
        echo "Running 'poetry lock' in $dir"
        (cd "$dir" && poetry lock)
    else
        echo "Skipping $dir (no pyproject.toml found)"
    fi
done
