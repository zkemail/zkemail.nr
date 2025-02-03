#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

cd $SCRIPT_DIR/..

fmt() {
    project=$1
    echo "Formatting $project"
    
    # Use pushd to change to the project directory and save the current directory
    pushd "$project" > /dev/null
    
    # Run the compile command
    nargo fmt
    
    # Use popd to return to the previous directory
    popd > /dev/null
}

# Loop over every child folder in the examples directory
for folder in ./examples/*/; do
    if [ -d "$folder" ]; then
        fmt "$folder"
    fi
done

# Format the main library
cd lib && nargo fmt