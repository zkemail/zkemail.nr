#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

cd "$SCRIPT_DIR/.."

compile_example() {
    project=$1
    echo "Compiling $project"
    
    # Use pushd to change to the project directory and save the current directory
    pushd "$project" > /dev/null
    
    # Run the compile command
    nargo compile --force --silence-warnings
    
    # Use popd to return to the previous directory
    popd > /dev/null
}

# Loop over every child folder in the examples directory
for folder in ./examples/*/; do
    if [ -d "$folder" ]; then
        compile_example "$folder"
    fi
done