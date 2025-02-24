#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

cd "$SCRIPT_DIR/.."

compile_example() {
    project=$1
    echo "Compiling $project verifier contract"
    
    # Use pushd to change to the project directory and save the current directory
    pushd "$project" > /dev/null
    
    # Run the vkey generation command
    echo "Generating vkey"
    echo $project.json
    echo $(pwd)
    bb write_vk_ultra_keccak_honk -b $project.json

    bb contract_ultra_honk
    
    # Use popd to return to the previous directory
    popd > /dev/null
}

# Loop over every child folder in the examples directory
for folder in ./examples/*; do
    if [ -d "$folder" ]; then
        compile_example "$folder"
    fi
done