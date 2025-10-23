#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Source the common script with version variables and check_versions function
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

get_circuit_size() {
    project=$1
    
    # Use pushd to change to the project directory and save the current directory
    pushd "$project" > /dev/null
    
    # Run the compile command
    circuit_output=$(bb gates -b target/$project.json | grep "circuit_size")
    
    # Extract the circuit size value (just the number) using awk
    circuit_size=$(echo "$circuit_output" | awk -F': ' '{print $2}' | tr -d ',')
    
    # Log the project name and circuit size
    echo "$project circuit size: $circuit_size"
    
    # Use popd to return to the previous directory
    popd > /dev/null
}

# Check the versions of Noir and BB
check_versions

cd "$SCRIPT_DIR/../examples" || { echo "Failed to change directory to $SCRIPT_DIR/../examples" >&2; exit 1; }

# Loop over every child folder in the examples directory
for folder in *; do
    if [ -d "$folder" ]; then
        get_circuit_size "$folder"
    fi
done
cd ".." || { echo "Failed to change directory to .." >&2; exit 1; }