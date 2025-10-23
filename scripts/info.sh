#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

NARGO_VERSION="1.0.0-beta.5"
BB_VERSION="0.84.0"

check_versions() {
    if [ "$(nargo --version | grep "nargo version = $NARGO_VERSION")" != "nargo version = $NARGO_VERSION" ]; then
        echo "Noir version is not $NARGO_VERSION, running noirup --version $NARGO_VERSION"
        noirup --version $NARGO_VERSION
    fi

    if [ "$(bb --version)" != "v$BB_VERSION" ]; then
        echo "BB version is not $BB_VERSION, running bbup --version $BB_VERSION"
        bbup --version $BB_VERSION
    fi
}

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

cd $SCRIPT_DIR/../examples

# Loop over every child folder in the examples directory
for folder in *; do
    if [ -d "$folder" ]; then
        get_circuit_size "$folder"
    fi
done
cd ..