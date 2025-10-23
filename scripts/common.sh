#!/bin/bash

# Version variables for Noir and BB
NARGO_VERSION="1.0.0-beta.5"
BB_VERSION="0.84.0"

# Function to check and update versions of Noir and BB
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
