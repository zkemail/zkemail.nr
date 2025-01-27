#!/bin/bash

gen_regex() {
    # Name of circuit to set
    circuit_name=$(echo "${1%.json}" | sed -r 's/(^|_)(.)/\U\2/g')
    # Name of file to set
    file_name="${1%.json}_regex.nr"

    # Gen regex
    zk-regex decomposed \
        -d "$1" \
        --noir-file-path "../$file_name" \
        -t "$circuit_name" \
        -g true
}

cd ../lib/src/regex/templates/

for file in *.json; do
    gen_regex "$file"
done


# zk-regex decomposed \
# -d ./t2.json \
# --noir-file-path ./src/simple_regex.nr \
# -t SimpleRegex \
# -g false