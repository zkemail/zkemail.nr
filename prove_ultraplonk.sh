#!/bin/bash

## Set the date utility depending on OSX or Linix
if command -v gdate &> /dev/null
then
    # Set variable for gdate
    date_cmd='gdate'
else
    # Set variable for date (Linux typically)
    date_cmd='date'
fi

## Force recompilation of the circuit
echo "Compiling circuit..."
nargo compile --force &> /dev/null
bb write_vk -b ./target/noir_zkemail.json -o ./target/noir_zkemail.up.vkey
echo "Calculating witness..."
start_time=$($date_cmd +%s%N)

## Calculate the witness of the circuit
nargo execute witness &> /dev/null
witness_end=$($date_cmd +%s%N)
duration_witness=$((witness_end - start_time))
witness_seconds=$(echo "$duration_witness / 1000000000" | bc -l)
echo "Witness generated in: $witness_seconds seconds"
echo "Proving with UltraPlonk..."

## Generate the proof
bb prove -b ./target/noir_zkemail.json -w ./target/witness.gz -o ./target/noir_zkemail.up.proof
end_time=$($date_cmd +%s%N)
duration_prover=$((end_time - witness_end))
duration_total=$((end_time - start_time))
prover_seconds=$(echo "$duration_prover / 1000000000" | bc -l)
total_seconds=$(echo "$duration_total / 1000000000" | bc -l)
echo "Proof generated in: $prover_seconds seconds"
echo "Total time for client: $total_seconds seconds"

## Verify
echo "Verifying proof..."
bb verify -k ./target/noir_zkemail.up.vkey -p ./target/noir_zkemail.up.proof
verify_time=$($date_cmd +%s%N)
duration_verify=$((verify_time - end_time))
verify_seconds=$(echo "$duration_verify / 1000000000" | bc -l)
echo "Proof verified in: $verify_seconds seconds"






