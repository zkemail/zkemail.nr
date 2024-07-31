#!/bin/bash
nargo compile --force && bb gates -b ./target/noir_zkemail.json | grep "circuit"