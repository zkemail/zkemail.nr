# zkemail.nr

Library for proving emails in Noir. Use the EML parser to generate a Prover.toml that
1. Authenticates the DKIM signature over an email header
2. Extracts the body hash from the authenticated body header
3. Authenticates a body that is hashed in circuit as matching the body hash in the header
4. Asserts the email is received by a specified domain (gmail.com as demo)
5. Outputs the pedersen hash of the DKIM pubkey modulus for verification

See [credits](#credits)

## Use
### Dependencies
0. Ensure you have `noirup` (circuit compiler) and `bbup` (circuit prover) installed:
```console
# Install noirup
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
# Install bbup
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash

# On Mac:
source ~/.zshrc
# On Linux 🗿: 
source ~/.bashrc
```
1. Install the correct versions of `bb` and `nargo` (if later than shown below probably works)
```
# Install nargo
noirup -v 0.32.0
# Install bb
bbup -v 0.46.1
```
### Running ZKEmail.nr
1. Install the repository with `git clone https://github.com/mach-34/zkemail.nr && cd zkemail.nr`
2. The CLI is set up to read `src/demo.eml`. Change the email here if needed. You can generate a `Prover.toml` file by running the cli
```
cd eml_parser && cargo run --release && cd -

## OUTPUTS
global EMAIL_HEADER_LENGTH: u32 = 472;
global EMAIL_BODY_LENGTH: u32 = 24;
```
3. Shown above are outputs for exact header and body lengths for the emails. Eventually, a max size for each can be provided, but in the meantime, you must replace these in `main.nr`

4. Prove the circuit and verify the authenticity of an email:
```console
# Prove with ultraplonk (verifier-contract friendly)
./prove_ultraplonk.sh
# Prove with megahonk (quicker but non-constant proof size)
./prove_megahonk.sh
```

### Note on String Search
Use of string search will be highly application dependent. This repo shows a demonstration of using string search to match the to recipient (rather than from which is probably more useful but at index 0 of the header). Use the implementation as a guide to searching for the from domain, or searching for strings within the body.

## Benchmarks
Note that the proving is broken with string search due to instability around bb v0.46.1. Benchmarks do not include string search.
### Gates
(NO PARTIAL HASH, MATCHING RECIPIENT DOMAIN)

SMALL EMAIL GATES: `80125` + 16k gates to hash pubkey modulus

BIG EMAIL GATES: TODO


### 11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz
#### Small Email
 * UltraPlonk: 8.0s witcalc, 8.4s proof gen
 * MegaPlonk: 7.6s witcalc, 3.0s proof gen
#### Big Email
TODO
### M1 Bare Metal
#### Small Email
 * UltraPlonk: TODO
 * MegaPlonk: TODO
#### Big Email
TODO
### Wasm
TODO

## Todo:

Note that this is a very rough version of this utility and the rust is not built to be maintainable yet.

- [x] CLI for .eml parsing into noir inputs
- [x] Prover.toml generation script
- [ ] Ensure works with big email (Quoted Pritable Encoding) support
- [x] Full body hash
- [ ] Partial body hash
- [x] Prove recipient using string search
- [ ] CLI takes input to specific .eml file rather than hardcoded
- [ ] Max body and header length rather than hardcoded
- [ ] Simple body/ header parsing (currently uses relaxed by default)
- [x] Proving
- [x] Basic Benchmarking script
- [ ] Robust Benchmarking script (30 samples)
- [x] Publicly output the pubkey modulus to verify the email authenticity
  [ ] EVM Contract Demo
  [ ] Aztec Contract Demo
  [ ] Hyle Aggregator Demo

## Credits
[ZK Email](https://github.com/zkemail) - repo is derived entirely from this work
[Noir-RSA (V1)](https://github.com/richardliang/noir-rsa/) - body hash base64, insights into how to implement (i thought dkim was over body hash not header until reading this repo)
[Noir_RSA (V2)](https://github.com/noir_lang/noir_rsa) - Makes ZKEmail possible in reasonable amount of time in Noir
