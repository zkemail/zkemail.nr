# zkemail.nr

Library for proving emails in Noir. Use the EML parser to generate a Prover.toml that
1. Authenticates the DKIM signature over an email header
2. Extracts the body hash from the authenticated body header
3. Authenticates a body that is hashed in circuit as matching the body hash in the header

See [credits](#credits)

## Use
0. Run `noirup -v0.32.0` to use this repo. Ignore if on later version probably
1. Nargo did not like using git to reference noir_rsa, so Nargo.toml expects noir_rsa to be installed in sibling folder to this directory
```
git clone https://github.com/noir_lang/noir_rsa
```
Then, in the same folder, run 
```
git clone https://github.com/mach-34/noir-zkemail
```
2. The CLI is set up to read `src/demo.eml`. Change the email here if needed. You can generate a `Prover.toml` file by running the cli
```
cd eml_parser && cargo run --release && cd -

## OUTPUTS
global EMAIL_HEADER_LENGTH: u32 = 472;
global EMAIL_BODY_LENGTH: u32 = 24;
```
3. Shown above are outputs for exact header and body lengths for the emails. Eventually, a max size for each will be provided, but in the meantime, you must replace these in `main.nr`
4. Run `nargo execute` to generate the witness - nargo prove is not present on nargo v0.32.0 unfortunately. You can also copy and paste the Prover.toml inputs into a test as shown in `main.nr`
## Todo:

Note that this is a very rough version of this utility and the rust is not built to be maintainable yet.

- [x] CLI for .eml parsing into noir inputs
- [x] Prover.toml generation script
- [ ] Ensure works on all valid test cases in https://github.com/zkemail/zk-email-verify/tree/main/packages/circuits/tests/test-emails
- [x] Full body hash
- [ ] Partial body hash
- [ ] Prove to, from, etc. using string search
- [ ] CLI takes input to specific .eml file rather than hardcoded
- [ ] Max body and header length rather than hardcoded
- [ ] Simple body/ header parsing (currently uses relaxed by default)
- [ ] Proving
- [ ] Benchmarks

## Credits
[ZK Email](https://github.com/zkemail) - repo is derived entirely from this work
[Noir-RSA (V1)](https://github.com/richardliang/noir-rsa/) - body hash base64, insights into how to implement (i thought dkim was over body hash not header until reading this repo)
[Noir_RSA (V2)](https://github.com/noir_lang/noir_rsa) - Makes ZKEmail possible in reasonable amount of time in Noir
