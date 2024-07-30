# zkemail.nr

Library for proving emails in Noir

WARNING: IN PROGRESS AND MAY NOT YET WORK WITH ALL EMAILS. ALSO DOES NOT YET PROVE BODY HASH / ACCESS TO/FROM.
LIBRARY CURRENTLY ONLY AUTOMATES TAKING A .EML FILE AND VERIFYING THE AUTHENTICITY OF THE SIGNATURE

## Use
0. Nargo did not like using git to reference noir_rsa, so Nargo.toml expects noir_rsa to be installed in sibling folder to this directory
```
git clone https://github.com/noir_lang/noir_rsa
```
Then, in the same folder, run 
```
git clone https://github.com/mach-34/noir-zkemail
```
1. The CLI is set up to read `src/demo.eml`. Change the email here if needed. To generate needed inputs, run `cd eml_parser && cargo run --release && cd -`. Output should look like
```rs
let header: [u8; 472] = [102, 114, 111, ..., 32, 98, 61];
let signature: BN2048 = BigNum::from_array([0x5779c85587e51cb8de5c29d7fdfeb0, ..., 0x12]);
let instance: BigNumInstance<18, instance_Params> = BigNumInstance::new(
    [
        0xe5cf995b5ef59ce9943d1f4209b6ab, ..., 0xd5
    ],
    [
        0xa48a824e4ebc7e0f1059f3ecfa57c4, ..., 0x0132
    ]
);
```
2. Take the output and place it in the `zk_email_test` where marked by comments. Also, replace `EMAIL_HEADER_LENGTH` at top if necessary.
3. Run `nargo test` and it will verify the signature over the header!

### Moving Forwards
From here, you would next verify the body hash contained within the header. Then you might verify the to/ from email or contents of the body from `https://github.com/noir-lang/noir_string_search`. This library will be updated to include such functionality.


## Todo:

Note that this is a very rough version of this utility and the rust is not built to be maintainable yet.

[x] CLI for turning .eml into inputs for Noir (printed)
[ ] parse pubkey and signature as bytes
[ ] Prover.toml generation script
[ ] Ensure works on all test cases in https://github.com/zkemail/zk-email-verify/tree/main/packages/circuits/tests/test-emails
[ ] Partial body hash
[ ] Find to, from, etc demo
[ ] CLI takes input to specific .eml file rather than hardcoded