## ZKEmail.nr
ZKEmail written in [NoirLang](https://noir-lang.org/)

## Using the Noir Library

In your Nargo.toml file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
zkemail = { tag = "v0.3.2", git = "https://github.com/zkemail/zkemail.nr", directory = "lib" }
```

The library exports the following functions:
- `dkim::RSAPubkey::verify_dkim_signature` -  for verifying DKIM signatures over an email header. This is needed for all email verifications.
- `headers::body_hash::get_body_hash` - constrained access and decoding of the body hash from the header
- `headers::email_address::get_email_address` - constrained extraction of to or from email addresses
- `partial_hash::partial_sha256_var_end` - finish a precomputed sha256 hash over the body
- `masking::mask_text` - apply a byte mask to the header or body to selectively reveal parts of the entire email
- `standard_outputs` - returns the hash of the DKIM pubkey and a nullifier for the email (`hash(signature)`)


```rust
use dep::zkemail::{
    KEY_LIMBS_1024, dkim::verify_dkim_1024, get_body_hash_by_index,     
    base64::body_hash_base64_decode, standard_outputs
};
use dep::std::hash::sha256_var;

// Somewhere in your function
...
  verify_dkim_1024(header, header_length, pubkey, pubkey_redc, signature);

  let body_hash_encoded = get_body_hash_by_index(header, body_hash_index);
  let signed_body_hash: [u8; 32] = body_hash_base64_decode(body_hash_encoded);

  let computed_body_hash: [u8; 32] = sha256_var(body, body_length as u64);

  assert(
      signed_body_hash == computed_body_hash, "SHA256 hash computed over body does not match body hash found in DKIM-signed header"
  );
...
```

### Usage with partial SHA

You can use partial hashing technique for email with large body when the part you want to constrain in the body is towards the end.

Since SHA works in chunks of 64 bytes, we can hash the body up to the chunk from where we want to extract outside of the circuit and do the remaining hash in the circuit. This will save a lot of constraints as SHA is very expensive in circuit.

```rust
use dep::zkemail::{
    KEY_LIMBS_2048, dkim::verify_dkim_2048, get_body_hash_by_index,
    partial_hash::partial_sha256_var_end, base64::body_hash_base64_decode,
};

...
  // verify the dkim signature over the header
  verify_dkim_2048(header, header_length, pubkey, pubkey_redc, signature);

  // manually extract the body hash from the header
  let body_hash_encoded = get_body_hash_by_index(header, body_hash_index);
  let signed_body_hash: [u8; 32] = body_hash_base64_decode(body_hash_encoded);

  // finish the partial hash
  let computed_body_hash = partial_sha256_var_end(partial_body_hash, body, partial_body_length as u64, body_length as u64);    

  // check the body hashes match
  assert(
      signed_body_hash == computed_body_hash, "Sha256 hash computed over body does not match DKIM-signed header"
  );
...
```

### Extracting Email Addresses

In the header, email addresses can appear in a variety of formats: 
 * `"name" <local-part@domain.com>`
 * `name <local-part@domain.com>`
 * `name local-part@domain.com`
 * `local-part@domain.com`
Without regex, we take a slightly different approach. 


Find examples of each implementation in the [examples](./examples) folder.


## Using the Input Generation JS Library

Install the library:
```console
yarn add @mach-34/zkemail-nr
```

### Usage
See the [witness simulation](./js/tests/circuits.test.ts) and [proving](./js/tests/proving.test.ts) tests for an in-depth demonstration of each use case.

```js
// example of generating inputs for a partial hash
import { generateEmailVerifierInputs } from "@mach-34/zkemail-nr";

const zkEmailInputs = await generateEmailVerifierInputs(emailContent, {
  maxBodyLength: 1280,
  maxHeadersLength: 1408,
  shaPrecomputeSelector: "some string in body up to which you want to hash outside circuit",
});

```

## Using ZKEmail.nr in EVM Smart Contracts
TODO

## Using ZKEmail.nr in Aztec Smart Contracts
TODO

## Todo
 - Negative Unit Testing
 - Expected InputGen testing
 - EVM Contract tests for email integration
 - Aztec Contract tests for email integration
 - 1024-bit key demo eml (current one is sensitive and cannot be provided in public repo)
 - Implementation with Regex
 - Add constraint estimations and benchmarking
 - Add native proving scripts
 - Macro Impl

### Proposed Macro Impl
```rust
// zkemail attribute would automatically inject fields
// header: BoundedVec<u8, MAX_HEADER_LEN>,
// pubkey: RSAPubkey<KEY_LIMBS>,
// signature: [Field; KEY_LIMBS]
// and add range check header.len() + pubkey::verify_rsa_signature
// it then would add additional necessary fields for each trait, add the 
#[zkemail(PartialHash, From, DKIMHash, Nullifier)]
let Input<let MAX_HEADER_LENGTH: u32, let MAX_BODY_LEN: u32, let KEY_LIMBS: u32> {};
//fn main(input: Input) {
//    input.verify()
//}
```

By [Mach-34](https://mach34.space)