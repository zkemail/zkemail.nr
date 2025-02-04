## ZKEmail.nr
ZKEmail written in [NoirLang](https://noir-lang.org/)

## Using the Noir Library

In your Nargo.toml file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
zkemail = { tag = "v0.4.2", git = "https://github.com/zkemail/zkemail.nr", directory = "lib" }
```

The library exports the following functions:
- `dkim::RSAPubkey::verify_dkim_signature` -  for verifying DKIM signatures over an email header. This is needed for all email verifications.
- `headers::body_hash::get_body_hash` - constrained access and decoding of the body hash from the header
- `headers::email_address::get_email_address` - constrained extraction of to or from email addresses
- `headers::constrain_header_field` - constrain an index/ length in the header to be the correct name, full, and uninterrupted
- `partial_hash::partial_sha256_var_end` - finish a precomputed sha256 hash over the body
- `masking::mask_text` - apply a byte mask to the header or body to selectively reveal parts of the entire email

Additionally, the `@zk-email/zkemail-nr` JS library exports an ergonomic API for easily deriving circuit inputs needed to utilize the Noir library.

For demonstrations of all functionality, see the [examples](./examples).

### Basic Email Verification
A basic email verifier will often look like this:
```rust
use zkemail::{
    KEY_LIMBS_1024, dkim::RSAPubkey, get_body_hash_by_index,     
    base64::body_hash_base64_decode
};
use std::hash::{sha256_var, pedersen_hash};

// Somewhere in your function
...
  // verify the dkim signature over the asserted header
  pubkey.verify_dkim_signature(header, signature);
  // extract the body hash from the header
  let signed_body_hash = get_body_hash(header, dkim_header_sequence, body_hash_index);
  // compute the sha256 hash of the asserted body
  let computed_body_hash: [u8; 32] = sha256_var(body.storage, body.len() as u64);
  // constain the computed body hash to match the one found in the header
  assert(
    signed_body_hash == computed_body_hash,
    "SHA256 hash computed over body does not match body hash found in DKIM-signed header"
  );
...
```
From here, you can operate on the header or body with guarantees that the accessed text was signed by the DKIM key.

You may also have an email where you need access to the header, but not the body. You can simply omit everything after `verify_dkim_signature` and proceed!

### Usage with partial SHA

You can use partial hashing technique for email with large body when the part you want to constrain in the body is towards the end.

Since SHA works in chunks of 64 bytes, we can hash the body up to the chunk from where we want to extract outside of the circuit and do the remaining hash in the circuit. This will save a lot of constraints as SHA is very expensive in circuit (~100 constraints/ byte).

```rust
use zkemail::{
    KEY_LIMBS_2048, dkim::RSAPubkey, headers::body_hash::get_body_hash,
    partial_hash::partial_sha256_var_end
};

...
  // verify the dkim signature over the asserted header
  pubkey.verify_dkim_signature(header, signature);
  // extract the body hash from the header
  let signed_body_hash = get_body_hash(header, dkim_header_sequence, body_hash_index);
  // finish the partial hash
  let computed_body_hash = partial_sha256_var_end(partial_body_hash, body.storage(), body.len() as u64, partial_body_real_length);   
  // constain the computed body hash to match the one found in the header
  assert(
    signed_body_hash == computed_body_hash,
    "SHA256 hash computed over body does not match body hash found in DKIM-signed header"
  );
...
```

### Extracting Email Addresses

To and from email addresses can be extracted from the header with `get_email_address`
```rust
use zkemail::get_email_address;
...
  // define the header field to access (set "to" or "from")
  let to = comptime { "to".as_bytes() };
  // constrained retrieval of the email header
  let to_address = get_email_address(header, to_header_sequence, to_address_sequence, to);
...
```
`to_address` is a "BoundedVec", meaning the output of a parsed email address "zkemail@prove.email" would export
```json
{
  "storage": [122, 107, 101, 109,  97, 105, 108,  64, 112, 114, 111, 118, 101,  46, 101, 109,  97, 105, 108, 0, ..., 0],
  "len": 19
}
```
which is easily interpreted with `Buffer.from(output.storage.slice(0, output.storage.len)).toString()`. You can additionally perform your own transformations or commitments in-circuit.


## Using the Input Generation JS Library

Install the library:
```console
yarn add @zk-email/zkemail-nr
```

### Usage
See the [witness simulation](./js/tests/circuits.test.ts) and [proving](./js/tests/proving.test.ts) tests for an in-depth demonstration of each use case.

```js
// example of generating inputs for a partial hash
import { generateEmailVerifierInputs } from "@zk-email/zkemail-nr";

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
 - Expected InputGen testing
 - EVM Contract tests for email integration
 - Aztec Contract tests for email integration
 - 1024-bit key demo eml (current one is sensitive and cannot be provided in public repo)
 - Implementation with Regex
 - Add constraint estimations and benchmarking
 - Add native proving scripts
 - Macro Impl

By [Mach-34](https://mach34.space)
