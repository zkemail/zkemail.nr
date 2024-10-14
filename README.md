## ZKEmail.nr
ZKEmail written in [NoirLang](https://noir-lang.org/)

## Using the Noir Library

In your Nargo.toml file, add the version of this library you would like to install under dependency:

```
[dependencies]
zkemail = { tag = "v0.3.1", git = "https://github.com/zkemail/zkemail.nr", directory = "lib" }
```

The library exports the following functions:
- `verify_dkim_1024` and `verify_dkim_2048` -  for verifying DKIM signatures over an email header. This is needed for all email verifications.
- `get_body_hash_by_index` - to get the body hash from the header.
- `body_hash_base64_decode` - to decode the body hash from the header.
- Above two methods are needed to verify the body hash of an email. This is only needed if you want to contrain something over the email body.
- `standard_outputs` - returns the hash of the DKIM pubkey and a nullifier for the email (`hash(signature)`)


```
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

You can use partial hashing technique for email with large body when the part you want to contrain in the body is towards the end.

Since SHA works in chunks of 64 bytes, we can hash the body up to the chunk from where we want to extract outside of the circuit and do the remaining hash in the circuit. This will save a lot of constraints as SHA is very expensive in circuit.

```
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

Find more examples in the [examples](./examples) folder.


## Using the Input Generation JS Library

Install the library:
```
yarn add @mach-34/zkemail-nr
```

### Usage

```
import { generateEmailVerifierInputs } from "@mach-34/zkemail-nr";

const zkEmailInputs = await generateEmailVerifierInputs(emailContent, {
  maxBodyLength: 1280, // Same as MAX_PARTIAL_EMAIL_BODY_LENGTH in circuit
  maxHeadersLength: 1408, // Same as MAX_EMAIL_HEADER_LENGTH in circuit
  shaPrecomputeSelector: "some string in body up to which you want to hash outside circuit", // if you want to use partial hashing
});

```

## Using ZKEmail.nr in EVM Smart Contracts
TODO

## Using ZKEmail.nr in Aztec Smart Contracts
TODO

## Todo
 - Negative Unit Testing
 - Expected InputGen testing
 - Robust from/ to string search implementation
 - Contract/ testing for UltraPlonk reintegrated
 - EVM Contract tests for email integration
 - Aztec Contract tests for email integration
 - 1024-bit key demo eml (current one is sensitive and cannot be provided in public repo)
 - DKIM Key pedersen hash function
 - Handle optional inputs (partial hashing, no body check, etc) gracefully again
 - Partial SHA256 hashing
 - Implementation with Regex 
 - test does not exit on completion?