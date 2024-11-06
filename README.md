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
- `headers::constrain_header_field` - constrain an index/ length in the header to be the correct name, full, and uninterrupted
- `partial_hash::partial_sha256_var_end` - finish a precomputed sha256 hash over the body
- `masking::mask_text` - apply a byte mask to the header or body to selectively reveal parts of the entire email
- `standard_outputs` - returns the hash of the DKIM pubkey and a nullifier for the email (`hash(signature)`)

Additionally, the `@zk-email/zkemail-nr` JS library exports an ergonomic API for easily deriving circuit inputs needed to utilize the Noir library.

For demonstrations of all functionality, see the [examples](./examples).

### Basic Email Verification
A basic email verifier will often look like this:
```rust
use dep::zkemail::{
    KEY_LIMBS_1024, dkim::RSAPubkey, get_body_hash_by_index,     
    base64::body_hash_base64_decode, standard_outputs
};
use dep::std::hash::sha256_var;

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
use dep::zkemail::{
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
use dep::zkemail::get_email_address;
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


## Using the JS Library

Install the library:
```console
yarn add @zk-email/zkemail-nr
```

The JS library provides all the necessary methods needed to convert a raw email (that you can download in .eml format from your service provider such as gmail) into:
1. intermediate input generation: an intermediate form of arrays of numeric/ field values that are then an input to the circuit
2. from these intermediate inputs to proof generated from the circuit using a prover method
3. verify the proof generated

Support of all of the above lets you fully prove and verify an email in various configurations. 
This is explained with an example email provided below.

Here's a [raw email](./js/tests/test-data/email-good.eml):
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=icloud.com; s=1a1hai; t=1693038337; bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=; h=from:Content-Type:Mime-Version:Subject:Message-Id:Date:to; b=EhLyVPpKD7d2/+h1nrnu+iEEBDfh6UWiAf9Y5UK+aPNLt3fAyEKw6Ic46v32NOcZD
	 M/zhXWucN0FXNiS0pz/QVIEy8Bcdy7eBZA0QA1fp8x5x5SugDELSRobQNbkOjBg7Mx
	 VXy7h4pKZMm/hKyhvMZXK4AX9fSoXZt4VGlAFymFNavfdAeKgg/SHXLds4lOPJV1wR
	 2E21g853iz5m/INq3uK6SQKzTnz/wDkdyiq90gC0tHQe8HpDRhPIqgL5KSEpuvUYmJ
	 wjEOwwHqP6L3JfEeROOt6wyuB1ah7wgRvoABOJ81+qLYRn3bxF+y1BC+PwFd5yFWH5
	 Ry43lwp1/3+sA==
from: runnier.leagues.0j@icloud.com
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3731.500.231\))
Subject: Hello
Message-Id: <8F819D32-B6AC-489D-977F-438BBC4CAB27@me.com>
Date: Sat, 26 Aug 2023 12:25:22 +0400
to: zkewtest@gmail.com

Hello,

How are you?
```
It is converted to intermediate numeric inputs:
```
Header Array: 102,114,111,109,58,114,117,110,110,105,101,114,46,108,101,97,103,117,101,115,46,48,106,64,105,99,108,111,117,100,46,99,111,109,13,10,99,111,110,116,101,110,116,45,116,121,112,101,58,116,101,120,116,47,112,108,97,105,110,59,32,99,104,97,114,115,101,116,61,117,115,45,97,115,99,105,105,13,10,109,105,109,101,45,118,101,114,115,105,111,110,58,49,46,48,32,40,77,97,99,32,79,83,32,88,32,77,97,105,108,32,49,54,46,48,32,92,40,51,55,51,49,46,53,48,48,46,50,51,49,92,41,41,13,10,115,117,98,106,101,99,116,58,72,101,108,108,111,13,10,109,101,115,115,97,103,101,45,105,100,58,60,56,70,56,49,57,68,51,50,45,66,54,65,67,45,52,56,57,68,45,57,55,55,70,45,52,51,56,66,66,67,52,67,65,66,50,55,64,109,101,46,99,111,109,62,13,10,100,97,116,101,58,83,97,116,44,32,50,54,32,65,117,103,32,50,48,50,51,32,49,50,58,50,53,58,50,50,32,43,48,52,48,48,13,10,116,111,58,122,107,101,119,116,101,115,116,64,103,109,97,105,108,46,99,111,109,13,10,100,107,105,109,45,115,105,103,110,97,116,117,114,101,58,118,61,49,59,32,97,61,114,115,97,45,115,104,97,50,53,54,59,32,99,61,114,101,108,97,120,101,100,47,114,101,108,97,120,101,100,59,32,100,61,105,99,108,111,117,100,46,99,111,109,59,32,115,61,49,97,49,104,97,105,59,32,116,61,49,54,57,51,48,51,56,51,51,55,59,32,98,104,61,55,120,81,77,68,117,111,86,86,85,52,109,48,87,48,87,82,86,83,114,86,88,77,101,71,83,73,65,83,115,110,117,99,75,57,100,74,115,114,99,43,118,85,61,59,32,104,61,102,114,111,109,58,67,111,110,116,101,110,116,45,84,121,112,101,58,77,105,109,101,45,86,101,114,115,105,111,110,58,83,117,98,106,101,99,116,58,77,101,115,115,97,103,101,45,73,100,58,68,97,116,101,58,116,111,59,32,98,61,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,14,192,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

Public Key (hex): (17) ['0x1193246589579230900252592422628472491', '0x1912823282459999274635310959025610339', '0x228304836181961761332702133760551800', '0x1287038673397707587809245808290310449', '0x847074879946527390340198003742080773', '0x1772812153284093774405261558543107601', '0x2378977728746033746331898306280144326', '0x997340440570508925167107712120786203', '0x857890276578197729951598293684046411', '0x745957132893515948993812065378390023', '0x11826361521340558402809758375801001', '0x1557958282669079306798259837263810673', '0x464398925464156428943676686705206575', '0x753583552319818198558893360085614180', '0x618649414253799015348495001053509399', '0x1673527244268347429413713439917472261', '0x4331651056499387160391393057762229']

Signature (hex): (17) ['0x454199870357587480887872582246596272', '0x2527336896821663183109874261190756320', '0x305669919670959025780473692262765449', '0x396197978309222674377234633495999015', '0x2305999751176063928824162179301162310', '0x549402302972866181705237186901085827', '0x1787385402973427706080900445160902699', '0x1370301041815322743450239257262604909', '0x1863346642222243427409360606128628384', '0x795556012935482925844757803421308171', '0x1081087375996457005248580316311364774', '0x706186279002171422749364117846958915', '0x1563729408982255657241502858528971011', '0x2251656200947406010169813942246500036', '0x1296204206818418929335952479462075383', '0x2481679741009209007932436093105982085', '0x366584477895090251126754992561849']
```
Which is then converted to a zk proof by passing as inputs to the Noir circuit (this can be a standard zkemail.nr circuit or a custom circuit both can be handled using the JS library)
The proof can be used to verify if it is valid or not.

### Usage
See the [witness simulation](./js/tests/circuits.test.ts) and [proving](./js/tests/proving.test.ts) tests for an in-depth demonstration of each use case.

Explaining some of the key usage from above, namely [proving](./js/tests/proving.test.ts) tests:

1. Generate inputs from raw email:
```js
import { generateEmailVerifierInputs } from "@zk-email/zkemail-nr";

const zkEmailInputs = await generateEmailVerifierInputs(emailContent, {
  maxHeadersLength: 512,
  maxBodyLength: 1024,
});
```

2. Import and use the JSProver to generate and verify proofs:
```js
import { ZKEmailProver } from "@zk-email/zkemail-nr/dist/prover";

// Initialize prover
let prover: ZKEmailProver;

// Generate proof
const proof = await prover.fullProve(inputs);

// Verify proof
const result = await prover.verify(proof);
expect(result).toBeTruthy();
```

Note: If you have a custom circuit in noir that you want to pass inputs to (after generating them from generateEmailVerifierInputs), you may also use @noir/noir-js methods for circuit initialization, proving and verification.


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