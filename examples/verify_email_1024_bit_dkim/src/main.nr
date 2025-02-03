use std::{collections::bounded_vec::BoundedVec, hash::{pedersen_hash, sha256_var}};
use zkemail::{dkim::RSAPubkey, headers::body_hash::get_body_hash, KEY_LIMBS_1024, Sequence};

global MAX_EMAIL_HEADER_LENGTH: u32 = 512;
global MAX_EMAIL_BODY_LENGTH: u32 = 1024;

/**
 * Verify an arbitrary email signed by a 1024-bit RSA DKIM signature
 * @dev TOTAL CONSTRAINTS: ~222,783
 *
 * @param header - The email header, 0-padded at end to the MAX_EMAIL_HEADER_LENGTH
 * @param body - The email body, 0-padded at end to the MAX_EMAIL_BODY_LENGTH
 * @param pubkey - The DKIM RSA Public Key modulus and reduction parameter
 * @param signature - The DKIM RSA Signature
 * @param body_hash_index - The index of the body hash in the partial hash array
 * @param dkim_header_sequence - The index and length of the DKIM header field
 * @return - 
 *         0: Pedersen hash of DKIM public key (root of trust)
 *         1: Pedersen hash of DKIM signature (email nullifier)
 */
fn main(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    body: BoundedVec<u8, MAX_EMAIL_BODY_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_1024>,
    signature: [Field; KEY_LIMBS_1024],
    body_hash_index: u32,
    dkim_header_sequence: Sequence,
) -> pub [Field; 2] {
    // check the body and header lengths are within bounds
    assert(header.len() <= MAX_EMAIL_HEADER_LENGTH);
    assert(body.len() <= MAX_EMAIL_BODY_LENGTH);

    // verify the dkim signature over the header
    pubkey.verify_dkim_signature(header, signature);

    // extract the body hash from the header
    let signed_body_hash = get_body_hash(header, dkim_header_sequence, body_hash_index);

    // hash the asserted body
    let computed_body_hash: [u8; 32] = sha256_var(body.storage(), body.len() as u64);

    // compare the body hashes
    assert(
        signed_body_hash == computed_body_hash,
        "SHA256 hash computed over body does not match body hash found in DKIM-signed header",
    );

    // hash the pubkey and signature for the standard outputs
    let email_nullifier = pedersen_hash(signature);
    [pubkey.hash(), email_nullifier]
}
