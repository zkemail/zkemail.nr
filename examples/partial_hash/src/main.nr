use std::hash::pedersen_hash;
use zkemail::{
    dkim::RSAPubkey, headers::body_hash::get_body_hash, KEY_LIMBS_2048,
    partial_hash::partial_sha256_var_end, Sequence,
};

global MAX_EMAIL_HEADER_LENGTH: u32 = 512;
global MAX_PARTIAL_EMAIL_BODY_LENGTH: u32 = 192;

/**
 * Verify an arbitrary email signed by a 1024-bit RSA DKIM signature
 *
 * @param body_hash_index - The index of the body hash in the partial hash array
 * @param header - The email header, 0-padded at end to the MAX_EMAIL_HEADER_LENGTH
 * @param header_length - The actual length of the email header
 * @param body - The remaining email body, 0-padded at end to the MAX_PARTIAL_EMAIL_BODY_LENGTH
 * @param body_length - The full length of the email body
 * @param partial_body_hash - The SHA256 state of the partially hashed body
 * @param partial_body_length - The remaining length of the email body to hash
 * @param pubkey_modulus_limbs - The DKIM RSA Pubkey
 * @param redc_params_limbs - Barrett Reduction Parameter for Pubkey for efficient signature verification
 * @param signature - The DKIM RSA Signature
 * @return - 
 *         0: Pedersen hash of DKIM public key (root of trust)
 *         1: Pedersen hash of DKIM signature (email nullifier)
 */
fn main(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    body: BoundedVec<u8, MAX_PARTIAL_EMAIL_BODY_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    body_hash_index: u32,
    dkim_header_sequence: Sequence,
    partial_body_hash: [u32; 8],
    partial_body_real_length: u64,
) -> pub [Field; 2] {
    // check the body and header lengths are within bounds
    assert(header.len() <= MAX_EMAIL_HEADER_LENGTH, "Email header length exceeds maximum length");
    assert(
        body.len() <= MAX_PARTIAL_EMAIL_BODY_LENGTH,
        "Partial email body length exceeds maximum length",
    );

    // verify the dkim signature over the header
    pubkey.verify_dkim_signature(header, signature);

    // manually extract the body hash from the header
    let signed_body_hash = get_body_hash(header, dkim_header_sequence, body_hash_index);

    // finish the partial hash
    let computed_body_hash = partial_sha256_var_end(
        partial_body_hash,
        body.storage(),
        body.len() as u64,
        partial_body_real_length,
    );

    // check the body hashes match
    assert(
        signed_body_hash == computed_body_hash,
        "Sha256 hash computed over body does not match DKIM-signed header",
    );

    // hash the pubkey and signature for the standard outputs
    let email_nullifier = pedersen_hash(signature);
    [pubkey.hash(), email_nullifier]
}
