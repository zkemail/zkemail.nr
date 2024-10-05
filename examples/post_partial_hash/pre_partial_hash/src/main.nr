use dep::zkemail::{
    KEY_LIMBS_2048, dkim::verify_dkim_2048, get_body_hash_by_index, base64::body_hash_base64_decode,
    partial_hash::partial_sha256_var_start
};
use dep::std::hash::sha256_var;

mod utils;

global MAX_EMAIL_HEADER_LENGTH: u32 = 512;
global MAX_EMAIL_BODY_LENGTH: u32 = 64;

/**
 * Verify an arbitrary email signed by a 2048-bit RSA DKIM signature
 * Only hash the first (64) bytes of the email body and defer the rest to the receipient
 *
 * @param body_hash_index - The index of the body hash in the partial hash array
 * @param header - The email header, 0-padded at end to the MAX_EMAIL_HEADER_LENGTH
 * @param header_length - The actual length of the email header
 * @param body - The beginning of the email body to be partially hashed (and accessed potentially)
 * @param pubkey_modulus_limbs - The DKIM RSA Pubkey
 * @param redc_params_limbs - Barrett Reduction Parameter for Pubkey for efficient signature verification
 * @param signature - The DKIM RSA Signature
 * @return - 
 *         0: Pedersen hash of DKIM public key (root of trust)
 *         1: Pedersen hash of DKIM signature (email nullifier)
 *         2: the 
 */
 #[recursive]
fn main(
    body_hash_index: u32,
    header: [u8; MAX_EMAIL_HEADER_LENGTH],
    header_length: u32,
    body: [u8; MAX_EMAIL_BODY_LENGTH],
    pubkey: [Field; KEY_LIMBS_2048],
    pubkey_redc: [Field; KEY_LIMBS_2048],
    signature: [Field; KEY_LIMBS_2048]
) -> pub [Field; 7] {
    // check the body and header lengths are within bounds
    assert(header_length <= MAX_EMAIL_HEADER_LENGTH);

    // verify the dkim signature over the header
    verify_dkim_2048(header, header_length, pubkey, pubkey_redc, signature);

    // extract the body hash from the header
    let body_hash_encoded = get_body_hash_by_index(header, body_hash_index);

    // base64 decode the body hash
    let signed_body_hash: [u8; 32] = body_hash_base64_decode(body_hash_encoded);

    // start the partial computation of the body hash
    let partial_body_hash = partial_sha256_var_start(body);

    // hash the pubkey and signature for the standard outputs
    utils::serialize_output(partial_body_hash, signed_body_hash, pubkey, signature)
}
