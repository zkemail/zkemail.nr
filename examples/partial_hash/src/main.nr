use dep::zkemail::{
    KEY_LIMBS_2048, dkim::verify_dkim_2048, body_hash::{get_body_hash_by_index, compare_body_hash},
    standard_outputs
};

global MAX_EMAIL_HEADER_LENGTH: u32 = 512;
global MAX_EMAIL_BODY_LENGTH: u32 = 128;

/**
 * Verify an arbitrary email signed by a 1024-bit RSA DKIM signature
 *
 * @param body_hash_index - The index of the body hash in the partial hash array
 * @param header - The email header, 0-padded at end to the MAX_EMAIL_HEADER_LENGTH
 * @param header_length - The actual length of the email header
 * @param body - The email body, 0-padded at end to the MAX_EMAIL_BODY_LENGTH
 * @param body_length - The actual length of the email body
 * @param pubkey_modulus_limbs - The DKIM RSA Pubkey
 * @param redc_params_limbs - Barrett Reduction Parameter for Pubkey for efficient signature verification
 * @param signature - The DKIM RSA Signature
 * @return - 
 *         0: Pedersen hash of DKIM public key (root of trust)
 *         1: Pedersen hash of DKIM signature (email nullifier)
 */
fn main(
    body_hash_index: u32,
    header: [u8; MAX_EMAIL_HEADER_LENGTH],
    header_length: u32,
    body: [u8; MAX_EMAIL_BODY_LENGTH],
    body_length: u32,
    partial_body_hash: [u8; 32],
    pubkey: [Field; KEY_LIMBS_2048],
    pubkey_redc: [Field; KEY_LIMBS_2048],
    signature: [Field; KEY_LIMBS_2048]
) -> pub [Field; 2] {
    // check the body and header lengths are within bounds
    assert(header_length <= MAX_EMAIL_HEADER_LENGTH);
    assert(body_length <= MAX_EMAIL_BODY_LENGTH);

    // verify the dkim signature over the header
    verify_dkim_2048(header, header_length, pubkey, pubkey_redc, signature);

    // manually extract the body hash from the header
    let body_hash_encoded = get_body_hash_by_index(header, body_hash_index);

    // compare the retrieved body hash to the computed body hash
    compare_body_hash(body_hash_encoded, body, body_length);

    // hash the pubkey and signature for the standard outputs
    standard_outputs(pubkey, signature)
}
