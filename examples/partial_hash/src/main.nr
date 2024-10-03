use dep::zkemail::{
    KEY_LIMBS_2048, dkim::verify_dkim_2048, get_body_hash_by_index, base64::body_hash_base64_decode,
    partial_hash::partial_sha256_var_end, standard_outputs
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
    body_hash_index: u32,
    header: [u8; MAX_EMAIL_HEADER_LENGTH],
    header_length: u32,
    body: [u8; MAX_PARTIAL_EMAIL_BODY_LENGTH], // use partial body length instead of full body length
    body_length: u32,
    partial_body_hash: [u32; 8],
    partial_body_length: u32,
    pubkey: [Field; KEY_LIMBS_2048],
    pubkey_redc: [Field; KEY_LIMBS_2048],
    signature: [Field; KEY_LIMBS_2048]
) -> pub [Field; 2] {
    // check the body and header lengths are within bounds
    assert(header_length <= MAX_EMAIL_HEADER_LENGTH, "Email header length exceeds maximum length");
    assert(partial_body_length <= MAX_PARTIAL_EMAIL_BODY_LENGTH, "Partial email body length exceeds maximum length");
    
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

    // hash the pubkey and signature for the standard outputs
    standard_outputs(pubkey, signature)
}
