use dep::rsa::bignum::fields::{Params1024, Params2048};
use dep::rsa::bignum::runtime_bignum::BigNumInstance;
use dep::rsa::types::RSA;
use dep::rsa::bignum::BigNum;
use dep::std::hash::sha256_var;
use dep::std::collections::bounded_vec::BoundedVec;
use crate::{KEY_LIMBS_1024, KEY_LIMBS_2048, KEY_BYTES_1024, KEY_BYTES_2048, RSA_EXPONENT};

type BN1024 = BigNum<KEY_LIMBS_1024, Params1024>;
type RSA1024 = RSA<BN1024, BigNumInstance<KEY_LIMBS_1024, Params1024>, KEY_BYTES_1024>;
type BN2048 = BigNum<KEY_LIMBS_2048, Params2048>;
type RSA2048 = RSA<BN2048, BigNumInstance<KEY_LIMBS_2048, Params2048>, KEY_BYTES_2048>;

/**
 * Verify a 1024-bit RSA (DKIM) signature over an email header
 * 
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header, 0-padded to the maximum possible length for this circuit
 * @param header_length - The actual length of the email header
 * @param pubkey_modulus_limbs - The DKIM RSA Pubkey
 * @param redc_params_limbs - Barrett Reduction Parameter for Pubkey for efficient signature verification
 * @param signature - The DKIM RSA Signature 
 */
pub fn verify_dkim_1024<let MAX_HEADER_LENGTH: u32>(
    header: [u8; MAX_HEADER_LENGTH],
    header_length: u32,
    pubkey: [Field; KEY_LIMBS_1024],
    pubkey_redc: [Field; KEY_LIMBS_1024],
    signature: [Field; KEY_LIMBS_1024]
) {
    // check the header length is within bounds
    assert(header_length <= MAX_HEADER_LENGTH);

    // instantiate the BNInstance for the pubkey
    let pubkey: BigNumInstance<KEY_LIMBS_1024, Params1024> = BigNumInstance::new(pubkey, pubkey_redc);

    // instantiate BN for the signature
    let signature: BN1024 = BigNum::from_array(signature);

    // hash the header
    let header_hash = sha256_var(header, header_length as u64);

    // verify the DKIM signature over the header
    let rsa: RSA1024 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(pubkey, header_hash, signature, RSA_EXPONENT));
}

/**
 * Verify a 1024-bit RSA (DKIM) signature over an email header
 * 
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header, 0-padded to the maximum possible length for this circuit
 * @param header_length - The actual length of the email header
 * @param pubkey_modulus_limbs - The DKIM RSA Pubkey
 * @param redc_params_limbs - Barrett Reduction Parameter for Pubkey for efficient signature verification
 * @param signature - The DKIM RSA Signature 
 */
pub fn verify_dkim_2048<let MAX_HEADER_LENGTH: u32>(
    header: [u8; MAX_HEADER_LENGTH],
    header_length: u32,
    pubkey: [Field; KEY_LIMBS_2048],
    pubkey_redc: [Field; KEY_LIMBS_2048],
    signature: [Field; KEY_LIMBS_2048]
) {
    // check the header length is within bounds
    assert(header_length <= MAX_HEADER_LENGTH);

    // instantiate the BNInstance for the pubkey
    let pubkey: BigNumInstance<KEY_LIMBS_2048, Params2048> = BigNumInstance::new(pubkey, pubkey_redc);

    // instantiate BN for the signature
    let signature: BN2048 = BigNum::from_array(signature);

    // hash the header
    let header_hash = sha256_var(header, header_length as u64);

    // verify the DKIM signature over the header
    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(pubkey, header_hash, signature, RSA_EXPONENT));
}
