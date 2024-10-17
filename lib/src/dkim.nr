use dep::std::{collections::bounded_vec::BoundedVec, hash::sha256_var, panic::panic};
use dep::rsa::{
    bignum::{fields::{Params1024, Params2048}, runtime_bignum::BigNumInstance, BigNum},
    types::RSA
};
use crate::{KEY_LIMBS_1024, KEY_BYTES_1024, KEY_LIMBS_2048, KEY_BYTES_2048, RSA_EXPONENT, RSAPubkey};

type BN1024 = BigNum<KEY_LIMBS_1024, Params1024>;
type RSA1024 = RSA<BN1024, BigNumInstance<KEY_LIMBS_1024, Params1024>, KEY_BYTES_1024>;
type BN2048 = BigNum<KEY_LIMBS_2048, Params2048>;
type RSA2048 = RSA<BN2048, BigNumInstance<KEY_LIMBS_2048, Params2048>, KEY_BYTES_2048>;

// pub comptime fn rsa_verification_params<let KEY_LIMBS: u32>() -> Quoted {
//     assert((KEY_LIMBS == 1024) | (KEY_LIMBS == 2048), "Invalid key size");
//     if KEY_LIMBS == KEY_LIMBS_1024 {
//         quote {
//             type Params = Params1024; 
//             type BN = BigNum<KEY_LIMBS_1024, Params1024;
//             type RSA = RSA_TYPE<BN, BigNumInstance<KEY_LIMBS_1024, Params1024>, KEY_BYTES_1024>;
//         }
//     } else {
//         quote { 
//             type Params = Params2048;
//             type BN = BigNum<KEY_LIMBS_1024, Params1024;
//             type RSA = RSA_TYPE<BN, BigNumInstance<KEY_LIMBS_1024, Params1024>, KEY_BYTES_1024>;
//         }
//     }
//     // params.append(quote {
//     //     // instantiate the BNInstance for the pubkey
//     //     let pubkey: BigNumInstance<KEY_LIMBS, Params> = BigNumInstance::new($pubkey.pubkey, $pubkey.redc);
//     //     // instantiate BN for the signature
//     //     let signature: BN = BigNum::from_array($signature);
//     //     // hash the header
//     //     let header_hash = sha256_var($header, $header.len() as u64);
//     //     // verify the DKIM signature over the header
//     //     let rsa: RSA = RSA {};
//     //     assert(rsa.verify_sha256_pkcs1v15(pubkey, header_hash, signature, RSA_EXPONENT));
//     // })
// }

// pub comptime fn verify_two(f: FunctionDefinition) {

//     let mut body = f.body().as_block().unwrap();

// }

// #[verify_two]
// pub fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32, let KEY_LIMBS: u32>(
//     header: BoundedVec<u8, MAX_HEADER_LENGTH>,
//     pubkey: RSAPubkey<KEY_LIMBS>,
//     signature: [Field; KEY_LIMBS]
// ) {
//     // macro to set types by key size
//     rsa_verification_params::<KEY_LIMBS>!();

//     let pubkey: BigNumInstance<KEY_LIMBS, Params> = BigNumInstance::new(pubkey.pubkey, pubkey.redc);

//     // instantiate BN for the signature
//     let signature: BN = BigNum::from_array(signature);

//     // hash the header
//     let header_hash = sha256_var(header, header.len() as u64);

//     // verify the DKIM signature over the header
//     let rsa: RSA = RSA {};
//     assert(rsa.verify_sha256_pkcs1v15(pubkey, header_hash, signature, RSA_EXPONENT));
// }

/**
 * Verify a 1024-bit RSA (DKIM) signature over an email header
 * 
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header as a bounded vector containing the length
 * @param pubkey- the RSA modulus and barrett reduction parameter for the dkim signing key
 * @param signature - The DKIM RSA 1024-bit Signature 
 */
pub fn verify_dkim_1024<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_1024>,
    signature: [Field; KEY_LIMBS_1024]
) {
    // hash the header
    let header_hash = sha256_var(header.storage, header.len() as u64);

    // instantiate the BNInstance for the pubkey
    // todo: make as BigNumInstance from the outset to reduce some work
    let pubkey: BigNumInstance<KEY_LIMBS_1024, Params1024> = BigNumInstance::new(pubkey.modulus, pubkey.redc);

    // instantiate BN for the signature
    let signature: BN1024 = BigNum::from_array(signature);

    // verify the DKIM signature over the header
    let rsa: RSA1024 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(pubkey, header_hash, signature, RSA_EXPONENT));
}

/**
 * Verify a 2048-bit RSA (DKIM) signature over an email header
 * 
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header as a bounded vector containing the length
 * @param pubkey- the RSA modulus and barrett reduction parameter for the dkim signing key
 * @param signature - The DKIM RSA 2048-bit Signature 
 */
pub fn verify_dkim_2048<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048]
) {
    // check the header length is within bounds
    assert(header.len() <= MAX_HEADER_LENGTH);

    // instantiate the BNInstance for the pubkey
    let pubkey: BigNumInstance<KEY_LIMBS_2048, Params2048> = BigNumInstance::new(pubkey.modulus, pubkey.redc);

    // instantiate BN for the signature
    let signature: BN2048 = BigNum::from_array(signature);

    // hash the header
    let header_hash = sha256_var(header.storage, header.len() as u64);

    // verify the DKIM signature over the header
    let rsa: RSA2048 = RSA {};
    assert(rsa.verify_sha256_pkcs1v15(pubkey, header_hash, signature, RSA_EXPONENT));
}
