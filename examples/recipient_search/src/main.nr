// use dep::zkemail::{
//     KEY_LIMBS_2048, dkim::verify_dkim_2048,
//     standard_outputs
// };

// global MAX_EMAIL_HEADER_LENGTH: u32 = 1024;
// global MAX_EMAIL_BODY_LENGTH: u32 = 1536;

// /**
//  * Verify an arbitrary email signed by a 1024-bit RSA DKIM signature
//  *
//  * @param body_hash_index - The index of the body hash in the partial hash array
//  * @param header - The email header, 0-padded at end to the MAX_EMAIL_HEADER_LENGTH
//  * @param header_length - The actual length of the email header
//  * @param body - The email body, 0-padded at end to the MAX_EMAIL_BODY_LENGTH
//  * @param body_length - The actual length of the email body
//  * @param pubkey_modulus_limbs - The DKIM RSA Pubkey
//  * @param redc_params_limbs - Barrett Reduction Parameter for Pubkey for efficient signature verification
//  * @param signature - The DKIM RSA Signature
//  * @return - 
//  *         0: Pedersen hash of DKIM public key (root of trust)
//  *         1: Pedersen hash of DKIM signature (email nullifier)
//  */
// fn main(
//     header: [u8; MAX_EMAIL_HEADER_LENGTH],
//     header_length: u32,
//     pubkey: [Field; KEY_LIMBS_2048],
//     pubkey_redc: [Field; KEY_LIMBS_2048],
//     signature: [Field; KEY_LIMBS_2048]
// ) -> pub [Field; 2] {
//     // check the body and header lengths are within bounds
//     assert(header_length <= MAX_EMAIL_HEADER_LENGTH);

//     // verify the dkim signature over the header
//     verify_dkim_2048(header, header_length, pubkey, pubkey_redc, signature);

//     // check the recipient email address
//     // todo

//     // hash the pubkey and signature for the standard outputs
//     standard_outputs(pubkey, signature)
// }

fn main() -> pub bool{
    1 + 1 == 2
}