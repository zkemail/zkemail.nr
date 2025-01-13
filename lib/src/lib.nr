use crate::dkim::RSAPubkey;
use std::hash::pedersen_hash;

pub mod dkim;
pub mod headers;
pub mod masking;
pub mod partial_hash;
pub mod remove_soft_line_breaks;
// mod macro;
mod tests;

global RSA_EXPONENT: u32 = 65537;
global KEY_LIMBS_1024: u32 = 9;
global KEY_LIMBS_2048: u32 = 18;
global BODY_HASH_BASE64_LENGTH: u32 = 44;
global CR: u8 = 0x0D;
global LF: u8 = 0x0A;
global MAX_DKIM_HEADER_FIELD_LENGTH: u32 = 300; // kinda arbitrary but gives > 100 chars for selector and domain
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 320;

pub struct Sequence {
    index: u32,
    length: u32,
}

impl Sequence {
    pub fn end_index(self) -> u32 {
        self.index + self.length
    }
}
// allowable chars in an email address (js/src/utils:makeAllowableEmailCharsTable()
// "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-@" = 1
// "<: " = 2
// ">\r\n" = 3
global EMAIL_ADDRESS_CHAR_TABLE: [u8; 123] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 2, 0, 3, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
];

/**
 * Default email verification function
 * @dev use #[zkemail] attribute macro to apply other functionality
 *
 * @param MAX_EMAIL_HEADER_LENGTH - The maximum length of the email header
 * @param KEY_LIMBS - The number of limbs in the RSA pubkey
 * @param header - The email header, 0-padded at end to the MAX_EMAIL_HEADER_LENGTH
 * @param pubkey - The DKIM RSA Public Key modulus and reduction parameter
 * @param signature - The DKIM RSA Signature
 */
pub fn verify_email<let MAX_EMAIL_HEADER_LENGTH: u32, let MAX_EMAIL_BODY_LENGTH: u32, // sometimes unused but needed for macro
let KEY_LIMBS: u32>(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
) {
    // ~ 86,553 constraints with 2048-bit RSA & 1024 bit max header length
    // verify the dkim signature over the header
    pubkey.verify_dkim_signature(header, signature);
}
