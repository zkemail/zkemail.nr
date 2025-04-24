use std::hash::pedersen_hash;
pub mod dkim;
pub mod headers;
pub mod masking;
pub mod partial_hash;
pub mod remove_soft_line_breaks;
pub mod utils;
mod tests;

global RSA_EXPONENT: u32 = 65537;
global KEY_LIMBS_1024: u32 = 9;
global KEY_LIMBS_2048: u32 = 18;
global BODY_HASH_BASE64_LENGTH: u32 = 44;
global CR: u8 = 0x0D;
global LF: u8 = 0x0A;
global MAX_DKIM_HEADER_FIELD_LENGTH: u32 = 300; // kinda arbitrary but gives > 100 chars for selector and domain
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 320; // derived via (https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3.1.1)

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
 * Create a nullifier for a signature with a blinding factor
 *
 * @param signature - The signature to nullify
 * @param nonce - The nonce to use in the nullifier as a blinding factor
 * @return - The blinded nullifier for the signature
 */
pub fn blinded_nullifier<let KEY_LIMBS: u32>(signature: [Field; KEY_LIMBS], nonce: Field) -> Field {
    let preimage = unsafe { __blinded_nullifier(signature, nonce) };
    for i in 0..KEY_LIMBS {
        assert(preimage[i] == signature[i], "Preimage does not contain signature");
    }
    assert(preimage[KEY_LIMBS] == nonce, "Preimage does not contain nonce");
    pedersen_hash(preimage)
}

/**
 * Builds the nullifier preimage with a nonce
 * @notice the nonce should be governed at the app level - i.e. an aztec note can pass this in
 * 
 * @param signature - The signature to nullify
 * @param nonce - The nonce to use in the nullifier as a blinding factor
 */
unconstrained fn __blinded_nullifier<let KEY_LIMBS: u32>(
    signature: [Field; KEY_LIMBS],
    nonce: Field,
) -> [Field; KEY_LIMBS + 1] {
    let mut nullifier_preimage = [0; KEY_LIMBS + 1];
    for i in 0..KEY_LIMBS {
        nullifier_preimage[i] = signature[i];
    }
    nullifier_preimage[KEY_LIMBS] = nonce;

    nullifier_preimage
}
