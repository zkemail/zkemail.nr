use dep::std::hash::pedersen_hash;
use dep::std::collections::bounded_vec::BoundedVec;

mod dkim;
mod headers;
mod partial_hash;
mod masking;

global RSA_EXPONENT: u32 = 65537;
global KEY_BYTES_1024: u32 = 128;
global KEY_BYTES_2048: u32 = 256;
global KEY_LIMBS_1024: u32 = 9;
global KEY_LIMBS_2048: u32 = 18;
global BODY_HASH_BASE64_LENGTH: u32 = 44;
global CR: u8 = 0x0D;
global LF: u8 = 0x0A;
global MAX_DKIM_HEADER_FIELD_LENGTH: u32 = 300; // kinda arbitrary but gives > 100 chars for selector and domain
global MAX_EMAIL_ADDRESS_LENGTH: u32 = 320;

pub struct RSAPubkey<let KEY_LIMBS: u32> {
    modulus: [Field; KEY_LIMBS],
    redc: [Field; KEY_LIMBS],
}

pub struct Sequence {
    index: u32,
    length: u32
}

/**
 * Standard outputs that essentially every email circuit will need to export (alongside app-specific outputs)
 * @notice if you only need the pubkey hash just import pedersen and hash away 
 *
 * @param pubkey - the BN limbs of the DKIM RSA pubkey
 * @param signature - the BN limbs of the DKIM RSA signature
 * @returns
 *        0: Pedersen hash of DKIM public key (root of trust)
 *        1: Pedersen hash of DKIM signature (email nullifier)
 */
pub fn standard_outputs<let KEY_BYTE_LENGTH: u32>(
    pubkey: [Field; KEY_BYTE_LENGTH],
    signature: [Field; KEY_BYTE_LENGTH]
) -> [Field; 2] {
    // create pedersen hash of DKIM signing key to minimize public outputs
    let pubkey_hash = pedersen_hash(pubkey);
    // create email nullifier for email
    let email_nullifier = pedersen_hash(signature);
    // output the root of trust and email nullifier
    [pubkey_hash, email_nullifier]
}
