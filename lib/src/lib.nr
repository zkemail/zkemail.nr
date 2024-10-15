use dep::std::hash::pedersen_hash;
use dep::std::collections::bounded_vec::BoundedVec;

mod dkim;
mod header_field;
mod partial_hash;
mod base64;
mod macro;
mod masking;

global RSA_EXPONENT: u32 = 65537;
global KEY_BYTES_1024: u32 = 128;
global KEY_BYTES_2048: u32 = 256;
global KEY_LIMBS_1024: u32 = 9;
global KEY_LIMBS_2048: u32 = 18;
global BODY_HASH_BASE64_LENGTH: u32 = 44;

struct Sequence {
    index: u32,
    length: u32
}

/**
 * Get the body hash from the header by allowing circuit input to choose index
 * @notice unsafe, can theoretically make a recipient display name = the bh
 *
 * @param HEADER_LENGTH - The length of the email header
 * @param header - The email header as validated in the DKIM signature
 * @param index - The asserted index to find the body hash at
 * @returns The base 64 encoded body hash
 */
pub fn get_body_hash_by_index<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8; MAX_HEADER_LENGTH>,
    body_hash_index: u32
) -> [u8; BODY_HASH_BASE64_LENGTH] {
    // check index range
    assert(index >= 3, "Index does not leave room for 'bh=' prefix");
    assert(index + BODY_HASH_BASE64_LENGTH < MAX_HEADER_LENGTH, "Index does not leave room for body hash");
    // check for 'bh=' prefix
    let BH_PREFIX: [u8; 3] = [98, 104, 61]; // "bh="
    for i in 0..3 {
        assert(header[index - 3 + i] == BH_PREFIX[i], "No 'bh=' prefix found");
    }
    // check for base64 suffix
    let BH_SUFFIX: u8 = 59; // ";"
    assert(header[index + BODY_HASH_BASE64_LENGTH] == BH_SUFFIX, "No base64 suffix found");
    // retrieve body hash
    let mut body_hash = [0 as u8; BODY_HASH_BASE64_LENGTH];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        body_hash[i] = header[index + i];
    }
    body_hash
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
