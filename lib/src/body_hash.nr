use crate::BODY_HASH_BASE64_LENGTH;
use crate::base64::bodyhash_base64_decode;
use dep::std::hash::sha256_var;

global BH_PREFIX: [u8; 3] = [98, 104, 61]; // "bh="
global BH_SUFFIX: u8 = 59; // ";"

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
    header: [u8; MAX_HEADER_LENGTH],
    index: u32
) -> [u8; BODY_HASH_BASE64_LENGTH] {
    // check index range
    assert(index >= 3, "Index does not leave room for 'bh=' prefix");
    assert(index + BODY_HASH_BASE64_LENGTH < MAX_HEADER_LENGTH, "Index does not leave room for body hash");
    // check for 'bh=' prefix
    for i in 0..3 {
        assert(header[index - 3 + i] == BH_PREFIX[i], "No 'bh=' prefix found");
    }
    // check for base64 suffix
    assert(header[index + BODY_HASH_BASE64_LENGTH] == BH_SUFFIX, "No base64 suffix found");
    // retrieve body hash
    let mut body_hash = [0 as u8; BODY_HASH_BASE64_LENGTH];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        body_hash[i] = header[index + i];
    }
    body_hash
}

/**
 * Given a retrieved base64-encoded body hash and the actual body, check that the body hashes to the same value
 * @notice not used with partial hash, see compare_partial_body_hash
 * @dev todo: check if b64 encoding or decoding is cheaper
 *
 * @param MAX_BODY_LENGTH - The maximum length of the email body
 * @param body_hash_encoded - The base 64 encoded body hash retrieved from the DKIM-signed header
 * @param body - The email body, 0-padded at end to the MAX_BODY_LENGTH
 * @param body_length - The actual length of the email body
 */
pub fn compare_body_hash<let MAX_BODY_LENGTH: u32>(
    body_hash_encoded: [u8; BODY_HASH_BASE64_LENGTH],
    body: [u8; MAX_BODY_LENGTH],
    body_length: u32
) {
    // base64 decode the retrieved encoded body hash
    // let signed_body_hash: [u8; 32] = base64_decode(body_hash_encoded);
    let signed_body_hash: [u8; 32] = bodyhash_base64_decode(body_hash_encoded);
    // sha256 hash the body
    let computed_body_hash: [u8; 32] = sha256_var(body, body_length as u64);
    // check the body hashes match
    assert(
        signed_body_hash == computed_body_hash, "Sha256 hash computed over body does not match DKIM-signed header"
    );
}
