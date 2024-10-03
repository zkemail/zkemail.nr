use crate::BODY_HASH_BASE64_LENGTH;

// noir_base64 has issues right now, just use this for now

/**
 * Decodes a base64 encoded body hash into a 32 byte sha256 hash of the body
 * @notice from https://github.com/richardliang/noir-rsa/blob/main/crates/rsa-biguint/src/lib.nr

 * @param encoded - the base 64 encoded body hash
 * @returns the decoded sha256 hash
 */
pub fn body_hash_base64_decode(encoded: [u8; BODY_HASH_BASE64_LENGTH]) -> [u8; 32] {
    let mut total_bits = [0 as u1; BODY_HASH_BASE64_LENGTH * 6];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        let translate = base64_lookup(encoded[i] as u8);
        // Store as big endian
        let translate_bits: [u1; 6] = (translate as Field).to_be_bits();
        for j in 0..6 {
            total_bits[i * 6 + j] = translate_bits[j];
        }
    }

    // Since we're returning the SHA256 hash, only need first 32 bytes (=256 bits)
    let mut output = [0 as u8; 32];
    for i in 0..32 {
        for j in 0..8 {
            // Convert from big endian back to little endian
            output[i] |= (total_bits[i * 8 + j] as u8) << (7 - j) as u8;
        }
    }

    output
}

/**
 * Lookup for the base 64 encoding
 * @todo: replace with noir_lang base64 lib
 *
 * @param input - the base 64 encoded character
 * @returns the decoded value
 */
fn base64_lookup(input: u8) -> u8 {
    // A-Z: 65-90
    if input >= 65 & input <= 90 {
        input - 65
    } else if input >= 97 & input <= 122 {
        // a-z: 97-122
        input - 71
    } else if input >= 48 & input <= 57 {
        // 0-9: 48-57
        input + 4
    } else if input == 43 {
        // +
        62
    } else if input == 47 {
        // /
        63
    } else {
        // =
        0
    }
}