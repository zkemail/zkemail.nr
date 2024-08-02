use crate::{BODY_HASH_BASE64_LENGTH, EMAIL_HEADER_LENGTH, MAX_ADDRESS_LOCAL_LENGTH, TO_DOMAIN_LENGTH};
use dep::string_search::{StringBody, SubString, StringBody512, SubString32, SubString64};


/**
 * Decodes a base64 encoded body hash into a 32 byte sha256 hash of the body
 * @notice from https://github.com/richardliang/noir-rsa/blob/main/crates/rsa-biguint/src/lib.nr

 * @param encoded - the base 64 encoded body hash
 * @returns the decoded sha256 hash
 */
pub fn bodyhash_base64_decode(encoded: [u8; BODY_HASH_BASE64_LENGTH]) -> [u8; 32] {
    let mut total_bits = [0 as u1; BODY_HASH_BASE64_LENGTH * 6];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        let translate = base64_lookup(encoded[i] as u8);
        // Store as big endian
        let translate_bits = (translate as Field).to_be_bits(6);
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

/**
 * Extracts the base 64 encoded body hash from an email header
 *
 * @param header - the email header as validated in the DKIM signature
 * @param index - the asserted index to find the body hash at
 * @returns the base 64 encoded body hash
 */
pub fn get_body_hash(header: [u8; EMAIL_HEADER_LENGTH], index: u32) -> [u8; BODY_HASH_BASE64_LENGTH] {
    let mut body_hash = [0 as u8; BODY_HASH_BASE64_LENGTH];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        body_hash[i] = header[index + i];
    }
    body_hash
}

/**
 * Attempt to find the index of the "to" field in the email header to eventually extract recipient domain
 *
 * @param header - the entire email header to search through
 * @param padded_recipient_local - the username (local part) of the recipient email address
 * @param recipient_local_length - the length of the username (local part) of the recipient email address
 * @returns (true/ false if found, index of start in the header)
 */
pub fn find_to_index(
    header: [u8; EMAIL_HEADER_LENGTH],
    padded_recipient_local: [u8; MAX_ADDRESS_LOCAL_LENGTH],
    recipient_local_length: u32
) -> (bool, u32) {
    // init the search params
    let needle_text_init: [u8; 3] = "to:".as_bytes();
    let needle_start: SubString32 = SubString::new(needle_text_init, needle_text_init.len());
    let needle_end: SubString64 = SubString::new(padded_recipient_local, recipient_local_length);
    let needle = needle_start.concat_into(needle_end);

    // init the search domain
    let haystack: StringBody512 = StringBody::new(header, EMAIL_HEADER_LENGTH);

    // find the index of the position
    haystack.substring_match(needle)
}

/**
 * Extracts the recipient domain from the email header given index of to field + expected recipient local length
 *
 * @param header - the email header to search through
 * @param recipient_local_length - the length of the username (local part) of the recipient email address
 * @param index - the index of the "to" field in the email header
 * @returns the supposed recipient domain
 */
pub fn extract_expected_recipient_domain(
    header: [u8; EMAIL_HEADER_LENGTH],
    recipient_local_length: u32,
    index: u32
) -> [u8; TO_DOMAIN_LENGTH] {
    let mut recipient_domain = [0 as u8; TO_DOMAIN_LENGTH];
    for i in 0..TO_DOMAIN_LENGTH {
        // iterator + found index starting the to search + length of recipient local address + len(to:)
        // should start at `@`
        recipient_domain[i] = header[i + index + recipient_local_length + 3];
    }
    recipient_domain
}