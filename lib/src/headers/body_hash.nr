use crate::{
    BODY_HASH_BASE64_LENGTH, headers::constrain_header_field, MAX_DKIM_HEADER_FIELD_LENGTH,
    Sequence,
};
use base64::BASE64_DECODER;

// ON DKIM-SIGNATURE PARSING:
// In the current version, DKIM-SIGNATURE tags are mostly ignored:
// c= is ignored, meaning we assume the canonicalization is relaxed. This can cause denial of service issues
// v= is ignored, meaning we do not check for a valid version of dkim signing
// l= is ignored, meaning we otherwise constrain the body length to be safe
// x= is ignored, meaning we accept signatures without expiration
// sdid= is ignored, meaning that we don't explicitly bind dkim keys to exact signing domains
// See line 42 of this file for parsing bh=;
// You will need to implement your own parsing for the tags' expected values

/**
 * Constrained access to the body hash in the header
 * 
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header as validated in the DKIM signature
 * @param dkim_header_field_sequence - The sequence of the DKIM header field
 * @param body_hash_index - The index of the body hash in the header
 */
pub fn get_body_hash<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    dkim_header_field_sequence: Sequence,
    body_hash_index: u32,
) -> [u8; 32] {
    // constrain the access of dkim signature field
    let header_field_name: [u8; 14] = comptime { "dkim-signature".as_bytes() };
    constrain_header_field::<MAX_HEADER_LENGTH, MAX_DKIM_HEADER_FIELD_LENGTH, 14>(
        header,
        dkim_header_field_sequence,
        header_field_name,
    );
    // constrain access to the body hash
    let start_range = body_hash_index > dkim_header_field_sequence.index;
    let end_range =
        body_hash_index + BODY_HASH_BASE64_LENGTH < dkim_header_field_sequence.end_index() + 1;
    assert(start_range & end_range, "Body hash index accessed outside of DKIM header field");

    // check bh prefix
    let bh_prefix_first_no_space: [u8; 5] = comptime { "e:bh=".as_bytes() };
    let bh_prefix_space: [u8; 5] = comptime { ": bh=".as_bytes() };
    let bh_prefix_subsequent: [u8; 5] = comptime { "; bh=".as_bytes() };
    let mut found_first = true;
    let mut found_subsequent = true;
    for i in 0..5 {
        let character = header.get_unchecked(body_hash_index - 5 + i);
        let match_first_no_space = character == bh_prefix_first_no_space[i];
        let match_first_space = character == bh_prefix_space[i];
        let match_first = match_first_no_space | match_first_space;
        found_first = found_first & match_first;
        let match_subsequent = character == bh_prefix_subsequent[i];
        found_subsequent = found_subsequent & match_subsequent;
    }
    assert(found_first | found_subsequent, "No ':bh=' or '; bh=' prefix found before body hash");

    // check that bh is followed by ;
    let bh_suffix: u8 = comptime { ";".as_bytes()[0] };
    assert(
        header.get_unchecked(body_hash_index + BODY_HASH_BASE64_LENGTH) == bh_suffix,
        "No ';' suffix found at asserted bh index",
    );
    // get the body hash
    get_body_hash_unsafe(header, body_hash_index)
}

/**
 * Get the body hash from the header without validating the access index. Does not validate body
 * hash is valid base64 sequence (https://github.com/noir-lang/noir_base64/blob/4431d08ac661ada9d8d18b115487ff0190b43856/src/lib.nr#L209-L232)
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header as validated in the DKIM signature
 * @param body_hash_index - The asserted index to find the body hash at
 */
pub fn get_body_hash_unsafe<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    body_hash_index: u32,
) -> [u8; 32] {
    // get the body hash
    let mut body_hash_encoded: [u8; BODY_HASH_BASE64_LENGTH] = [0; BODY_HASH_BASE64_LENGTH];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        body_hash_encoded[i] = header.get_unchecked(body_hash_index + i);
    }
    // return the decoded body hash
    // idk why encode vs decode...
    BASE64_DECODER.decode(body_hash_encoded)
}
