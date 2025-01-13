use crate::{
    BODY_HASH_BASE64_LENGTH, headers::constrain_header_field, MAX_DKIM_HEADER_FIELD_LENGTH,
    Sequence,
};
use base64::BASE64_DECODER;

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
    assert(
        body_hash_index > dkim_header_field_sequence.index
            & body_hash_index < dkim_header_field_sequence.end_index() + 1,
        "Body hash index accessed outside of DKIM header field",
    );
    let bh_prefix: [u8; 5] = comptime { "; bh=".as_bytes() };
    for i in 0..5 {
        let character = header.get_unchecked(body_hash_index - 5 + i);
        assert(character == bh_prefix[i], "No 'bh=' prefix found at asserted bh index");
    }
    let bh_suffix: u8 = comptime { ";".as_bytes()[0] };
    assert(
        header.get_unchecked(body_hash_index + BODY_HASH_BASE64_LENGTH) == bh_suffix,
        "No ';' suffix found at asserted bh index",
    );
    // get the body hash
    get_body_hash_unsafe(header, body_hash_index)
}

/**
 * Get the body hash from the header without validating the access index
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
