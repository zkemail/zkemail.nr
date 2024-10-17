use dep::base64::base64_encode;
use dep::std::collections::bounded_vec::BoundedVec;
use crate::{Sequence, CR, LF, MAX_DKIM_HEADER_FIELD_LENGTH, BODY_HASH_BASE64_LENGTH};

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
        & body_hash_index < dkim_header_field_sequence.index + dkim_header_field_sequence.length,
        "Body hash index accessed outside of DKIM header field"
    );
    let bh_prefix: [u8; 3] = comptime { "bh=".as_bytes() };
    for i in 0..3 {
        assert(
            header.get_unchecked(body_hash_index - 3 + i) == bh_prefix[i],
            "No 'bh=' prefix found at asserted bh index"
        );
    }
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
    base64_encode::<BODY_HASH_BASE64_LENGTH, 32>(body_hash_encoded)
}

pub fn get_email_address<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    from_header_field_sequence: Sequence,

)

/**
 * Constrains a header field to be within 
 */
pub fn constrain_header_field<
    let MAX_HEADER_LENGTH: u32,
    let MAX_HEADER_FIELD_LENGTH: u32,
    let HEADER_FIELD_NAME_LENGTH: u32,
>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) {
    // check that the sequence is within bounds
    assert(
        header_field_sequence.index + header_field_sequence.length <= header.len(),
        "Header field out of bounds"
    );
    // check the range of the sequence is within the header (so we can use get_unchecked)
    let end_index = header_field_sequence.index + header_field_sequence.length;
    assert(end_index <= header.len(), "Header field out of bounds of header");

    // if the sequence is not the start, check for a newline
    if header_field_sequence.index != 0 {
        assert(header.get_unchecked(header_field_sequence.index - 2) == CR, "Header field must start with CRLF");
        assert(header.get_unchecked(header_field_sequence.index - 1) == LF, "Header field must start with CRLF");
    }
    // if the sequence is not the end, check for a newline
    if end_index != header.len() {
        assert(
            header.get_unchecked(end_index) == CR,
            "Header field must end with CRLF"
        );
        assert(header.get_unchecked(end_index + 1) == LF,
        "Header field must end with CRLF"
        );
    }
    // check that the header field name matches the expected name
    for i in 0..HEADER_FIELD_NAME_LENGTH {
        assert(
            header.get_unchecked(header_field_sequence.index + i) == header_field_name[i],
            "Header field name does not match"
        );
    }
    assert(
        header.get_unchecked(header_field_sequence.index + HEADER_FIELD_NAME_LENGTH) == 0x3a,
        "Header field name must be followed by a colon"
    );
    // check the header field is uninterrupted
    let start_index = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    for i in (HEADER_FIELD_NAME_LENGTH + 1)..MAX_HEADER_FIELD_LENGTH {
        // is it safe enough to cut this constraint cost in half by not checking lf? i think so
        let index = start_index + i;
        if (index < header_field_sequence.index + header_field_sequence.length) {
            assert(
                header.get_unchecked(index) != CR,
                "Header field must not contain newlines"
            );
        }
    }
}

/**
 * Constrains a header field to be within 
 */
pub fn constrain_header_field_detect_last_angle_bracket<
    let MAX_HEADER_LENGTH: u32,
    let MAX_HEADER_FIELD_LENGTH: u32,
    let HEADER_FIELD_NAME_LENGTH: u32,
>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> u32 {
    // check that the sequence is within bounds
    assert(
        header_field_sequence.index + header_field_sequence.length <= header.len(),
        "Header field out of bounds"
    );
    // check the range of the sequence is within the header (so we can use get_unchecked)
    let end_index = header_field_sequence.index + header_field_sequence.length;
    assert(end_index <= header.len(), "Header field out of bounds of header");

    // if the sequence is not the start, check for a newline
    if header_field_sequence.index != 0 {
        assert(header.get_unchecked(header_field_sequence.index - 2) == CR, "Header field must start with CRLF");
        assert(header.get_unchecked(header_field_sequence.index - 1) == LF, "Header field must start with CRLF");
    }
    // if the sequence is not the end, check for a newline
    if end_index != header.len() {
        assert(
            header.get_unchecked(end_index) == CR,
            "Header field must end with CRLF"
        );
        assert(header.get_unchecked(end_index + 1) == LF,
            "Header field must end with CRLF"
        );
    }
    // check that the header field name matches the expected name
    for i in 0..HEADER_FIELD_NAME_LENGTH {
        assert(
            header.get_unchecked(header_field_sequence.index + i) == header_field_name[i],
            "Header field name does not match"
        );
    }
    assert(
        header.get_unchecked(header_field_sequence.index + HEADER_FIELD_NAME_LENGTH) == 0x3a,
        "Header field name must be followed by a colon"
    );
    // check the header field is uninterrupted
    let mut last_angle_bracket = 0;
    let start_index = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    for i in (HEADER_FIELD_NAME_LENGTH + 1)..MAX_HEADER_FIELD_LENGTH {
        // is it safe enough to cut this constraint cost in half by not checking lf? i think so
        let index = start_index + i;
        if (index < header_field_sequence.index + header_field_sequence.length) {
            let byte = header.get_unchecked(index);
            assert(
                byte != CR,
                "Header field must not contain newlines"
            );
            if byte == 0x3c {
                last_angle_bracket = index;
            }
        }
    }
    last_angle_bracket
}
