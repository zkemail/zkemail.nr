use crate::{CR, LF, Sequence};

pub mod body_hash;
pub mod email_address;

/**
 * Constrain a sequence in a header to be within the correct bounds
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param MAX_HEADER_FIELD_LENGTH - The maximum length of the header field
 * @param HEADER_FIELD_NAME_LENGTH - The length of the header field name
 * @param header - The email header as validated in the DKIM signature
 * @param header_field_sequence - The sequence of the header field
 * @param header_field_name - The name of the header field
 */
fn check_header_field_bounds<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) {
    // REASON: the expected name must itself be a valid field name (printable ASCII except ':',
    // RFC 5322 s2.2). A name containing ':' or CRLF would let the "name" swallow part of a field
    // value or a line break (Consensys Diligence v1 audit, finding 5.3). Free for constant names.
    assert(HEADER_FIELD_NAME_LENGTH != 0, "Header field name must not be empty");
    for i in 0..HEADER_FIELD_NAME_LENGTH {
        let c = header_field_name[i];
        assert((c >= 0x21) & (c <= 0x7e) & (c != 0x3a), "Invalid header field name");
    }

    // check the range of the sequence is within the header (so we can use get_unchecked)
    let end_index = header_field_sequence.end_index();
    assert(end_index <= header.len(), "Header field out of bounds of header");

    // NOTE: the sequence must at least hold "<name>:" (Consensys v1 audit, finding 5.4).
    assert(
        header_field_sequence.length > HEADER_FIELD_NAME_LENGTH,
        "Header field too short to contain name and colon",
    );

    // REASON: the callers' "no line break inside the field" loops start right after
    // "<name>:" and only scan MAX_HEADER_FIELD_LENGTH bytes. Without this bound, bytes of a longer
    // claimed field past that window were never checked, so a sequence could extend over later
    // header lines. Removing this check reintroduces that gap.
    assert(
        header_field_sequence.length <= HEADER_FIELD_NAME_LENGTH + 1 + MAX_HEADER_FIELD_LENGTH,
        "Header field too long",
    );

    // if the sequence is not the start, check for a newline
    if header_field_sequence.index != 0 {
        assert(
            header.get_unchecked(header_field_sequence.index - 2) == CR,
            "Header field must start with CRLF",
        );
        assert(
            header.get_unchecked(header_field_sequence.index - 1) == LF,
            "Header field must start with CRLF",
        );
    }

    // if the sequence is not the end, check for a newline that really ends the field
    if end_index != header.len() {
        assert(header.get_unchecked(end_index) == CR, "Header field must end with CRLF");
        assert(header.get_unchecked(end_index + 1) == LF, "Header field must end with CRLF");
        // REASON: a CRLF followed by SP/HTAB is a fold, i.e. the same field continues on the next
        // line (kept by c=simple canonicalization). Ending the sequence there would let a prover
        // claim only the first line(s) of a folded field as the whole field (Consensys v1 audit,
        // finding 5.1, Critical). relaxed canonicalization never produces a fold, so this rejects
        // no relaxed header. When end_index + 2 == len there is no next line (the byte there is
        // padding), so it is not read.
        if end_index + 2 < header.len() {
            let next = header.get_unchecked(end_index + 2);
            assert((next != 0x20) & (next != 0x09), "Header field must not end inside a fold");
        }
    }

    // check that the header field name matches the expected name, ignoring ASCII case.
    // NOTE: field names are case-insensitive (RFC 5322 s1.2.2). relaxed header canonicalization
    // lowercases them, but c=simple keeps the original case (e.g. "DKIM-Signature", "From"), which
    // an exact byte match rejected. Only A-Z are folded, so no other byte can alias a name byte.
    for i in 0..HEADER_FIELD_NAME_LENGTH {
        assert(
            to_ascii_lowercase(header.get_unchecked(header_field_sequence.index + i))
                == to_ascii_lowercase(header_field_name[i]),
            "Header field name does not match",
        );
    }
    assert(
        header.get_unchecked(header_field_sequence.index + HEADER_FIELD_NAME_LENGTH) == 0x3a,
        "Header field name must be followed by a colon",
    );
}

/**
 * Constrain a sequence in a header to match the specific header field
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param MAX_HEADER_FIELD_LENGTH - The maximum length of the header field
 * @param HEADER_FIELD_NAME_LENGTH - The length of the header field name
 * @param header - The email header as validated in the DKIM signature
 * @param header_field_sequence - The sequence of the header field
 * @param header_field_name - The name of the header field
 */
pub fn constrain_header_field<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) {
    // constrain beginning of header field
    check_header_field_bounds::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
    );

    // check the header field is uninterrupted: a CR inside the field is only allowed as the start
    // of a fold (CRLF followed by SP or HTAB), which continues the same field (RFC 5322 s2.2.3).
    // NOTE: relaxed canonicalization unfolds headers, but c=simple keeps folds, and long fields
    // such as DKIM-Signature are almost always folded. A CRLF followed by anything else starts a
    // new header line and must never be inside the field.
    // REASON (cost): the fold is checked with two carried flags instead of reading header[index + 1]
    // and header[index + 2] in each iteration; every dynamic read is a memory op, and this loop runs
    // MAX_HEADER_FIELD_LENGTH (1024 for DKIM-Signature) times.
    // (Measured on examples/verify_email_2048_bit_dkim: ~12k fewer ACIR opcodes than three reads.)
    let start_index = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    let end_index = header_field_sequence.end_index();
    let mut expect_lf = false; // previous field byte was CR
    let mut expect_wsp = false; // previous two field bytes were CRLF
    for i in 0..MAX_HEADER_FIELD_LENGTH {
        let index = start_index + i;
        if (index < end_index) {
            let byte = header.get_unchecked(index);
            let lf_ok = !expect_lf | (byte == LF);
            let wsp_ok = !expect_wsp | (byte == 0x20) | (byte == 0x09);
            assert(lf_ok & wsp_ok, "Header field must not contain newlines");
            expect_wsp = expect_lf;
            expect_lf = byte == CR;
        }
    }
    // REASON: a fold must be complete inside the field. Otherwise a field ending in CR or CRLF
    // could be "completed" by bytes outside it (including unconstrained padding past header.len()).
    assert(!expect_lf & !expect_wsp, "Header field must not contain newlines");
}

// Lowercase an ASCII letter; every other byte is returned unchanged.
fn to_ascii_lowercase(byte: u8) -> u8 {
    if (byte >= 0x41) & (byte <= 0x5a) {
        byte + 0x20
    } else {
        byte
    }
}

/**
 * constrain_header_field with checks for the last occurence of "<" inside the loop to save constraints
 */
pub fn constrain_header_field_detect_last_angle_bracket<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> u32 {
    // constrain beginning of header field
    check_header_field_bounds::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
    );

    // check the header field is uninterrupted
    let mut last_angle_bracket = 0;
    let start_index = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    for i in (HEADER_FIELD_NAME_LENGTH + 1)..MAX_HEADER_FIELD_LENGTH {
        // is it safe enough to cut this constraint cost in half by not checking lf? i think so
        let index = start_index + i;
        if (index < header_field_sequence.end_index()) {
            let byte = header.get_unchecked(index);
            assert(byte != CR, "Header field must not contain newlines");
            if byte == 0x3c {
                last_angle_bracket = index;
            }
        }
    }
    last_angle_bracket
}
