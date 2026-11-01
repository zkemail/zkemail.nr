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
    // the expected name must itself be a valid field name: printable ASCII except ':' (RFC 5322
    // section 2.2). A name containing ':' or CRLF could swallow part of a field value or a line
    // break. Free for constant names.
    assert(HEADER_FIELD_NAME_LENGTH != 0, "Header field name must not be empty");
    for i in 0..HEADER_FIELD_NAME_LENGTH {
        let c = header_field_name[i];
        assert((c >= 0x21) & (c <= 0x7e) & (c != 0x3a), "Invalid header field name");
    }

    // the sequence must at least hold "<name>:"
    assert(
        header_field_sequence.length > HEADER_FIELD_NAME_LENGTH,
        "Header field too short to contain name and colon",
    );

    // the field must fit in the range scanned by the callers
    assert(header_field_sequence.length <= MAX_HEADER_FIELD_LENGTH, "Header field too long");

    // check the range of the sequence is within the header (so we can use get_unchecked)
    let end_index = header_field_sequence.end_index();
    assert(end_index <= header.len(), "Header field out of bounds of header");

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
        // a CRLF followed by SP or HTAB is a fold: the field continues on the next line (c=simple
        // keeps folds). Ending the sequence there would claim only the first line(s) of a folded
        // field as the whole field. When end_index + 2 == len there is no next line.
        if end_index + 2 < header.len() {
            let next = header.get_unchecked(end_index + 2);
            assert((next != 0x20) & (next != 0x09), "Header field must not end inside a fold");
        }
    }

    // check that the header field name matches the expected name, ignoring ASCII case: field
    // names are case-insensitive (RFC 5322 section 1.2.2) and c=simple keeps their original case.
    // Only A-Z are folded, so no other byte can alias a name byte. Comparing each header byte with
    // both cases of the expected byte costs about 8 gates less per byte than lowercasing it.
    for i in 0..HEADER_FIELD_NAME_LENGTH {
        let lower = to_ascii_lowercase(header_field_name[i]);
        let upper = if (lower >= 0x61) & (lower <= 0x7a) {
            lower - 0x20
        } else {
            lower
        };
        let byte = header.get_unchecked(header_field_sequence.index + i);
        assert((byte == lower) | (byte == upper), "Header field name does not match");
    }
    assert(
        header.get_unchecked(header_field_sequence.index + HEADER_FIELD_NAME_LENGTH) == 0x3a,
        "Header field name must be followed by a colon",
    );
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
 * Constrain a sequence in a header to match the specific header field
 * The field must be on one line, as relaxed canonicalization (which the library assumes) leaves
 * it. Use constrain_header_field_with_folds for c=simple headers, which keep folded lines.
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
    constrain_header_field_inner::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
        false,
    );
}

/**
 * constrain_header_field that also accepts folded lines (CRLF followed by SP or HTAB), as kept by
 * c=simple header canonicalization. A CRLF not followed by SP or HTAB still ends the field.
 * This costs about 12 more gates per byte of MAX_HEADER_FIELD_LENGTH than constrain_header_field.
 */
pub fn constrain_header_field_with_folds<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) {
    constrain_header_field_inner::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
        true,
    );
}

fn constrain_header_field_inner<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
    allow_folds: bool,
) {
    // constrain beginning of header field
    check_header_field_bounds::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
    );

    // check the header field is uninterrupted
    let start_index = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    let mut folds = FoldCheck::new();
    for i in 0..MAX_HEADER_FIELD_LENGTH {
        let index = start_index + i;
        if (index < header_field_sequence.end_index()) {
            let byte = header.get_unchecked(index);
            if allow_folds {
                folds.check(byte);
            } else {
                assert(byte != CR, "Header field must not contain newlines");
            }
        }
    }
    if allow_folds {
        folds.finish();
    }
}

/**
 * constrain_header_field with checks for the last occurence of "<" inside the loop to save constraints.
 * Comments and quoted-pairs are rejected and quoted strings must be closed, so a field cannot end
 * inside a comment or quoted string.
 */
pub fn constrain_header_field_detect_last_angle_bracket<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> u32 {
    detect_last_angle_bracket_inner::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
        false,
    )
}

/**
 * constrain_header_field_detect_last_angle_bracket that also accepts folded lines (CRLF followed
 * by SP or HTAB), as kept by c=simple header canonicalization.
 */
pub fn constrain_header_field_detect_last_angle_bracket_with_folds<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> u32 {
    detect_last_angle_bracket_inner::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
        true,
    )
}

fn detect_last_angle_bracket_inner<let MAX_HEADER_LENGTH: u32, let MAX_HEADER_FIELD_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
    allow_folds: bool,
) -> u32 {
    // constrain beginning of header field
    check_header_field_bounds::<MAX_HEADER_LENGTH, MAX_HEADER_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
    );

    // check the header field is uninterrupted
    let mut last_angle_bracket = 0;
    let mut quoted = false;
    let mut folds = FoldCheck::new();
    let start_index = header_field_sequence.index + HEADER_FIELD_NAME_LENGTH + 1;
    for i in 0..(MAX_HEADER_FIELD_LENGTH - HEADER_FIELD_NAME_LENGTH - 1) {
        let index = start_index + i;
        if (index < header_field_sequence.end_index()) {
            let byte = header.get_unchecked(index);
            if allow_folds {
                folds.check(byte);
            } else {
                assert(byte != CR, "Header field must not contain newlines");
            }
            assert(
                (byte as Field - 0x28) * (byte as Field - 0x5c) != 0,
                "Comments and quoted-pairs are not supported in address fields",
            );
            quoted = quoted != (byte == 0x22);
            if byte == 0x3c {
                last_angle_bracket = index;
            }
        }
    }
    if allow_folds {
        folds.finish();
    }
    assert(!quoted, "Unterminated quoted string");
    last_angle_bracket
}

// Line-break check for folded fields: a CR is allowed only as the start of a complete fold,
// CRLF followed by SP or HTAB (RFC 5322 section 2.2.3). A CRLF followed by anything else starts
// a new header line. Two carried flags replace reading the next two bytes for every byte, and
// the checks are Field products rather than boolean selects, which keeps the cost per byte low.
struct FoldCheck {
    expect_lf: Field, // the previous field byte was CR
    expect_wsp: Field, // the previous two field bytes were CRLF
}

impl FoldCheck {
    fn new() -> Self {
        FoldCheck { expect_lf: 0, expect_wsp: 0 }
    }

    fn check(&mut self, byte: u8) {
        let byte = byte as Field;
        assert(
            self.expect_lf * (byte - LF as Field) == 0,
            "Header field must not contain newlines",
        );
        assert(
            self.expect_wsp * (byte - 0x20) * (byte - 0x09) == 0,
            "Header field must not contain newlines",
        );
        self.expect_wsp = self.expect_lf;
        self.expect_lf = (byte == CR as Field) as Field;
    }

    // a fold must be complete inside the field: otherwise a field ending in CR or CRLF could be
    // completed by bytes outside it, including the unconstrained storage past header.len()
    fn finish(self) {
        assert(
            (self.expect_lf == 0) & (self.expect_wsp == 0),
            "Header field must not contain newlines",
        );
    }
}
