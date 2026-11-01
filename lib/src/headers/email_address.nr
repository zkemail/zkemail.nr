use crate::{
    EMAIL_ADDRESS_CHAR_TABLE, headers::constrain_header_field_detect_last_angle_bracket,
    MAX_EMAIL_ADDRESS_LENGTH, Sequence,
};

/**
 * Constrained extraction of the email address from an address header field
 * Fields longer than MAX_EMAIL_ADDRESS_LENGTH + HEADER_FIELD_NAME_LENGTH + 1 bytes (name included)
 * are rejected; use get_email_address_with_max_field_length to choose another cap.
 */
pub fn get_email_address<let MAX_HEADER_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    email_address_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    get_email_address_with_max_field_length::<MAX_HEADER_LENGTH, HEADER_FIELD_NAME_LENGTH, MAX_EMAIL_ADDRESS_LENGTH + HEADER_FIELD_NAME_LENGTH + 1>(
        header,
        header_field_sequence,
        email_address_sequence,
        header_field_name,
    )
}

/**
 * get_email_address with a caller-chosen cap on the header field length
 * The field is scanned up to the cap, so circuit size grows with it. A larger cap allows long
 * display names; the address itself is still at most MAX_EMAIL_ADDRESS_LENGTH bytes.
 *
 * @param MAX_FIELD_LENGTH - The maximum length of the header field, name included
 */
pub fn get_email_address_with_max_field_length<let MAX_HEADER_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32, let MAX_FIELD_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    email_address_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    // check field is uninterrupted and matches the expected field name
    let last_angle_bracket = constrain_header_field_detect_last_angle_bracket::<MAX_HEADER_LENGTH, MAX_FIELD_LENGTH, HEADER_FIELD_NAME_LENGTH>(
        header,
        header_field_sequence,
        header_field_name,
    );
    // if angle bracket found, assert index is +1
    if last_angle_bracket != 0 {
        assert(
            email_address_sequence.index == last_angle_bracket + 1,
            "Email address must start immediately after '<' if bracket is present",
        );
    }
    // check email sequence is within header field
    assert(
        email_address_sequence.index >= header_field_sequence.index
            & email_address_sequence.end_index() <= header_field_sequence.end_index(),
        "Email address sequence out of bounds",
    );

    // constrained get email address
    let email_address = parse_email_address(header, email_address_sequence);
    // the address must end the field (followed only by '>' if bracketed), so text after it,
    // such as a comment holding "<other@address>", cannot be selected instead
    let email_end = email_address_sequence.end_index();
    if last_angle_bracket != 0 {
        assert(
            (email_end + 1 == header_field_sequence.end_index())
                & (header.get_unchecked(email_end) == 0x3e),
            "Email address and its closing '>' must end the field",
        );
    } else {
        assert(
            email_end == header_field_sequence.end_index(),
            "Email address must end the field if no bracket is present",
        );
    }
    email_address
}

// EMAIL_ADDRESS_CHAR_TABLE with '@' (0x40) marked 4 instead of 1
global ADDRESS_CHAR_CLASS: [u8; 123] = comptime {
    let mut table = EMAIL_ADDRESS_CHAR_TABLE;
    table[0x40] = 4;
    table
};

// The offset of the only '@' in the address, or its length if it has none or several (so that
// parse_email_address fails with the '@' message rather than the character message).
unconstrained fn find_at_sign<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    email_address_sequence: Sequence,
) -> u32 {
    let mut offset = email_address_sequence.length;
    let mut count = 0;
    for i in 0..email_address_sequence.length {
        if header.get_unchecked(email_address_sequence.index + i) == 0x40 {
            offset = i;
            count += 1;
        }
    }
    if count == 1 {
        offset
    } else {
        email_address_sequence.length
    }
}

pub fn parse_email_address<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    email_address_sequence: Sequence,
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    // check the sequence is proceeded by an acceptable character
    if email_address_sequence.index != 0 {
        assert(
            EMAIL_ADDRESS_CHAR_TABLE[header.get_unchecked(email_address_sequence.index - 1) as u32]
                == 2,
            "Email address must start with an acceptable character",
        );
    }
    if email_address_sequence.end_index() < header.len() {
        assert(
            EMAIL_ADDRESS_CHAR_TABLE[header.get_unchecked(
                email_address_sequence.index + email_address_sequence.length,
            ) as u32]
                == 3,
            "Email address must end with an acceptable character",
        );
    }
    // check the email address and assign
    let mut email_address: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> =
        BoundedVec::from_parts([0; MAX_EMAIL_ADDRESS_LENGTH], email_address_sequence.length);
    // exactly one '@': the prover names its offset, the byte there must be '@', and every other
    // byte must be an acceptable character other than '@'. This costs one constraint per byte on
    // top of the character check, where counting the '@'s costs several.
    // Safety: the byte at at_offset is constrained to be the address's '@' below
    let at_offset = unsafe { find_at_sign(header, email_address_sequence) };
    assert(
        at_offset < email_address_sequence.length,
        "Email address must contain '@' exactly once",
    );
    assert(
        header.get_unchecked(email_address_sequence.index + at_offset) == 0x40,
        "Email address must contain '@' exactly once",
    );
    for i in 0..MAX_EMAIL_ADDRESS_LENGTH {
        let index = email_address_sequence.index + i;
        if index < email_address_sequence.end_index() {
            let letter = header.get_unchecked(index);
            email_address.set_unchecked(i, letter);
            let class = ADDRESS_CHAR_CLASS[letter as u32] as Field;
            assert(
                (class - 1) * (i as Field - at_offset as Field) == 0,
                "Email address must only contain acceptable characters",
            );
        }
    }
    email_address
}
