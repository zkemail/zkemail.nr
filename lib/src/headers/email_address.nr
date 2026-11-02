use crate::{
    EMAIL_ADDRESS_CHAR_TABLE, headers::constrain_header_field_detect_last_angle_bracket,
    MAX_EMAIL_ADDRESS_LENGTH, Sequence,
};

/**
 * Constrained extraction of the email address from an address header field
 * Fields whose value (after "<name>:") is longer than MAX_EMAIL_ADDRESS_LENGTH +
 * HEADER_FIELD_NAME_LENGTH + 1 bytes are rejected; use get_email_address_with_max_field_length to
 * choose another cap.
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
 * get_email_address with a caller-chosen cap on the header field value
 * The field is scanned up to the cap, so circuit size grows with it. A larger cap allows long
 * display names; the address itself is still at most MAX_EMAIL_ADDRESS_LENGTH bytes.
 *
 * @param MAX_FIELD_LENGTH - The maximum length of the header field value, after "<name>:"
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
    parse_email_address(header, email_address_sequence)
}

pub fn parse_email_address<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    email_address_sequence: Sequence,
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    // check the sequence is proceeded by an acceptable character
    if email_address_sequence.index != 0 {
        assert(
            EMAIL_ADDRESS_CHAR_TABLE[header.get_unchecked(email_address_sequence.index - 1)] == 2,
            "Email address must start with an acceptable character",
        );
    }
    if email_address_sequence.end_index() < header.len() {
        assert(
            EMAIL_ADDRESS_CHAR_TABLE[header.get_unchecked(
                email_address_sequence.index + email_address_sequence.length,
            )]
                == 3,
            "Email address must end with an acceptable character",
        );
    }
    // check the email address and assign
    let mut email_address: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> = BoundedVec::new();
    let mut at_count = 0;
    for i in 0..MAX_EMAIL_ADDRESS_LENGTH {
        let index = email_address_sequence.index + i;
        if index < email_address_sequence.end_index() {
            let letter = header.get_unchecked(index);
            email_address.set_unchecked(i, letter);
            assert(
                EMAIL_ADDRESS_CHAR_TABLE[letter] == 1,
                "Email address must only contain acceptable characters",
            );
            if letter == 0x40 {
                at_count += 1;
            }
        }
    }
    assert(at_count == 1, "Email address must contain '@' exactly once");
    email_address.len = email_address_sequence.length;
    email_address
}
