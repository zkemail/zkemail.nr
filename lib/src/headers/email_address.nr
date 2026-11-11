use crate::{
    EMAIL_ADDRESS_CHAR_TABLE, headers::scan_address_field, MAX_EMAIL_ADDRESS_LENGTH, Sequence,
};

pub fn get_email_address<let MAX_HEADER_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    header_field_sequence: Sequence,
    email_address_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH],
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    // check field is uninterrupted and matches the expected field name
    let (last_angle_bracket, last_non_fws) = scan_address_field::<MAX_HEADER_LENGTH, MAX_EMAIL_ADDRESS_LENGTH + HEADER_FIELD_NAME_LENGTH + 1, HEADER_FIELD_NAME_LENGTH>(
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
    // REASON: the address must end the field, followed only by '>' if bracketed and then by
    // folding whitespace (c=simple keeps trailing whitespace and folds; relaxed strips them). Text
    // after it, such as a quoted string holding "<other@address>", cannot be selected instead.
    let email_end = email_address_sequence.end_index();
    if last_angle_bracket != 0 {
        assert(
            (header.get_unchecked(email_end) == 0x3e) & (last_non_fws == email_end),
            "Email address and its closing '>' must end the field",
        );
    } else {
        assert(
            last_non_fws + 1 == email_end,
            "Email address must end the field if no bracket is present",
        );
    }
    email_address
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
    let mut at_count = 0;
    for i in 0..MAX_EMAIL_ADDRESS_LENGTH {
        let index = email_address_sequence.index + i;
        if index < email_address_sequence.end_index() {
            let letter = header.get_unchecked(index);
            email_address.set_unchecked(i, letter);
            assert(
                EMAIL_ADDRESS_CHAR_TABLE[letter as u32] == 1,
                "Email address must only contain acceptable characters",
            );
            if letter == 0x40 {
                at_count += 1;
            }
        }
    }
    assert(at_count == 1, "Email address must contain '@' exactly once");
    email_address
}
