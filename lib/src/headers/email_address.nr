use dep::std::collections::bounded_vec::BoundedVec;
use crate::{
    Sequence, MAX_EMAIL_ADDRESS_LENGTH, EMAIL_ADDRESS_CHAR_TABLE,
    headers::constrain_header_field_detect_last_angle_bracket
};

pub fn get_email_address<let MAX_HEADER_LENGTH: u32, let HEADER_FIELD_NAME_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    from_header_field_sequence: Sequence,
    email_address_sequence: Sequence,
    header_field_name: [u8; HEADER_FIELD_NAME_LENGTH]
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    // check field is uninterrupted and matches the expected field name
    let last_angle_bracket = constrain_header_field_detect_last_angle_bracket::<
        MAX_HEADER_LENGTH,
        MAX_EMAIL_ADDRESS_LENGTH + HEADER_FIELD_NAME_LENGTH + 1,
        HEADER_FIELD_NAME_LENGTH
    >(header, from_header_field_sequence, header_field_name);
    // if angle bracket found, assert index is +1
    if last_angle_bracket != 0 {
        assert(
            email_address_sequence.index == last_angle_bracket + 1, "Email address must start immediately after '<' if bracket is present"
        );
    }
    // check email sequence is within header field
    assert(
        email_address_sequence.index >= from_header_field_sequence.index
        & email_address_sequence.index + email_address_sequence.length <= last_angle_bracket, "Email address sequence out of bounds"
    );

    // constrained get email address
    parse_email_address(header, email_address_sequence)
}

pub fn parse_email_address<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    email_address_sequence: Sequence
) -> BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> {
    // check the sequence is proceeded by an acceptable character
    assert(
        EMAIL_ADDRESS_CHAR_TABLE[header.get_unchecked(email_address_sequence.index - 1)] == 2, "Email address must start with an acceptable character"
    );
    assert(
        EMAIL_ADDRESS_CHAR_TABLE[header.get_unchecked(email_address_sequence.index + email_address_sequence.length)]
        == 3, "Email address must end with an acceptable character"
    );
    // check the email address and assign
    let mut email_address: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> = BoundedVec::new();
    for i in 0..MAX_EMAIL_ADDRESS_LENGTH {
        let index = email_address_sequence.index + i;
        assert(
            EMAIL_ADDRESS_CHAR_TABLE[header.get_unchecked(index)] != 1, "Email address contains an unacceptable character"
        );
        email_address.push(header.get_unchecked(index));
    }
    // todo: should probably introduce a check for @

    email_address
}

