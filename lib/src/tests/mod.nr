pub(crate) mod test_inputs;

mod test_success {

    use crate::{
        headers::{body_hash::get_body_hash, email_address::get_email_address},
        MAX_EMAIL_ADDRESS_LENGTH,
        partial_hash::partial_sha256_var_end,
        tests::test_inputs::EmailLarge,
    };
    use std::hash::sha256_var;

    #[test]
    fn test_dkim_signature() {
        EmailLarge::PUBKEY.verify_dkim_signature(EmailLarge::HEADER, EmailLarge::SIGNATURE);
    }

    #[test]
    fn test_body_hash() {
        // get the body hash from the header
        let signed_body_hash = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
        // compute the body hash
        let computed_body_hash: [u8; 32] =
            sha256_var(EmailLarge::BODY.storage(), EmailLarge::BODY.len() as u64);
        // compare the body hashes
        assert(
            signed_body_hash == computed_body_hash,
            "SHA256 hash computed over body does not match body hash found in DKIM-signed header",
        );
    }

    #[test]
    fn test_partial_hash() {
        // get the body hash from the header
        let signed_body_hash = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
        // finish the partial hash
        let computed_body_hash = partial_sha256_var_end(
            EmailLarge::PARTIAL_BODY_HASH,
            EmailLarge::PARTIAL_BODY.storage(),
            EmailLarge::PARTIAL_BODY.len() as u64,
            EmailLarge::PARTIAL_BODY_REAL_LENGTH as u64,
        );
        // compare the body hashes
        assert(
            signed_body_hash == computed_body_hash,
            "Sha256 hash computed over body does not match DKIM-signed header",
        );
    }

    #[test]
    fn test_address_extraction() {
        let from = comptime { "from".as_bytes() };
        let to = comptime { "to".as_bytes() };
        // 16k gate cost? has to be able to be brought down
        let from_address = get_email_address(
            EmailLarge::HEADER,
            EmailLarge::FROM_HEADER_SEQUENCE,
            EmailLarge::FROM_ADDRESS_SEQUENCE,
            from,
        );
        let to_address = get_email_address(
            EmailLarge::HEADER,
            EmailLarge::TO_HEADER_SEQUENCE,
            EmailLarge::TO_ADDRESS_SEQUENCE,
            to,
        );
        let expected_from_address: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> =
            BoundedVec::from_array("runnier.leagues.0j@icloud.com".as_bytes());
        let expected_to_address: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> =
            BoundedVec::from_array("zkewtest@gmail.com".as_bytes());
        assert_eq(
            expected_from_address,
            from_address,
            "From address does not match expected address",
        );
        assert_eq(expected_to_address, to_address, "To address does not match expected address");
    }
}

mod test_tampered_hash {
    use crate::{headers::body_hash::get_body_hash, tests::test_inputs::EmailLarge};
    use std::hash::sha256_var;

    // no reasonable message to constrain here
    #[test(should_fail)]
    fn test_tampered_header() {
        // get tampered header
        let mut tampered_header = unsafe { EmailLarge::tampered_header() };
        // attempt to verify the DKIM signature
        EmailLarge::PUBKEY.verify_dkim_signature(tampered_header, EmailLarge::SIGNATURE);
    }

    #[test]
    fn test_tampered_body() {
        // get the body hash from the header
        let signed_body_hash = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
        // get tampered body
        let mut tampered_body = unsafe { EmailLarge::tampered_body() };
        // compute the body hash
        let tampered_body_hash: [u8; 32] =
            sha256_var(tampered_body.storage(), tampered_body.len() as u64);
        // compare the body hashes
        assert(
            signed_body_hash != tampered_body_hash,
            "SHA256 hash should not match tampered body hash",
        );
    }

    #[test(should_fail_with = "all to assert_max_bit_size")]
    fn test_dkim_signature_unnormalized() {
        let mut sig = EmailLarge::SIGNATURE;
        let pubkey = EmailLarge::PUBKEY;
        let delta = 1;
        sig[0] += delta * 0x1000000000000000000000000000000;
        sig[1] -= delta;
        pubkey.verify_dkim_signature(EmailLarge::HEADER, sig);
    }
}

mod header_field_access {

    use crate::{headers::body_hash::get_body_hash, Sequence, tests::test_inputs::EmailLarge};

    #[test(should_fail_with = "No ':bh=' or '; bh=' prefix found before body hash")]
    fn test_bad_body_hash_off_one_minus() {
        // attempt to get body hash with one off index
        let _ = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX - 1,
        );
    }

    #[test(should_fail_with = "No ':bh=' or '; bh=' prefix found before body hash")]
    fn test_bad_body_hash_off_one_plus() {
        // attempt to get body hash with one off index
        let _ = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX + 1,
        );
    }

    #[test(should_fail_with = "Header field name does not match")]
    fn test_bad_body_hash_not_in_dkim_field() {
        // create header field for malicious bh
        let mut dkim_field: BoundedVec<u8, EmailLarge::EMAIL_LARGE_MAX_HEADER_LENGTH> =
            BoundedVec::new();
        dkim_field.len = EmailLarge::HEADER.len();
        // craft a malicious "to" field where attacker tries to put bh in display name
        let mut malicious_to: [u8; 78] = comptime {
            "\r\nto:\"bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\" <zkewtest@gmail.com>\r\n"
                .as_bytes()
        };
        let mut malicious_sequence = Sequence {
            index: 8, // 8 to make it check for crlf on both sides (could be anything > 2)
            length: malicious_to.len() - 4, // 4 is the crlf on each end
        };
        for i in 0..malicious_to.len() {
            let index = malicious_sequence.index + i - 2;
            dkim_field.storage[index] = malicious_to[i];
        }
        let malicious_body_hash_index = 15;
        // copy the body hash to the beginning of the
        // attempt to get body hash
        let _ = get_body_hash(dkim_field, malicious_sequence, malicious_body_hash_index);
    }

    #[test]
    fn test_body_hash_at_start() {
        let mut dkim_field: [u8; 203] = comptime {
            "dkim-signature:bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; v=1; a=rsa-sha256; c=relaxed/relaxed; d=icloud.com; s=1a1hai; t=1712141644; h=from:Content-Type:Mime-Version:Subject:Message-Id:Date:to; b="
                .as_bytes()
        };
        let header: BoundedVec<u8, 203> = BoundedVec { storage: dkim_field, len: 203 };
        let mut dkim_field_sequence = Sequence { index: 0, length: 203 };
        let body_hash_index = 18;
        let _ = get_body_hash(header, dkim_field_sequence, body_hash_index);
    }

    #[test(should_fail_with = "No ':bh=' or '; bh=' prefix found before body hash")]
    fn test_malicious_body_hash_index() {
        // tests against "dkim-signature: v=1; a=rsa-sha256; d=example.com; s=selector; c=relaxed/relaxed; q=dns/txt; t=1683849600; x=1684454400; h=from:to:subject:date; z=From:bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=@domain.com|To:recipient@example.net|Subject:Hello|Date:Thu, 11 May 2023 15:00:00 -0700; bh=2jUSOH9NhtVGCaWpZT2ncBgaamXkef9OgICHkqfsmKY=; b="
        let (header, body_hash_index) = EmailLarge::tampered_dkim_field();
        let sequence: Sequence = Sequence { index: 0, length: header.len() };
        let _ = get_body_hash(header, sequence, body_hash_index);
    }

    #[test(should_fail_with = "Header field must end with CRLF")]
    fn test_header_field_sequence_overflow_end() {
        // make sequence extend beyond the end of the header field
        let mut overflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        overflowed_sequence.length = overflowed_sequence.length + 1;
        // set header len to be a bit longer so it doesn't overflow
        let mut longer_header = EmailLarge::HEADER;
        longer_header.len = longer_header.len + 2;
        // attempt to get body hash
        let _ = get_body_hash(
            longer_header,
            overflowed_sequence,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must start with CRLF")]
    fn test_header_field_sequence_overflow_start() {
        // make sequence extend beyond the start of the header field
        let mut overflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        overflowed_sequence.index = overflowed_sequence.index - 1;
        // attempt to get body hash
        let _ = get_body_hash(
            EmailLarge::HEADER,
            overflowed_sequence,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must end with CRLF")]
    fn test_header_field_sequence_underflow_end() {
        // make sequence extend beyond the end of the header field
        let mut underflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        underflowed_sequence.length = underflowed_sequence.length - 1;
        // attempt to get body hash
        let _ = get_body_hash(
            EmailLarge::HEADER,
            underflowed_sequence,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must start with CRLF")]
    fn test_header_field_sequence_underflow_start() {
        // make sequence extend beyond the end of the header field
        let mut underflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        underflowed_sequence.index = underflowed_sequence.length + 1;
        // attempt to get body hash
        let _ = get_body_hash(
            EmailLarge::HEADER,
            underflowed_sequence,
            EmailLarge::BODY_HASH_INDEX,
        );
    }

    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_header_field_multiple_fields() {
        // combine to and dkim-signature fields together
        let mut tampered_header: BoundedVec<u8, EmailLarge::EMAIL_LARGE_MAX_HEADER_LENGTH> =
            BoundedVec::new();
        let combined_sequence = Sequence {
            index: 2,
            length: EmailLarge::TO_HEADER_SEQUENCE.length
                + EmailLarge::DKIM_HEADER_SEQUENCE.length
                + 2, // 2 for crlf in middle
        };
        tampered_header.len = combined_sequence.length + 4;
        // copy dkim-signature field
        for i in 0..EmailLarge::DKIM_HEADER_SEQUENCE.length + 2 {
            tampered_header.set(
                i,
                EmailLarge::HEADER.get(EmailLarge::DKIM_HEADER_SEQUENCE.index + i - 2),
            );
        }
        tampered_header.set(EmailLarge::DKIM_HEADER_SEQUENCE.length + 2, "\r".as_bytes()[0]);
        tampered_header.set(EmailLarge::DKIM_HEADER_SEQUENCE.length + 3, "\n".as_bytes()[0]);
        // copy to field
        for i in 0..EmailLarge::TO_HEADER_SEQUENCE.length + 2 {
            let index = EmailLarge::DKIM_HEADER_SEQUENCE.length + 4;
            tampered_header.set(
                index + i,
                EmailLarge::HEADER.get(EmailLarge::TO_HEADER_SEQUENCE.index + i),
            );
        }
        // set crlf at end
        tampered_header.set(combined_sequence.length + 2, "\r".as_bytes()[0]);
        tampered_header.set(combined_sequence.length + 3, "\n".as_bytes()[0]);
        let tampered_body_hash_index = 93; // just manually setting this
        // attempt to get body hash
        let _ = get_body_hash(tampered_header, combined_sequence, tampered_body_hash_index);
    }

    #[test(should_fail_with = "Header field out of bounds")]
    fn test_header_field_outside_header() {
        let mut shortened_header = EmailLarge::HEADER;
        // shorten header to be just under the end of the dkim field
        shortened_header.len =
            EmailLarge::DKIM_HEADER_SEQUENCE.index + EmailLarge::DKIM_HEADER_SEQUENCE.length - 1;
        // attempt to get body hash
        let _ = get_body_hash(
            shortened_header,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX,
        );
    }
}

mod test_address_extraction {
    // header field constrains are not checked here, should work same as tests in header_field_access
    use crate::{headers::email_address::get_email_address, tests::test_inputs::EmailAddresses};

    #[test]
    fn test_email_only() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::ADDRESS_ONLY);
        let address = get_email_address(
            header,
            EmailAddresses::ADDRESS_ONLY_FIELD_SEQUENCE,
            EmailAddresses::ADDRESS_ONLY_ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddresses::ADDRESS);
    }

    #[test]
    fn test_no_brackets() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::NO_BRACKETS);
        let address = get_email_address(
            header,
            EmailAddresses::NO_BRACKETS_FIELD_SEQUENCE,
            EmailAddresses::NO_BRACKETS_ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddresses::ADDRESS);
    }

    #[test]
    fn test_brackets() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::BRACKETS);
        let address = get_email_address(
            header,
            EmailAddresses::BRACKETS_FIELD_SEQUENCE,
            EmailAddresses::BRACKETS_ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddresses::ADDRESS);
    }

    #[test]
    fn test_quotes() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::QUOTES);
        let address = get_email_address(
            header,
            EmailAddresses::QUOTES_FIELD_SEQUENCE,
            EmailAddresses::QUOTES_ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddresses::ADDRESS);
    }

    #[test(should_fail_with = "Email address must start immediately after '<' if bracket is present")]
    fn test_malicious_display_name() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::QUOTES);
        let _ = get_email_address(
            header,
            EmailAddresses::QUOTES_FIELD_SEQUENCE,
            EmailAddresses::MALICIOUS_QUOTES_ADDRESS_SEQUENCE,
            from,
        );
    }

    #[test(should_fail_with = "Email address must start immediately after '<' if bracket is present")]
    fn test_not_full_address_bracket_start() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        // mutate index to remove "runnier." from address
        let mut malicious_sequence = EmailAddresses::QUOTES_ADDRESS_SEQUENCE;
        malicious_sequence.index = malicious_sequence.index + 8;
        malicious_sequence.length = malicious_sequence.length - 8;
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::QUOTES);
        let _ = get_email_address(
            header,
            EmailAddresses::QUOTES_FIELD_SEQUENCE,
            malicious_sequence,
            from,
        );
    }

    #[test(should_fail_with = "Email address must end with an acceptable character")]
    fn test_not_full_address_bracket_end() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        // mutate index to remove ".com" from address
        let mut malicious_sequence = EmailAddresses::QUOTES_ADDRESS_SEQUENCE;
        malicious_sequence.index = malicious_sequence.index;
        malicious_sequence.length = malicious_sequence.length - 4;
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::QUOTES);
        let _ = get_email_address(
            header,
            EmailAddresses::QUOTES_FIELD_SEQUENCE,
            malicious_sequence,
            from,
        );
    }

    #[test(should_fail_with = "Email address must start with an acceptable character")]
    fn test_not_full_address_start() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        // mutate index to remove "runnier." from address
        let mut malicious_sequence = EmailAddresses::ADDRESS_ONLY_ADDRESS_SEQUENCE;
        malicious_sequence.index = malicious_sequence.index + 8;
        malicious_sequence.length = malicious_sequence.length - 8;
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::ADDRESS_ONLY);
        let _ = get_email_address(
            header,
            EmailAddresses::ADDRESS_ONLY_FIELD_SEQUENCE,
            malicious_sequence,
            from,
        );
    }

    #[test(should_fail_with = "Email address must end with an acceptable character")]
    fn test_not_full_address_end() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        // mutate index to remove ".com" from address
        let mut malicious_sequence = EmailAddresses::ADDRESS_ONLY_ADDRESS_SEQUENCE;
        malicious_sequence.index = malicious_sequence.index;
        malicious_sequence.length = malicious_sequence.length - 4;
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddresses::ADDRESS_ONLY);
        let _ = get_email_address(
            header,
            EmailAddresses::ADDRESS_ONLY_FIELD_SEQUENCE,
            malicious_sequence,
            from,
        );
    }
}
