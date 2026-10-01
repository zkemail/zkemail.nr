pub(crate) mod test_inputs;

mod test_success {

    use crate::{
        headers::{body_hash::get_body_hash, email_address::get_email_address},
        MAX_EMAIL_ADDRESS_LENGTH,
        partial_hash::partial_sha256_var_end,
        tests::test_inputs::EmailLarge,
    };
    use sha256::sha256_var;

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
    use sha256::sha256_var;

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

mod test_redc_binding_2048 {
    use crate::tests::test_inputs::EmailLarge;

    /// Regression test for Veridise vulnerability reintroduced by PR #52.
    /// Verifies that modifying redc changes hash[1] (redc hash) but NOT hash[0] (modulus hash).
    #[test]
    fn test_modified_redc_changes_hash_2048() {
        let pubkey = EmailLarge::PUBKEY;
        let original_hash = pubkey.hash();

        // Construct a pubkey with same modulus but tampered redc (flip one limb)
        let mut tampered_redc = pubkey.redc;
        tampered_redc[0] = tampered_redc[0] + 1;
        let tampered_pubkey = crate::dkim::RSAPubkey::new(pubkey.modulus, tampered_redc);
        let tampered_hash = tampered_pubkey.hash();

        // hash[0] = poseidon(modulus) -- must be UNCHANGED since modulus is the same
        assert(
            original_hash[0] == tampered_hash[0],
            "modulus hash (hash[0]) must not change when only redc is modified",
        );
        // hash[1] = poseidon(redc) -- must DIFFER since redc was tampered
        assert(
            original_hash[1] != tampered_hash[1],
            "redc hash (hash[1]) must change when redc is modified",
        );
    }

    /// poseidon_large only hashes the low 17 bits of redc[17] (17 x 121-bit repacking), so any
    /// higher bit set there must be rejected by validate_in_range, or redc would not be bound by
    /// hash()[1].
    #[test(should_fail)]
    fn test_redc_top_limb_bits_outside_hash_are_rejected_2048() {
        let pubkey = EmailLarge::PUBKEY;
        let mut tampered_redc = pubkey.redc;
        tampered_redc[17] = tampered_redc[17] + 131072; // 1 << 17: lowest bit the hash ignores
        let tampered_pubkey = crate::dkim::RSAPubkey::new(pubkey.modulus, tampered_redc);
        let _ = tampered_pubkey.hash();
    }
}

mod test_redc_binding_1024 {
    use crate::tests::test_inputs::EmailSmall;

    /// Same regression test as test_redc_binding but for the 1024-bit code path,
    /// which uses poseidon_large_padded_1024 (pads 9 limbs to 18 before hashing).
    #[test]
    fn test_modified_redc_changes_hash_1024() {
        let pubkey = EmailSmall::PUBKEY;
        let original_hash = pubkey.hash();

        let mut tampered_redc = pubkey.redc;
        tampered_redc[0] = tampered_redc[0] + 1;
        let tampered_pubkey = crate::dkim::RSAPubkey::new(pubkey.modulus, tampered_redc);
        let tampered_hash = tampered_pubkey.hash();

        // hash[0] = poseidon_large_padded_1024(modulus) -- must be UNCHANGED
        assert(
            original_hash[0] == tampered_hash[0],
            "modulus hash (hash[0]) must not change when only redc is modified (1024-bit)",
        );
        // hash[1] = poseidon_large_padded_1024(redc) -- must DIFFER
        assert(
            original_hash[1] != tampered_hash[1],
            "redc hash (hash[1]) must change when redc is modified (1024-bit)",
        );
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
    use crate::{
        headers::email_address::get_email_address,
        tests::test_inputs::{EmailAddresses, EmailAddressUnderscore},
    };

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

    #[test]
    fn test_underscore_address() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 512> = BoundedVec::from_array(EmailAddressUnderscore::HEADER);
        let address = get_email_address(
            header,
            EmailAddressUnderscore::FIELD_SEQUENCE,
            EmailAddressUnderscore::ADDRESS_SEQUENCE,
            from,
        );
        assert_eq(address, EmailAddressUnderscore::ADDRESS);
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

// Header-field parsing: case-insensitive names, folded fields (c=simple), field length bound.
mod test_header_field_canonicalization {
    use crate::{headers::{body_hash::get_body_hash, constrain_header_field}, Sequence};

    // sha256("") = e3b0c442...b855, base64 "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    global EMPTY_BODY_HASH: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    #[test]
    fn test_uppercase_field_name_matches() {
        let header: BoundedVec<u8, 64> = BoundedVec::from_array(
            comptime { "Subject:hi\r\nFrom:a@b.cd\r\nto:x@y.zz".as_bytes() },
        );
        let from: [u8; 4] = comptime { "from".as_bytes() };
        constrain_header_field::<64, 16, 4>(header, Sequence { index: 12, length: 11 }, from);
    }

    #[test(should_fail_with = "Header field name does not match")]
    fn test_different_field_name_rejected() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "Frum:a@b.cd\r\nto:x@y.zz".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        constrain_header_field::<64, 16, 4>(header, Sequence { index: 0, length: 11 }, from);
    }

    #[test]
    fn test_folded_field_accepted() {
        let header: BoundedVec<u8, 64> = BoundedVec::from_array(
            comptime { "x-test:a;\r\n\tb;\r\n c\r\nto:x@y.zz".as_bytes() },
        );
        let name: [u8; 6] = comptime { "x-test".as_bytes() };
        constrain_header_field::<64, 32, 6>(header, Sequence { index: 0, length: 18 }, name);
    }

    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_line_break_without_fold_rejected() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "x-test:a\r\nto:x@y.zz".as_bytes() });
        let name: [u8; 6] = comptime { "x-test".as_bytes() };
        constrain_header_field::<64, 32, 6>(header, Sequence { index: 0, length: 19 }, name);
    }

    // A fold's CRLF + WSP must be inside the field; the bytes after header.len() are unconstrained
    // padding and must not complete one.
    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_fold_completed_by_padding_rejected() {
        let storage: [u8; 16] = comptime { "x-test:a\r\n zzzzz".as_bytes() };
        let header: BoundedVec<u8, 16> = BoundedVec::from_parts_unchecked(storage, 9);
        let name: [u8; 6] = comptime { "x-test".as_bytes() };
        constrain_header_field::<16, 32, 6>(header, Sequence { index: 0, length: 9 }, name);
    }

    #[test]
    fn test_field_at_max_length_accepted() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "from:abcd".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        constrain_header_field::<64, 4, 4>(header, Sequence { index: 0, length: 9 }, from);
    }

    // The line-break scan covers MAX_HEADER_FIELD_LENGTH bytes after "<name>:", so a longer
    // field must be rejected rather than partially checked.
    #[test(should_fail_with = "Header field too long")]
    fn test_field_longer_than_scan_window_rejected() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "from:abcdef\r\nto:zz".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        constrain_header_field::<64, 4, 4>(header, Sequence { index: 0, length: 18 }, from);
    }

    // Same bound on the DKIM-Signature path (MAX_DKIM_HEADER_FIELD_LENGTH = 1024).
    #[test(should_fail_with = "Header field too long")]
    fn test_dkim_field_longer_than_max_rejected() {
        let prefix: [u8; 68] = comptime {
            "dkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;".as_bytes()
        };
        let mut storage: [u8; 1100] = [0x61; 1100];
        for i in 0..68 {
            storage[i] = prefix[i];
        }
        let header: BoundedVec<u8, 1100> = BoundedVec::from_array(storage);
        let _ = get_body_hash(header, Sequence { index: 0, length: 1100 }, 23);
    }

    // Long real-world DKIM-Signature fields (> the old 300-byte window) must still be accepted.
    #[test]
    fn test_dkim_field_of_900_bytes_accepted() {
        let prefix: [u8; 68] = comptime {
            "dkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;".as_bytes()
        };
        let mut storage: [u8; 900] = [0x61; 900];
        for i in 0..68 {
            storage[i] = prefix[i];
        }
        let header: BoundedVec<u8, 900> = BoundedVec::from_array(storage);
        let body_hash = get_body_hash(header, Sequence { index: 0, length: 900 }, 23);
        assert(body_hash == EMPTY_BODY_HASH);
    }

    // c=simple keeps the "DKIM-Signature" spelling.
    #[test]
    fn test_body_hash_mixed_case_dkim_signature() {
        let header: BoundedVec<u8, 128> = BoundedVec::from_array(
            comptime {
                "from:a@b.cd\r\nDKIM-Signature: v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let body_hash = get_body_hash(header, Sequence { index: 13, length: 72 }, 37);
        assert(body_hash == EMPTY_BODY_HASH);
    }

    #[test]
    fn test_body_hash_after_semicolon_without_space() {
        let header: BoundedVec<u8, 128> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1;bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;b=".as_bytes()
            },
        );
        let body_hash = get_body_hash(header, Sequence { index: 0, length: 69 }, 22);
        assert(body_hash == EMPTY_BODY_HASH);
    }

    #[test]
    fn test_body_hash_after_tab_fold() {
        let header: BoundedVec<u8, 128> = BoundedVec::from_array(
            comptime {
                "DKIM-Signature: v=1; a=rsa-sha256;\r\n\tbh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n\tb="
                    .as_bytes()
            },
        );
        let body_hash = get_body_hash(header, Sequence { index: 0, length: 90 }, 40);
        assert(body_hash == EMPTY_BODY_HASH);
    }

    #[test]
    fn test_body_hash_after_space_fold() {
        let header: BoundedVec<u8, 128> = BoundedVec::from_array(
            comptime {
                "DKIM-Signature: v=1; a=rsa-sha256;\r\n bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n b="
                    .as_bytes()
            },
        );
        let body_hash = get_body_hash(header, Sequence { index: 0, length: 90 }, 40);
        assert(body_hash == EMPTY_BODY_HASH);
    }

    // "bh=" that does not start a tag (here the tail of "xbh=") is still rejected.
    #[test(should_fail_with = "No ':bh=' or '; bh=' prefix found before body hash")]
    fn test_body_hash_not_starting_a_tag_rejected() {
        let header: BoundedVec<u8, 128> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; xbh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;b=".as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 71 }, 24);
    }
}

mod test_masking {
    use crate::masking::mask_text;

    // Bytes past len are unconstrained padding and must never be output, even if the mask
    // selects them.
    #[test]
    fn test_mask_text_zeroes_bytes_past_len() {
        let text: BoundedVec<u8, 8> =
            BoundedVec::from_parts_unchecked([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68], 4);
        let masked = mask_text(text, [true; 8]);
        assert(masked == [0x61, 0x62, 0x63, 0x64, 0, 0, 0, 0]);
    }

    #[test]
    fn test_mask_text_applies_mask_within_len() {
        let text: BoundedVec<u8, 8> =
            BoundedVec::from_parts_unchecked([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68], 4);
        let masked = mask_text(text, [true, false, true, false, true, true, true, true]);
        assert(masked == [0x61, 0, 0x63, 0, 0, 0, 0, 0]);
    }
}
