pub(crate) mod test_inputs;
mod header_parsing;

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
            sha256_var(EmailLarge::BODY.storage(), EmailLarge::BODY.len());
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
            EmailLarge::PARTIAL_BODY.len(),
            EmailLarge::PARTIAL_BODY_REAL_LENGTH,
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
    use crate::{
        headers::body_hash::get_body_hash,
        tests::test_inputs::{EmailLarge, SyntheticKey1024},
    };
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
        let tampered_body_hash: [u8; 32] = sha256_var(tampered_body.storage(), tampered_body.len());
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

    #[test(should_fail_with = "Limb does not fit in u128")]
    fn test_dkim_signature_limb_above_u128() {
        // `as u128` would drop the 2^128 term, leaving the original signature
        let mut sig = EmailLarge::SIGNATURE;
        sig[0] += 0x100000000000000000000000000000000;
        EmailLarge::PUBKEY.verify_dkim_signature(EmailLarge::HEADER, sig);
    }

    #[test]
    fn test_dkim_signature_synthetic_1024() {
        SyntheticKey1024::PUBKEY.verify_dkim_signature(
            SyntheticKey1024::MESSAGE,
            SyntheticKey1024::SIGNATURE,
        );
    }

    #[test(should_fail_with = "all to assert_max_bit_size")]
    fn test_dkim_signature_not_reduced() {
        SyntheticKey1024::PUBKEY.verify_dkim_signature(
            SyntheticKey1024::MESSAGE,
            SyntheticKey1024::SIGNATURE_PLUS_MODULUS,
        );
    }
}

mod test_digest_verification {
    use crate::tests::test_inputs::{EmailLarge, SyntheticKey1024};
    use sha256::sha256_var;

    #[test]
    fn test_verify_digest_2048() {
        let digest = sha256_var(EmailLarge::HEADER.storage(), EmailLarge::HEADER.len());
        let verified =
            EmailLarge::PUBKEY.verify_digest_sha256_pkcs1v15(digest, EmailLarge::SIGNATURE);
        assert_eq(verified, digest);
    }

    #[test]
    fn test_verify_digest_1024() {
        let message = SyntheticKey1024::MESSAGE;
        let digest = sha256_var(message.storage(), message.len());
        let _ = SyntheticKey1024::PUBKEY.verify_digest_sha256_pkcs1v15(
            digest,
            SyntheticKey1024::SIGNATURE,
        );
    }

    #[test(should_fail)]
    fn test_verify_digest_wrong_digest() {
        let mut digest = sha256_var(EmailLarge::HEADER.storage(), EmailLarge::HEADER.len());
        digest[0] ^= 1;
        let _ = EmailLarge::PUBKEY.verify_digest_sha256_pkcs1v15(digest, EmailLarge::SIGNATURE);
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

    /// From zkemail/zkemail.nr#67 (Divide-By-0). poseidon_large only hashes the low 17 bits of
    /// redc[17] (17 x 121-bit repacking), so any higher bit set there must be rejected by
    /// validate_in_range, or redc would not be bound by hash()[1].
    #[test(should_fail)]
    fn test_redc_top_limb_bits_outside_hash_are_rejected_2048() {
        let pubkey = EmailLarge::PUBKEY;
        let mut tampered_redc = pubkey.redc;
        tampered_redc[17] = tampered_redc[17] + 131072; // 1 << 17: lowest bit the hash ignores
        let tampered_pubkey = crate::dkim::RSAPubkey::new(pubkey.modulus, tampered_redc);
        let _ = tampered_pubkey.hash();
    }

    /// From zkemail/zkemail.nr#67 (Divide-By-0). Guard: the largest top limb the hash covers
    /// (17 bits) is still accepted. Honest keys use at most 15 bits there (2048-bit modulus,
    /// 2^(2k+6) redc; see js/tests/redc-bound.test.ts).
    #[test]
    fn test_redc_top_limb_17_bits_accepted_2048() {
        let pubkey = EmailLarge::PUBKEY;
        let mut redc = pubkey.redc;
        redc[17] = 131071; // 2^17 - 1
        let _ = crate::dkim::RSAPubkey::new(pubkey.modulus, redc).hash();
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

mod test_fold_limbs {
    use crate::hash::fold_limbs121;

    #[test]
    fn test_fold_even_limb_count() {
        let base = 2.pow_32(121);
        assert_eq(fold_limbs121::<4, 2>([1, 2, 3, 4]), [1 + base * 2, 3 + base * 4]);
    }

    #[test(should_fail_with = "K_out must be ceil(K / 2)")]
    fn test_fold_rejects_dropped_limbs() {
        let _ = fold_limbs121::<5, 2>([1, 2, 3, 4, 5]);
    }
}

mod header_field_access {

    use crate::{
        headers::body_hash::{get_body_hash, get_body_hash_with_max_field_length},
        Sequence,
        tests::test_inputs::EmailLarge,
    };

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
        dkim_field = BoundedVec::from_parts(dkim_field.storage(), EmailLarge::HEADER.len());
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
            dkim_field.set_unchecked(index, malicious_to[i]);
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
        let header: BoundedVec<u8, 203> = BoundedVec::from_array(dkim_field);
        let mut dkim_field_sequence = Sequence { index: 0, length: 203 };
        let body_hash_index = 18;
        let _ = get_body_hash(header, dkim_field_sequence, body_hash_index);
    }

    #[test(should_fail_with = "No ':bh=' or '; bh=' prefix found before body hash")]
    fn test_malicious_body_hash_index() {
        // tests against a z= copy of "From:bh=..." in "dkim-signature: v=1; a=rsa-sha256; d=example.com; s=selector; c=relaxed/relaxed; t=1683849600; h=from:to:subject:date; z=From:bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=@domain.com|To:recipient@example.net|Subject:Hello; bh=2jUSOH9NhtVGCaWpZT2ncBgaamXkef9OgICHkqfsmKY=; b="
        let (header, body_hash_index) = EmailLarge::tampered_dkim_field();
        let sequence: Sequence = Sequence { index: 0, length: header.len() };
        let _ = get_body_hash(header, sequence, body_hash_index);
    }

    #[test(should_fail_with = "No ':bh=' or '; bh=' prefix found before body hash")]
    fn test_body_hash_in_tag_value() {
        // "e:bh=" inside the z= copy of a Date header
        let header: BoundedVec<u8, 127> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; z=Date:bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=; bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 127 }, 30);
    }

    #[test(should_fail_with = "DKIM-Signature field must be the last header field")]
    fn test_body_hash_in_earlier_dkim_field() {
        // a signed, earlier dkim-signature field with a different bh
        let header: BoundedVec<u8, 136> = BoundedVec::from_array(
            comptime {
                "dkim-signature:bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=;\r\ndkim-signature:v=1; bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 63 }, 18);
    }

    #[test(should_fail_with = "Header field too long")]
    fn test_long_dkim_field_default_cap() {
        // a 331-byte field (long h= list) is over the default 300-byte cap
        let header: BoundedVec<u8, 331> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; h=from:to:subject:date:message-id:mime-version:content-type:reply-to:cc:list-unsubscribe:list-unsubscribe-post:x-campaign:x-mailer:feedback-id:in-reply-to:references:sender:list-id:x-original-sender; bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 331 }, 283);
    }

    #[test]
    fn test_long_dkim_field_larger_cap() {
        let header: BoundedVec<u8, 331> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=selector; h=from:to:subject:date:message-id:mime-version:content-type:reply-to:cc:list-unsubscribe:list-unsubscribe-post:x-campaign:x-mailer:feedback-id:in-reply-to:references:sender:list-id:x-original-sender; bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=; b="
                    .as_bytes()
            },
        );
        let body_hash = get_body_hash_with_max_field_length::<331, 512>(
            header,
            Sequence { index: 0, length: 331 },
            283,
        );
        let expected: [u8; 32] = [
            239, 20, 12, 14, 234, 21, 85, 78, 38, 209, 109, 22, 69, 84, 171, 85, 115, 30, 25, 34, 0,
            74, 201, 238, 112, 175, 93, 38, 202, 220, 250, 245,
        ];
        assert_eq(body_hash, expected);
    }

    #[test(should_fail_with = "Header field must end with CRLF")]
    fn test_header_field_sequence_overflow_end() {
        // make sequence extend beyond the end of the header field
        let mut overflowed_sequence = EmailLarge::DKIM_HEADER_SEQUENCE;
        overflowed_sequence.length = overflowed_sequence.length + 1;
        // set header len to be a bit longer so it doesn't overflow
        let mut longer_header = EmailLarge::HEADER;
        longer_header = BoundedVec::from_parts(longer_header.storage(), longer_header.len() + 2);
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
        tampered_header =
            BoundedVec::from_parts(tampered_header.storage(), combined_sequence.length + 4);
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
        shortened_header = BoundedVec::from_parts(
            shortened_header.storage(),
            EmailLarge::DKIM_HEADER_SEQUENCE.index + EmailLarge::DKIM_HEADER_SEQUENCE.length - 1,
        );
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
        headers::email_address::{get_email_address, get_email_address_with_max_field_length},
        Sequence,
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

    #[test(should_fail_with = "Comments and quoted-pairs are not supported in address fields")]
    fn test_address_in_trailing_comment() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 40> = BoundedVec::from_array(
            comptime { "\r\nfrom:<bob@evil.com> (<ceo@bank.com>)\r\n".as_bytes() },
        );
        let _ = get_email_address(
            header,
            Sequence { index: 2, length: 36 },
            Sequence { index: 24, length: 12 },
            from,
        );
    }

    #[test(should_fail_with = "Email address and its closing '>' must end the field")]
    fn test_address_in_quoted_display_name() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 38> = BoundedVec::from_array(
            comptime { "\r\nfrom:\"<ceo@bank.com>\" bob@evil.com\r\n".as_bytes() },
        );
        let _ = get_email_address(
            header,
            Sequence { index: 2, length: 34 },
            Sequence { index: 9, length: 12 },
            from,
        );
    }

    #[test(should_fail_with = "Email address must end the field if no bracket is present")]
    fn test_bare_address_in_quoted_string() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 39> = BoundedVec::from_array(
            comptime { "\r\nfrom:bob@evil.com \"x ceo@bank.com>\"\r\n".as_bytes() },
        );
        let _ = get_email_address(
            header,
            Sequence { index: 2, length: 35 },
            Sequence { index: 23, length: 12 },
            from,
        );
    }

    #[test(should_fail_with = "Comments and quoted-pairs are not supported in address fields")]
    fn test_address_in_unterminated_comment() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 39> = BoundedVec::from_array(
            comptime { "\r\nfrom:<bob@evil.com> (<ceo@bank.com>\r\n".as_bytes() },
        );
        let _ = get_email_address(
            header,
            Sequence { index: 2, length: 35 },
            Sequence { index: 24, length: 12 },
            from,
        );
    }

    #[test(should_fail_with = "Unterminated quoted string")]
    fn test_address_in_unterminated_quote() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 37> = BoundedVec::from_array(
            comptime { "\r\nfrom:bob@evil.com \"<ceo@bank.com>\r\n".as_bytes() },
        );
        let _ = get_email_address(
            header,
            Sequence { index: 2, length: 33 },
            Sequence { index: 22, length: 12 },
            from,
        );
    }

    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_short_field_spanning_next_line() {
        // the CRLF after "a@b" sits in the first bytes of the value
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let header: BoundedVec<u8, 31> = BoundedVec::from_array(
            comptime { "\r\nfrom:a@b\r\nto:<victim@x.com>\r\n".as_bytes() },
        );
        let _ = get_email_address(
            header,
            Sequence { index: 2, length: 27 },
            Sequence { index: 16, length: 12 },
            from,
        );
    }

    #[test(should_fail_with = "Header field too long")]
    fn test_long_field_spanning_next_line() {
        // the CRLF after a 330-byte value is past the scanned range
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let start: [u8; 7] = comptime { "\r\nfrom:".as_bytes() };
        let end: [u8; 26] = comptime { "\r\nsubject:<victim@x.com>\r\n".as_bytes() };
        let mut storage: [u8; 363] = [0x41; 363];
        for i in 0..7 {
            storage[i] = start[i];
        }
        for i in 0..26 {
            storage[337 + i] = end[i];
        }
        let header: BoundedVec<u8, 363> = BoundedVec::from_array(storage);
        let _ = get_email_address(
            header,
            Sequence { index: 2, length: 359 },
            Sequence { index: 348, length: 12 },
            from,
        );
    }

    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_long_field_spanning_next_line_larger_cap() {
        // with a cap that admits the field, the CRLF inside it is found
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let start: [u8; 7] = comptime { "\r\nfrom:".as_bytes() };
        let end: [u8; 26] = comptime { "\r\nsubject:<victim@x.com>\r\n".as_bytes() };
        let mut storage: [u8; 363] = [0x41; 363];
        for i in 0..7 {
            storage[i] = start[i];
        }
        for i in 0..26 {
            storage[337 + i] = end[i];
        }
        let header: BoundedVec<u8, 363> = BoundedVec::from_array(storage);
        let _ = get_email_address_with_max_field_length::<363, 4, 512>(
            header,
            Sequence { index: 2, length: 359 },
            Sequence { index: 348, length: 12 },
            from,
        );
    }

    #[test]
    fn test_long_display_name_larger_cap() {
        // a 355-byte From field (long display name) needs more than the default 325-byte cap
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let mut storage: [u8; 355] = [0x41; 355];
        let start: [u8; 5] = comptime { "from:".as_bytes() };
        let end: [u8; 10] = comptime { " <a@b.com>".as_bytes() };
        for i in 0..5 {
            storage[i] = start[i];
        }
        for i in 0..10 {
            storage[345 + i] = end[i];
        }
        let header: BoundedVec<u8, 355> = BoundedVec::from_array(storage);
        let field = Sequence { index: 0, length: 355 };
        let address_sequence = Sequence { index: 347, length: 7 };
        let address = get_email_address_with_max_field_length::<355, 4, 512>(
            header,
            field,
            address_sequence,
            from,
        );
        assert_eq(address.len(), 7);
        let expected: [u8; 7] = comptime { "a@b.com".as_bytes() };
        for i in 0..7 {
            assert_eq(address.get(i), expected[i]);
        }
    }

    #[test(should_fail_with = "Header field too long")]
    fn test_long_display_name_default_cap() {
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let mut storage: [u8; 355] = [0x41; 355];
        let start: [u8; 5] = comptime { "from:".as_bytes() };
        let end: [u8; 10] = comptime { " <a@b.com>".as_bytes() };
        for i in 0..5 {
            storage[i] = start[i];
        }
        for i in 0..10 {
            storage[345 + i] = end[i];
        }
        let header: BoundedVec<u8, 355> = BoundedVec::from_array(storage);
        let _ = get_email_address(
            header,
            Sequence { index: 0, length: 355 },
            Sequence { index: 347, length: 7 },
            from,
        );
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

mod test_masking {
    use crate::masking::mask_text;

    #[test]
    fn test_mask_ignores_inactive_bytes() {
        // storage past len() is prover-chosen and unsigned
        let text: BoundedVec<u8, 4> = BoundedVec::from_parts([65, 66, 90, 91], 2);
        assert_eq(mask_text(text, [false, true, true, true]), [0, 66, 0, 0]);
    }

    // from zkemail/zkemail.nr#67 (Divide-By-0): bytes past len are unconstrained padding and
    // must never be output, even if the mask selects them
    #[test]
    fn test_mask_text_zeroes_bytes_past_len() {
        let text: BoundedVec<u8, 8> =
            BoundedVec::from_parts([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68], 4);
        let masked = mask_text(text, [true; 8]);
        assert(masked == [0x61, 0x62, 0x63, 0x64, 0, 0, 0, 0]);
    }

    // from zkemail/zkemail.nr#67 (Divide-By-0)
    #[test]
    fn test_mask_text_applies_mask_within_len() {
        let text: BoundedVec<u8, 8> =
            BoundedVec::from_parts([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68], 4);
        let masked = mask_text(text, [true, false, true, false, true, true, true, true]);
        assert(masked == [0x61, 0, 0x63, 0, 0, 0, 0, 0]);
    }
}
