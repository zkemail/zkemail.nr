mod test_inputs;

mod test_success {

    use crate::{
        headers::body_hash::get_body_hash, tests::test_inputs::EmailLarge,
        partial_hash::partial_sha256_var_end
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
            EmailLarge::BODY_HASH_INDEX
        );
        // compute the body hash
        let computed_body_hash: [u8; 32] = sha256_var(EmailLarge::BODY.storage, EmailLarge::BODY.len() as u64);
        // compare the body hashes
        assert(
            signed_body_hash == computed_body_hash, "SHA256 hash computed over body does not match body hash found in DKIM-signed header"
        );
    }

    #[test]
    fn test_partial_hash() {
        // get the body hash from the header
        let signed_body_hash = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX
        );
        // finish the partial hash
        let computed_body_hash = partial_sha256_var_end(
            EmailLarge::PARTIAL_BODY_HASH,
            EmailLarge::PARTIAL_BODY.storage,
            EmailLarge::PARTIAL_BODY.len() as u64,
            EmailLarge::PARTIAL_BODY_REAL_LENGTH as u64
        );
        // compare the body hashes
        assert(
            signed_body_hash == computed_body_hash, "Sha256 hash computed over body does not match DKIM-signed header"
        );
    }
}

mod test_tampered_hash {
    use crate::{headers::body_hash::get_body_hash, tests::test_inputs::EmailLarge};
    use std::hash::sha256_var;

    // no reasonable message to constrain here
    #[test(should_fail)]
    fn test_tampered_header() {
        // get tampered header
        let mut tampered_header = EmailLarge::tampered_header();
        // attempt to verify the DKIM signature
        EmailLarge::PUBKEY.verify_dkim_signature(tampered_header, EmailLarge::SIGNATURE);
    }

    #[test]
    fn test_tampered_body() {
        // get the body hash from the header
        let signed_body_hash = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX
        );
        // get tampered body
        let mut tampered_body = EmailLarge::tampered_body();
        // compute the body hash
        let tampered_body_hash: [u8; 32] = sha256_var(tampered_body.storage, tampered_body.len() as u64);
        // compare the body hashes
        assert(signed_body_hash != tampered_body_hash, "SHA256 hash should not match tampered body hash");
    }
}

mod header_field_access {

    use crate::{headers::body_hash::get_body_hash, Sequence, tests::test_inputs::EmailLarge};

    #[test(should_fail_with = "No 'bh=' prefix found at asserted bh index")]
    fn test_bad_body_hash_off_one_minus() {
        // attempt to get body hash with one off index
        let _ = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX - 1
        );
    }

    #[test(should_fail_with = "No 'bh=' prefix found at asserted bh index")]
    fn test_bad_body_hash_off_one_plus() {
        // attempt to get body hash with one off index
        let _ = get_body_hash(
            EmailLarge::HEADER,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX + 1
        );
    }

    #[test(should_fail_with = "Header field name does not match")]
    fn test_bad_body_hash_not_in_dkim_field() {
        // create header field for malicious bh
        let mut dkim_field: BoundedVec<u8, EmailLarge::EMAIL_LARGE_MAX_HEADER_LENGTH> = BoundedVec::new();
        dkim_field.len = EmailLarge::HEADER.len();
        // craft a malicious "to" field where attacker tries to put bh in display name
        let mut malicious_to: [u8; 78] = comptime {
            "\r\nto:\"bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\" <zkewtest@gmail.com>\r\n".as_bytes()
        };
        let mut malicious_sequence = Sequence {
            index: 8, // 8 to make it check for crlf on both sides (could be anything > 2)
            length: malicious_to.len() - 4 // 4 is the crlf on each end
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
            EmailLarge::BODY_HASH_INDEX
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
            EmailLarge::BODY_HASH_INDEX
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
            EmailLarge::BODY_HASH_INDEX
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
            EmailLarge::BODY_HASH_INDEX
        );
    }

    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_header_field_multiple_fields() {
        // combine to and dkim-signature fields together
        let mut tampered_header: BoundedVec<u8, EmailLarge::EMAIL_LARGE_MAX_HEADER_LENGTH> = BoundedVec::new();
        let combined_sequence = Sequence {
            index: 2,
            length: EmailLarge::TO_HEADER_SEQUENCE.length + EmailLarge::DKIM_HEADER_SEQUENCE.length + 2 // 2 for crlf in middle
        };
        tampered_header.len = combined_sequence.length + 4;
        // copy dkim-signature field
        for i in 0..EmailLarge::DKIM_HEADER_SEQUENCE.length + 2 {
            tampered_header.storage[i] = EmailLarge::HEADER.storage[EmailLarge::DKIM_HEADER_SEQUENCE.index + i - 2];
        }
        tampered_header.storage[EmailLarge::DKIM_HEADER_SEQUENCE.length + 2] = "\r".as_bytes()[0];
        tampered_header.storage[EmailLarge::DKIM_HEADER_SEQUENCE.length + 3] = "\n".as_bytes()[0];
        // copy to field
        for i in 0..EmailLarge::TO_HEADER_SEQUENCE.length + 2 {
            let index = EmailLarge::DKIM_HEADER_SEQUENCE.length + 4;
            tampered_header.storage[index + i] = EmailLarge::HEADER.storage[EmailLarge::TO_HEADER_SEQUENCE.index + i];
        }
        // set crlf at end
        tampered_header.storage[combined_sequence.length + 2] = "\r".as_bytes()[0];
        tampered_header.storage[combined_sequence.length + 3] = "\n".as_bytes()[0];
        let tampered_body_hash_index = 93; // just manually setting this
        // attempt to get body hash
        let _ = get_body_hash(
            tampered_header,
            combined_sequence,
            tampered_body_hash_index
        );
    }

    #[test(should_fail_with = "Header field out of bounds")]
    fn test_header_field_outside_header() {
        let mut shortened_header = EmailLarge::HEADER;
        // shorten header to be just under the end of the dkim field
        shortened_header.len = EmailLarge::DKIM_HEADER_SEQUENCE.index + EmailLarge::DKIM_HEADER_SEQUENCE.length - 1;
        // attempt to get body hash
        let _ = get_body_hash(
            shortened_header,
            EmailLarge::DKIM_HEADER_SEQUENCE,
            EmailLarge::BODY_HASH_INDEX
        );
    }
}
