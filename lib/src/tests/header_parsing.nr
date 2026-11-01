// Header-parsing tests adapted from zkemail/zkemail.nr#67 (Divide-By-0): DKIM body-hash tag
// binding, header-field names, lengths and folds, and address boundaries. Adaptations: the
// field caps include "<name>:", folded (c=simple) fields use the *_with_folds functions, and
// BoundedVec::from_parts replaces from_parts_unchecked.

mod test_header_field_canonicalization {
    use crate::{
        headers::{
            body_hash::{get_body_hash, get_body_hash_with_max_field_length},
            constrain_header_field,
        },
        Sequence,
    };

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

    // the cap includes "<name>:", so 9 bytes here (#67: 4 value bytes)
    #[test]
    fn test_field_at_max_length_accepted() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "from:abcd".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        constrain_header_field::<64, 9, 4>(header, Sequence { index: 0, length: 9 }, from);
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

    // The DKIM-Signature field is bounded too (MAX_DKIM_HEADER_FIELD_LENGTH = 300, name included).
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

    // Long real-world DKIM-Signature fields (> the default 300-byte cap) are accepted with a larger
    // cap. #67 raises the default to 1024 value bytes; here the caller chooses it (name included).
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
        let body_hash = get_body_hash_with_max_field_length::<900, 1039>(
            header,
            Sequence { index: 0, length: 900 },
            23,
        );
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

mod test_header_field_boundaries {
    use crate::{
        headers::{
            body_hash::get_body_hash, constrain_header_field,
            constrain_header_field_detect_last_angle_bracket,
        },
        Sequence,
    };

    // A folded field (c=simple) must not be cut at the fold.
    #[test(should_fail_with = "Header field must not end inside a fold")]
    fn test_field_cut_at_fold_rejected() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "from:a@b.cd\r\n x\r\nto:c@d.ef".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        constrain_header_field::<64, 32, 4>(header, Sequence { index: 0, length: 11 }, from);
    }

    // Same on the address-extraction path.
    #[test(should_fail_with = "Header field must not end inside a fold")]
    fn test_address_field_cut_at_fold_rejected() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "from:a@b.cd\r\n\tx\r\nto:c@d.ef".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let _ = constrain_header_field_detect_last_angle_bracket::<64, 32, 4>(
            header,
            Sequence { index: 0, length: 11 },
            from,
        );
    }

    #[test(should_fail_with = "Invalid header field name")]
    fn test_name_with_colon_rejected() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "subject:foo:bar\r\nto:c@d.ef".as_bytes() });
        let name: [u8; 11] = comptime { "subject:foo".as_bytes() };
        constrain_header_field::<64, 32, 11>(header, Sequence { index: 0, length: 15 }, name);
    }

    // The "<name>:" must lie inside the sequence (here it would lie in the padding past len).
    #[test(should_fail_with = "Header field too short to contain name and colon")]
    fn test_field_shorter_than_name_rejected() {
        let storage: [u8; 16] = comptime { "\r\nfrom:a@b.cd   ".as_bytes() };
        let header: BoundedVec<u8, 16> = BoundedVec::from_parts(storage, 4);
        let from: [u8; 4] = comptime { "from".as_bytes() };
        constrain_header_field::<16, 32, 4>(header, Sequence { index: 2, length: 2 }, from);
    }

    // bh= must come from the DKIM-Signature being verified, which is the last field.
    #[test(should_fail_with = "DKIM-Signature field must be the last header field")]
    fn test_body_hash_from_earlier_dkim_signature_rejected() {
        let header: BoundedVec<u8, 128> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=\r\nfrom:a@b.cd"
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 71 }, 23);
    }
}

mod test_address_early_value_boundaries {
    use crate::{
        headers::{
            constrain_header_field_detect_last_angle_bracket, email_address::get_email_address,
        },
        Sequence,
    };

    #[test(should_fail_with = "Email address must start immediately after '<' if bracket is present")]
    fn test_early_angle_bracket_cannot_select_later_address() {
        let header: BoundedVec<u8, 64> =
            BoundedVec::from_array(comptime { "from:<real@a.bc> fake@b.cd".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let _ = get_email_address(
            header,
            Sequence { index: 0, length: 26 },
            Sequence { index: 17, length: 9 },
            from,
        );
    }

    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_early_bare_cr_in_address_field_rejected() {
        let header: BoundedVec<u8, 32> =
            BoundedVec::from_array(comptime { "from:a\rX@b.cd".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let _ = constrain_header_field_detect_last_angle_bracket::<32, 32, 4>(
            header,
            Sequence { index: 0, length: 13 },
            from,
        );
    }

    #[test(should_fail_with = "Email address must contain '@'")]
    fn test_address_without_at_rejected() {
        let header: BoundedVec<u8, 32> =
            BoundedVec::from_array(comptime { "from:fake".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let _ = get_email_address(
            header,
            Sequence { index: 0, length: 9 },
            Sequence { index: 5, length: 4 },
            from,
        );
    }

    #[test(should_fail_with = "Email address must contain '@' exactly once")]
    fn test_address_with_two_at_signs_rejected() {
        let header: BoundedVec<u8, 32> =
            BoundedVec::from_array(comptime { "from:a@@b.cd".as_bytes() });
        let from: [u8; 4] = comptime { "from".as_bytes() };
        let _ = get_email_address(
            header,
            Sequence { index: 0, length: 12 },
            Sequence { index: 5, length: 7 },
            from,
        );
    }
}

mod test_body_hash_authenticated_length {
    use crate::{headers::body_hash::get_body_hash, Sequence};

    // The semicolon terminator is outside header.len() but inside storage. It cannot authorize bh=.
    #[test(should_fail_with = "Body hash index accessed outside of DKIM header field")]
    fn test_suffix_in_unauthed_storage_tail_rejected() {
        let storage: [u8; 64] = comptime {
            "dkim-signature:bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;X".as_bytes()
        };
        let header: BoundedVec<u8, 64> = BoundedVec::from_parts(storage, 62);
        let _ = get_body_hash(header, Sequence { index: 0, length: 62 }, 18);
    }

    #[test(should_fail)]
    fn test_zero_body_hash_index_rejected() {
        let header: BoundedVec<u8, 80> = BoundedVec::from_array(
            comptime {
                "dkim-signature:bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=".as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 66 }, 0);
    }

    #[test(should_fail)]
    fn test_overflow_body_hash_index_rejected() {
        let header: BoundedVec<u8, 80> = BoundedVec::from_array(
            comptime {
                "dkim-signature:bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=".as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 66 }, 4294967295);
    }

    #[test]
    fn test_suffix_inside_field_accepted() {
        let header: BoundedVec<u8, 80> = BoundedVec::from_array(
            comptime {
                "dkim-signature:bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=".as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 66 }, 18);
    }
}

mod test_cross_header_bh_matrix {
    use crate::{headers::body_hash::get_body_hash, Sequence};

    #[test(should_fail_with = "Body hash index accessed outside of DKIM header field")]
    fn test_content_type_no_space_semicolon_rejected() {
        let header: BoundedVec<u8, 180> = BoundedVec::from_array(
            comptime {
                "content-type:text/plain;bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 74, length: 71 }, 27);
    }

    #[test(should_fail_with = "Body hash index accessed outside of DKIM header field")]
    fn test_list_unsubscribe_no_space_semicolon_rejected() {
        let header: BoundedVec<u8, 180> = BoundedVec::from_array(
            comptime {
                "list-unsubscribe:<https://example.test/u>;bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 92, length: 71 }, 45);
    }

    #[test(should_fail_with = "Body hash index accessed outside of DKIM header field")]
    fn test_subject_tab_fold_semicolon_rejected() {
        let header: BoundedVec<u8, 180> = BoundedVec::from_array(
            comptime {
                "Subject: x;\r\n\tbh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 64, length: 71 }, 17);
    }
}

mod test_body_hash_injection {
    use crate::{headers::body_hash::get_body_hash, Sequence};

    // sha256("") = e3b0c442...b855, base64 "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    global EMPTY_BODY_HASH: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    // A ';bh=' in Subject is outside the DKIM-Signature field.
    #[test(should_fail_with = "Body hash index accessed outside of DKIM header field")]
    fn test_subject_semicolon_bh_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "subject:hi;bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 61, length: 71 }, 14);
    }

    // Claiming the Subject line is the DKIM-Signature field fails the name check.
    #[test(should_fail_with = "Header field name does not match")]
    fn test_subject_claimed_as_dkim_field_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "subject:hi;bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 59 }, 14);
    }

    // A 'dkim-signature:' written inside the Subject value does not start a line.
    #[test(should_fail_with = "Header field must start with CRLF")]
    fn test_dkim_name_inside_subject_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "subject:x;dkim-signature:bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 10, length: 63 }, 28);
    }

    // c=simple: a folded Subject continuation starts with WSP, so it can't be named dkim-signature.
    #[test(should_fail_with = "Header field name does not match")]
    fn test_dkim_name_in_folded_subject_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "Subject: x;\r\n dkim-signature:bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;\r\nDKIM-Signature: v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 13, length: 64 }, 32);
    }

    // Content-Type also carries '; '-separated parameters; the DKIM field can't be stretched over it.
    #[test(should_fail_with = "Header field must not contain newlines")]
    fn test_dkim_field_extended_into_content_type_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=\r\ncontent-type:text/plain; bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;"
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 146 }, 101);
    }

    // Signature-like fields with other names (X-Google-DKIM-Signature, ARC-Message-Signature) are not DKIM-Signature.
    #[test(should_fail_with = "Header field must start with CRLF")]
    fn test_x_google_dkim_signature_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "x-google-dkim-signature:v=1; bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; b=\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 9, length: 71 }, 32);
    }

    #[test(should_fail_with = "Header field name does not match")]
    fn test_arc_message_signature_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "arc-message-signature:i=1; bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; b=\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 78 }, 30);
    }

    // z= copies sender-controlled header fields into the DKIM-Signature, '=' escaped as =3D. A copied
    // field whose name ends in 'e' (Date, Content-Type) produces 'e:bh=', which used to pass as the
    // 'dkim-signature:bh=' first-tag prefix. (The literal trailing '=' here would be escaped by a real
    // signer, so this pins the prefix rule rather than reproducing an end-to-end exploit.)
    #[test(should_fail_with = "No ':bh=' or '; bh=' prefix found before body hash")]
    fn test_z_tag_copied_date_bh_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; z=Date:bh=3DsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 127 }, 30);
    }

    // The real bh= is still found when z= is present.
    #[test]
    fn test_body_hash_with_z_tag_accepted() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; z=Date:bh=3DsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let body_hash = get_body_hash(header, Sequence { index: 0, length: 127 }, 79);
        assert(body_hash == EMPTY_BODY_HASH);
    }

    // c=simple keeps an all-caps name; bh= as the first tag is still found.
    #[test]
    fn test_body_hash_first_tag_uppercase_name_accepted() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "DKIM-SIGNATURE:bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=".as_bytes()
            },
        );
        let body_hash = get_body_hash(header, Sequence { index: 0, length: 66 }, 18);
        assert(body_hash == EMPTY_BODY_HASH);
    }

    // The old check OR-ed "e:bh=" and ": bh=" byte by byte, so mixes like "::bh=" and "e bh="
    // also passed, anywhere in the field. Each form is now matched whole, at its anchored position.
    #[test(should_fail_with = "No ':bh=' or '; bh=' prefix found before body hash")]
    fn test_body_hash_first_tag_off_anchor_rejected() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "dkim-signature::bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=".as_bytes()
            },
        );
        let _ = get_body_hash(header, Sequence { index: 0, length: 67 }, 19);
    }

    // Two DKIM-Signature fields in the signed header still work: bh= comes from the last one.
    #[test]
    fn test_last_dkim_signature_accepted() {
        let header: BoundedVec<u8, 160> = BoundedVec::from_array(
            comptime {
                "dkim-signature:v=1; bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=; b=\r\nsubject:hi\r\ndkim-signature:v=1; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
                    .as_bytes()
            },
        );
        let body_hash = get_body_hash(header, Sequence { index: 85, length: 71 }, 108);
        assert(body_hash == EMPTY_BODY_HASH);
    }
}
