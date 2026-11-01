pub(crate) mod EmailLarge {

    use crate::{dkim::RSAPubkey, KEY_LIMBS_2048, Sequence};

    // regular inputs
    pub(crate) global EMAIL_LARGE_MAX_HEADER_LENGTH: u32 = 512;
    pub(crate) global EMAIL_LARGE_MAX_BODY_LENGTH: u32 = 1024;
    pub(crate) global HEADER: BoundedVec<u8, EMAIL_LARGE_MAX_HEADER_LENGTH> = BoundedVec::from([
        102, 114, 111, 109, 58, 114, 117, 110, 110, 105, 101, 114, 46, 108, 101, 97, 103, 117, 101,
        115, 46, 48, 106, 64, 105, 99, 108, 111, 117, 100, 46, 99, 111, 109, 13, 10, 99, 111, 110,
        116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 116, 101, 120, 116, 47, 112, 108, 97, 105,
        110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 109, 105,
        109, 101, 45, 118, 101, 114, 115, 105, 111, 110, 58, 49, 46, 48, 32, 40, 77, 97, 99, 32, 79,
        83, 32, 88, 32, 77, 97, 105, 108, 32, 49, 54, 46, 48, 32, 92, 40, 51, 55, 51, 49, 46, 53,
        48, 48, 46, 50, 51, 49, 92, 41, 41, 13, 10, 115, 117, 98, 106, 101, 99, 116, 58, 66, 105,
        116, 99, 111, 105, 110, 13, 10, 109, 101, 115, 115, 97, 103, 101, 45, 105, 100, 58, 60, 49,
        50, 56, 48, 48, 65, 57, 48, 45, 52, 69, 67, 67, 45, 52, 53, 49, 51, 45, 57, 50, 57, 56, 45,
        65, 51, 51, 53, 52, 54, 49, 50, 50, 57, 50, 48, 64, 109, 101, 46, 99, 111, 109, 62, 13, 10,
        100, 97, 116, 101, 58, 87, 101, 100, 44, 32, 51, 32, 65, 112, 114, 32, 50, 48, 50, 52, 32,
        49, 54, 58, 50, 51, 58, 52, 56, 32, 43, 48, 53, 51, 48, 13, 10, 116, 111, 58, 122, 107, 101,
        119, 116, 101, 115, 116, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109, 13, 10, 100, 107,
        105, 109, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 58, 118, 61, 49, 59, 32, 97, 61,
        114, 115, 97, 45, 115, 104, 97, 50, 53, 54, 59, 32, 99, 61, 114, 101, 108, 97, 120, 101,
        100, 47, 114, 101, 108, 97, 120, 101, 100, 59, 32, 100, 61, 105, 99, 108, 111, 117, 100, 46,
        99, 111, 109, 59, 32, 115, 61, 49, 97, 49, 104, 97, 105, 59, 32, 116, 61, 49, 55, 49, 50,
        49, 52, 49, 54, 52, 52, 59, 32, 98, 104, 61, 50, 74, 115, 100, 75, 52, 66, 77, 122, 122,
        116, 57, 119, 52, 90, 108, 122, 50, 84, 100, 121, 86, 67, 70, 99, 43, 108, 55, 118, 78, 121,
        84, 53, 97, 65, 103, 71, 68, 89, 102, 55, 102, 77, 61, 59, 32, 104, 61, 102, 114, 111, 109,
        58, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 77, 105, 109, 101, 45, 86,
        101, 114, 115, 105, 111, 110, 58, 83, 117, 98, 106, 101, 99, 116, 58, 77, 101, 115, 115, 97,
        103, 101, 45, 73, 100, 58, 68, 97, 116, 101, 58, 116, 111, 59, 32, 98, 61,
    ]);
    pub(crate) global BODY: BoundedVec<u8, EMAIL_LARGE_MAX_BODY_LENGTH> = BoundedVec::from([
        84, 104, 101, 32, 84, 105, 109, 101, 115, 32, 48, 51, 47, 74, 97, 110, 47, 50, 48, 48, 57,
        32, 67, 104, 97, 110, 99, 101, 108, 108, 111, 114, 32, 111, 110, 32, 98, 114, 105, 110, 107,
        32, 111, 102, 32, 115, 101, 99, 111, 110, 100, 32, 98, 97, 105, 108, 111, 117, 116, 32, 102,
        111, 114, 32, 98, 97, 110, 107, 115, 13, 10, 13, 10, 49, 53, 32, 121, 101, 97, 114, 115, 32,
        97, 103, 111, 44, 32, 83, 97, 116, 111, 115, 104, 105, 32, 109, 105, 110, 101, 100, 32, 116,
        104, 101, 32, 102, 105, 114, 115, 116, 32, 98, 108, 111, 99, 107, 32, 111, 102, 32, 116,
        104, 101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 98, 108, 111, 99, 107, 99, 104, 97, 105,
        110, 32, 61, 13, 10, 65, 102, 116, 101, 114, 32, 116, 104, 101, 32, 66, 105, 116, 99, 111,
        105, 110, 32, 119, 104, 105, 116, 101, 32, 112, 97, 112, 101, 114, 32, 97, 112, 112, 101,
        97, 114, 101, 100, 32, 111, 110, 32, 79, 99, 116, 111, 98, 101, 114, 32, 51, 49, 44, 32, 50,
        48, 48, 56, 44, 32, 111, 110, 32, 97, 32, 61, 13, 10, 99, 114, 121, 112, 116, 111, 103, 114,
        97, 112, 104, 121, 32, 109, 97, 105, 108, 105, 110, 103, 32, 108, 105, 115, 116, 44, 32,
        116, 104, 101, 32, 71, 101, 110, 101, 115, 105, 115, 32, 66, 108, 111, 99, 107, 32, 61, 69,
        50, 61, 56, 48, 61, 57, 52, 32, 116, 104, 101, 32, 102, 105, 114, 115, 116, 32, 98, 105,
        116, 99, 111, 105, 110, 32, 61, 13, 10, 98, 108, 111, 99, 107, 32, 97, 110, 100, 32, 116,
        104, 101, 32, 98, 97, 115, 105, 115, 32, 111, 102, 32, 116, 104, 101, 32, 101, 110, 116,
        105, 114, 101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 116, 114, 97, 100, 105, 110, 103,
        32, 115, 121, 115, 116, 101, 109, 32, 105, 110, 32, 112, 108, 97, 99, 101, 32, 116, 111, 32,
        61, 13, 10, 116, 104, 105, 115, 32, 100, 97, 121, 32, 61, 69, 50, 61, 56, 48, 61, 57, 52,
        32, 119, 97, 115, 32, 109, 105, 110, 101, 100, 32, 111, 110, 32, 74, 97, 110, 117, 97, 114,
        121, 32, 51, 44, 32, 50, 48, 48, 57, 46, 61, 50, 48, 13, 10, 13, 10, 84, 104, 101, 32, 71,
        101, 110, 101, 115, 105, 115, 32, 66, 108, 111, 99, 107, 32, 105, 115, 32, 97, 108, 115,
        111, 32, 107, 110, 111, 119, 110, 32, 97, 115, 32, 66, 108, 111, 99, 107, 32, 48, 32, 111,
        114, 32, 66, 108, 111, 99, 107, 32, 49, 44, 32, 97, 110, 100, 32, 105, 115, 32, 115, 116,
        105, 108, 108, 32, 105, 110, 32, 61, 13, 10, 116, 104, 101, 32, 66, 105, 116, 99, 111, 105,
        110, 32, 110, 101, 116, 119, 111, 114, 107, 44, 32, 119, 104, 101, 114, 101, 32, 105, 116,
        32, 119, 105, 108, 108, 32, 114, 101, 109, 97, 105, 110, 32, 97, 115, 32, 108, 111, 110,
        103, 32, 97, 115, 32, 116, 104, 101, 114, 101, 32, 105, 115, 32, 97, 32, 99, 111, 109, 112,
        117, 116, 101, 114, 32, 61, 13, 10, 114, 117, 110, 110, 105, 110, 103, 32, 116, 104, 101,
        32, 66, 105, 116, 99, 111, 105, 110, 32, 115, 111, 102, 116, 119, 97, 114, 101, 46, 61, 50,
        48, 13, 10, 13, 10, 65, 108, 108, 32, 110, 111, 100, 101, 115, 32, 105, 110, 32, 116, 104,
        101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 110, 101, 116, 119, 111, 114, 107, 32, 99, 97,
        110, 32, 99, 111, 110, 115, 117, 108, 116, 32, 105, 116, 44, 32, 101, 118, 101, 110, 32,
        105, 102, 32, 105, 116, 32, 105, 115, 32, 97, 116, 32, 116, 104, 101, 32, 61, 13, 10, 111,
        116, 104, 101, 114, 32, 101, 110, 100, 32, 111, 102, 32, 116, 104, 101, 32, 110, 101, 116,
        119, 111, 114, 107, 32, 119, 105, 116, 104, 32, 104, 117, 110, 100, 114, 101, 100, 115, 32,
        111, 102, 32, 116, 104, 111, 117, 115, 97, 110, 100, 115, 32, 111, 102, 32, 98, 108, 111,
        99, 107, 115, 46, 13, 10,
    ]);

    // redc = floor(2^(2 * 2048 + 6) / modulus), as BigNum v0.11 expects
    pub(crate) global PUBKEY: RSAPubkey<KEY_LIMBS_2048> = RSAPubkey::new(
        [
            0xe5cf995b5ef59ce9943d1f4209b6ab,
            0xe0caf03235e91a2db27e9ed214bcc6,
            0xafe1309f87414bd36ed296dacfade2,
            0xbeff3f19046a43adce46c932514988,
            0x324041af8736e87de4358860fff057,
            0xadcc6669dfa346f322717851a8c22a,
            0x8b2a193089e6bf951c553b5a6f71aa,
            0x0a570fe582918c4f731a0002068df2,
            0x39419a433d6bfdd1978356cbca4b60,
            0x550d695a514d38b45c862320a00ea5,
            0x1c56ac1dfbf1beea31e8a613c2a51f,
            0x6a30c9f22d2e5cb6934263d0838809,
            0x0a281f268a44b21a4f77a91a52f960,
            0x5134dc3966c8e91402669a47cc8597,
            0x71590781df114ec072e641cdc5d224,
            0xa1bc0f0937489c806c1944fd029dc9,
            0x911f6e47f84db3b64c3648ebb5a127,
            0xd5,
        ],
        [
            0x22a09393af1f83c4167cfb3e95f118,
            0x7076c8fcf1f51eb5f9f5f3f6946269,
            0x6edaeef63eb3c047c08bea4146bb01,
            0x3ea933bd1d2fb58e4d8ba9c7de885e,
            0x40ea942ddf892c0c21069f41856049,
            0xefd398a01786182a41303d9a97eb45,
            0x2f492dc910b4b3991f75f42910da16,
            0xd2a20e69118305a7739c4e3bf6bbd7,
            0xc1b8278c646e656c2396d1460bd941,
            0x7eb52a27e0da7f8439752db8526843,
            0x1de2c5660b447afdff88ed3857c414,
            0x27fce9159c1dd44311d392b02886b7,
            0xdf9a7976eddc59edcc1979316b5aa8,
            0x3d1dd388b9ff8e8e190861bdeb9d2c,
            0xb9cad7ad3204e8ecde66020eaae07b,
            0x239c142aa2afb739691705a614dd85,
            0x4ca1794ecc8ac887def3d3e3e2b629,
            0x4cb7,
        ],
    );
    pub(crate) global SIGNATURE: [Field; KEY_LIMBS_2048] = [
        0xf193c3300b7c9902e32861c38d0d2d,
        0x9f6927fdb3df0b84092d8459654327,
        0x8a0bea5e2fa82821e49c27b68d5a7b,
        0xaa8c0acc1190f9fd845ef64f8e7ae9,
        0xa7aeebb37f4395965543e6df69a5a7,
        0x087ecef9921569cfba83331ca11c6b,
        0x4589ed316ed20757e65ad221736011,
        0x0835d8748f11dcc985700c3fea27b1,
        0xe870d2493fb83b4a1d72350e5de926,
        0x268b28eda0aac07625cfab32b60af1,
        0xb41a164eae7ba1602eaec5b5a39fe6,
        0x693cc5ec578422bee48eabe390fc37,
        0xa29504dd504f14423f2ce65b2ac388,
        0x6c3ac6310c084a0b126fcd5225c208,
        0xab0903e48563e5f4a5365ac5cbd888,
        0xf05bf2e5b6266c0ac88dfc733c414f,
        0xf58f9e9669e0f4f3086cce1187fd44,
        0xb9,
    ];
    pub(crate) global BODY_HASH_INDEX: u32 = 361;
    pub(crate) global DKIM_HEADER_SEQUENCE: Sequence = Sequence { index: 267, length: 203 };
    // partial hash inputs
    pub(crate) global EMAIL_LARGE_MAX_PARTIAL_BODY_LENGTH: u32 = 192;
    pub(crate) global PARTIAL_BODY_HASH: [u32; 8] = [
        616616639, 1838516336, 2875062989, 1377577374, 300896023, 2753786313, 2559427666, 979052520,
    ];
    pub(crate) global PARTIAL_BODY_REAL_LENGTH: u32 = BODY.len();
    pub(crate) global PARTIAL_BODY: BoundedVec<u8, EMAIL_LARGE_MAX_PARTIAL_BODY_LENGTH> = BoundedVec::from(
        [
            104, 101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 115, 111, 102, 116, 119, 97, 114,
            101, 46, 61, 50, 48, 13, 10, 13, 10, 65, 108, 108, 32, 110, 111, 100, 101, 115, 32, 105,
            110, 32, 116, 104, 101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 110, 101, 116, 119,
            111, 114, 107, 32, 99, 97, 110, 32, 99, 111, 110, 115, 117, 108, 116, 32, 105, 116, 44,
            32, 101, 118, 101, 110, 32, 105, 102, 32, 105, 116, 32, 105, 115, 32, 97, 116, 32, 116,
            104, 101, 32, 61, 13, 10, 111, 116, 104, 101, 114, 32, 101, 110, 100, 32, 111, 102, 32,
            116, 104, 101, 32, 110, 101, 116, 119, 111, 114, 107, 32, 119, 105, 116, 104, 32, 104,
            117, 110, 100, 114, 101, 100, 115, 32, 111, 102, 32, 116, 104, 111, 117, 115, 97, 110,
            100, 115, 32, 111, 102, 32, 98, 108, 111, 99, 107, 115, 46, 13, 10,
        ],
    );
    // email address inputs
    pub(crate) global FROM_HEADER_SEQUENCE: Sequence = Sequence { index: 0, length: 34 };
    pub(crate) global FROM_ADDRESS_SEQUENCE: Sequence = Sequence { index: 5, length: 29 };
    pub(crate) global TO_HEADER_SEQUENCE: Sequence = Sequence { index: 244, length: 21 };
    pub(crate) global TO_ADDRESS_SEQUENCE: Sequence = Sequence { index: 247, length: 18 };

    // mutate inputs

    pub fn tampered_header() -> BoundedVec<u8, EMAIL_LARGE_MAX_HEADER_LENGTH> {
        let mut header = HEADER;
        header.set(140, header.get_unchecked(140) + 1);
        header
    }

    pub fn tampered_body() -> BoundedVec<u8, EMAIL_LARGE_MAX_BODY_LENGTH> {
        let mut body = BODY;
        body.set(140, body.get_unchecked(140) + 1);
        body
    }

    pub fn body_hash_outside_sequence() -> u32 {
        let dkim_sequence_start = DKIM_HEADER_SEQUENCE.index;
        dkim_sequence_start - 40
    }

    pub fn tampered_dkim_field() -> (BoundedVec<u8, 276>, u32) {
        let header: BoundedVec<u8, 276> = BoundedVec::from_array(
            comptime {
                "dkim-signature: v=1; a=rsa-sha256; d=example.com; s=selector; c=relaxed/relaxed; t=1683849600; h=from:to:subject:date; z=From:bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=@domain.com|To:recipient@example.net|Subject:Hello; bh=2jUSOH9NhtVGCaWpZT2ncBgaamXkef9OgICHkqfsmKY=; b="
                    .as_bytes()
            },
        );
        let body_hash_index: u32 = 129;
        (header, body_hash_index)
    }
}

pub(crate) mod EmailAddresses {

    use crate::{MAX_EMAIL_ADDRESS_LENGTH, Sequence};
    pub(crate) global ADDRESS: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> =
        BoundedVec::from_array("runnier.leagues.0j@icloud.com".as_bytes());
    pub(crate) global ADDRESS_ONLY: [u8; 38] =
        comptime { "\r\nfrom:runnier.leagues.0j@icloud.com\r\n".as_bytes() };
    pub(crate) global NO_BRACKETS: [u8; 51] =
        comptime { "\r\nfrom:ZKEmail Team runnier.leagues.0j@icloud.com\r\n".as_bytes() };
    pub(crate) global BRACKETS: [u8; 53] =
        comptime { "\r\nfrom:ZKEmail Team <runnier.leagues.0j@icloud.com>\r\n".as_bytes() };
    pub(crate) global QUOTES: [u8; 67] = comptime {
        "\r\nfrom:\"president@whitehouse.gov\" <runnier.leagues.0j@icloud.com>\r\n".as_bytes()
    };
    pub(crate) global ADDRESS_ONLY_FIELD_SEQUENCE: Sequence = Sequence { index: 2, length: 34 };
    pub(crate) global ADDRESS_ONLY_ADDRESS_SEQUENCE: Sequence = Sequence { index: 7, length: 29 };
    pub(crate) global NO_BRACKETS_FIELD_SEQUENCE: Sequence = Sequence { index: 2, length: 47 };
    pub(crate) global NO_BRACKETS_ADDRESS_SEQUENCE: Sequence = Sequence { index: 20, length: 29 };
    pub(crate) global BRACKETS_FIELD_SEQUENCE: Sequence = Sequence { index: 2, length: 49 };
    pub(crate) global BRACKETS_ADDRESS_SEQUENCE: Sequence = Sequence { index: 21, length: 29 };
    pub(crate) global QUOTES_FIELD_SEQUENCE: Sequence = Sequence { index: 2, length: 63 };
    pub(crate) global QUOTES_ADDRESS_SEQUENCE: Sequence = Sequence { index: 35, length: 29 };
    pub(crate) global MALICIOUS_QUOTES_ADDRESS_SEQUENCE: Sequence =
        Sequence { index: 8, length: 24 };
}

pub(crate) mod EmailAddressUnderscore {
    use crate::{MAX_EMAIL_ADDRESS_LENGTH, Sequence};

    pub(crate) global ADDRESS: BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH> =
        BoundedVec::from_array("john_doe@example.com".as_bytes());
    // "\r\nfrom:john_doe@example.com\r\n" = 29 bytes
    pub(crate) global HEADER: [u8; 29] =
        comptime { "\r\nfrom:john_doe@example.com\r\n".as_bytes() };
    pub(crate) global FIELD_SEQUENCE: Sequence = Sequence { index: 2, length: 25 };
    pub(crate) global ADDRESS_SEQUENCE: Sequence = Sequence { index: 7, length: 20 };
}

pub(crate) mod EmailSmall {
    use crate::{dkim::RSAPubkey, KEY_LIMBS_1024};

    // Synthetic 1024-bit RSA key for hash testing.
    // Values are arbitrary but respect range constraints:
    // - modulus limbs[0..7]: 120 bits each
    // - modulus limbs[8]: 64 bits (1024 - 8*120 = 64)
    // - redc limbs[0..8]: 120 bits each
    pub(crate) global PUBKEY: RSAPubkey<KEY_LIMBS_1024> = RSAPubkey::new(
        [
            0xaabbccdd11223344aabbccdd1122,
            0x112233445566778899aabbccddee,
            0xffeeddccbbaa99887766554433,
            0x00112233445566778899aabbccddee,
            0xdeadbeefcafebabe12345678abcd,
            0xfedcba98765432100fedcba98765,
            0x0123456789abcdef0123456789ab,
            0xabcdef0123456789abcdef012345,
            0xdeadbeefcafebabe,
        ],
        [
            0x111111111111111111111111111111,
            0x222222222222222222222222222222,
            0x333333333333333333333333333333,
            0x444444444444444444444444444444,
            0x555555555555555555555555555555,
            0x666666666666666666666666666666,
            0x777777777777777777777777777777,
            0x888888888888888888888888888888,
            0x99999999999999999999,
        ],
    );
}

pub(crate) mod SyntheticKey1024 {
    use crate::{dkim::RSAPubkey, KEY_LIMBS_1024};

    // Synthetic 1024-bit key whose modulus is just above 2^1023, so that
    // SIGNATURE + modulus still fits in 1024 bits.
    pub(crate) global MESSAGE: BoundedVec<u8, 4> = BoundedVec::from_array([116, 101, 115, 116]); // "test"
    pub(crate) global PUBKEY: RSAPubkey<KEY_LIMBS_1024> = RSAPubkey::new(
        [
            0xbb6307c434288353a09ea3ea9cbfa3,
            0x0b5f9d76d49c51f81b033a67bb30c0,
            0x81eb552985cef8150f14b80b481945,
            0x62314c8451da2e8e1fd2bd7a0e29fd,
            0x44d827bff9c5c661fbb0652034bfc7,
            0x00e9b1c86d86e8caf3fa324a8c77a4,
            0x0,
            0x0,
            0x8000000000000000,
        ],
        [
            0xbffeb70c33a75f87b3b526322a2c15,
            0xa1096619431e18218fe7cadc5f4fe1,
            0x56ac28fe61388babe67359220ce35d,
            0xceb37bae25d171e02eed3026724a65,
            0x27d840063a399e044f9adfcb40389d,
            0x164e37927917350c05cdb573885bbb,
            0xffffffffffffffffffffffffffffff,
            0xffffffffffffffffffffffffffffff,
            0x7fffffffffffffffff,
        ],
    );
    pub(crate) global SIGNATURE: [Field; KEY_LIMBS_1024] = [
        0x44dbc4748f1ca3a57eeda2af6b58c6,
        0x50b6bb8afd5b1ffb90458520b83c11,
        0x9dd277983e26b4a6c1881a6f89657d,
        0x52c5a9a0b723c31b74d48b2c733ae1,
        0x8c4ad5c53d05e8caea86aa4524f25b,
        0x348864c9844a3fe2e2b631feff2a2f,
        0x8d902862aed5d978d1b6a88e62a3c3,
        0xd7684b2ed91af5a77e7f7cb53465fd,
        0x2fc1778ecf09272e,
    ];
    // SIGNATURE + modulus: the same residue, so it passes the RSA check unless
    // the signature is required to be reduced.
    pub(crate) global SIGNATURE_PLUS_MODULUS: [Field; KEY_LIMBS_1024] = [
        0x003ecc38c34526f91f8c469a081869,
        0x5c165901d1f771f3ab48bf88736cd2,
        0x1fbdccc1c3f5acbbd09cd27ad17ec2,
        0xb4f6f62508fdf1a994a748a68164df,
        0xd122fd8536cbaf2ce6370f6559b222,
        0x35721691f1d128add6b064498ba1d3,
        0x8d902862aed5d978d1b6a88e62a3c3,
        0xd7684b2ed91af5a77e7f7cb53465fd,
        0xafc1778ecf09272e,
    ];
}

pub(crate) mod SyntheticKey4096 {
    use crate::{dkim::RSAPubkey, KEY_LIMBS_4096};

    // Synthetic 4096-bit key; SIGNATURE signs "test" with SHA-256
    pub(crate) global MESSAGE: BoundedVec<u8, 4> = BoundedVec::from_array([116, 101, 115, 116]); // "test"
    pub(crate) global PUBKEY: RSAPubkey<KEY_LIMBS_4096> = RSAPubkey::new(
        [
            0xe53f4fc1b6ab56726c7b2175f27283,
            0x34140e69c58e159f205005689cfd0e,
            0xc4a826c4626e5305905a02dbc520cb,
            0xa4c685db3d3e41e93320b6ace59364,
            0x5b2afee0d5940d7ba2296183cd80a4,
            0x261d608ec299e42a597357790f202e,
            0xdbb756bd70089ee76e4420ce0a95b4,
            0x31e2d9fffa7e1456599430670757c7,
            0x98fa1fb3cf399115472342ca37c340,
            0x4664e0fd0f0ebe2945c6025fb928d7,
            0xd9455e60a1edaf1c5657a12e78fea5,
            0x84f566b53c27d52dbf2ed9ca9391ba,
            0x3559b29d49cffb13b237d42ed32d68,
            0x8f8ba6747b04062b99c074ec44720e,
            0x1bcac6446ae622b38ed666aa130ace,
            0x54f16f3b95eb19d848fbda5583a3ce,
            0x3709c6df38c3a078ca0c5c63bbabf0,
            0xe3a7341fff7c7ec8165c3e30e6c4e6,
            0x23c02665dc010109a783618577b759,
            0x815fcd0f90e061d660708864647b61,
            0x56e38f518235e98d27375748e23dbf,
            0xf631c19eb5d528cc334b0b9534c206,
            0x74c012f21d4c307920d8142afbf25f,
            0xbf6f8d4f6bd6f640622439e669ea1b,
            0x25a5e1cc7de22781a42f66a6bab9b1,
            0xefc2b489ceb9a8c4929f6b52a345dd,
            0x57df7d57def5f4e9af3756ab33922b,
            0x4dcad3e6407e3bf080a944039ffe2b,
            0xf48ca805343a5f422eff35dcc350ed,
            0x16e7bde58fcdd1e73cbbddc3ddfe80,
            0x6c7b57de8677371b7a54de434626d4,
            0xbe01218ff3fbecc627d52836b37605,
            0x9ec841997c3da24b3796d91694ae86,
            0xa12e64cc84170661249a62e597e832,
            0xc940,
        ],
        [
            0x982f66708799ff49f7e04f1e0ad8e8,
            0xbc6b6a1a66711c87fe51463068d795,
            0xb92fd94420fb834b1207779305d434,
            0x1ef7581e158548e805b67fc5a10fb7,
            0xdb8442bdded1b515d394802214edf9,
            0xf660d70d718705f84b59b01c55cc4d,
            0xb894c08d7d1b4491e73f8f1fd80ecd,
            0x8c9e9831a796d6362b9965f5f96f0d,
            0xcfe888d0cfc6c0791085707e66ff33,
            0x5ea0496704b4309bba8c3f97fec05f,
            0xf6fb65bf736a5f8dc89ae92fbd193b,
            0x756c413d9d72fa7db7af02b0705f54,
            0xe557baeb5a87fa7d1aceede5ebc3af,
            0xcfe6cf56a7de293c605d0e4a7934da,
            0x55ef823d6727873279fe1becec87ad,
            0xe19447bffe4fb60fb118af13747960,
            0x32fbe7e6dbaf67495aac4715112ca3,
            0x71ded6c11dea6f85d9d4d38feed368,
            0xed5512e9863c8e0de6538db996ab91,
            0x244834335df11f2e3e1de3356b4f3,
            0x85e598d271b920e75a6a021152409b,
            0x5684ef8444ed10525485854b0b393d,
            0x4d9b023e818cf4f94cd0c00a1a027d,
            0xdc8213717d03e214ebaf3bf3b8cefe,
            0xad381936e95841ccee007edba0a770,
            0x91a9989209576e4467902c91df7cf7,
            0x61d60cc9c46f04f8d7f8b4d8edc9a1,
            0x14b70c2ea6cc4054f6740f274b1cdc,
            0x6bb8ac85caec3fd51557e5985971e7,
            0xa2f2caee40da06365fd9a1cc61c3cc,
            0xe783058bbc0f34f01bc1de272419dc,
            0x73d9027e4198079991d893a98be92f,
            0xe7fd0dad331b77f03b1b4bf9366d87,
            0xe62f8d4ef0a891372e919a3fe54fa9,
            0x516901,
        ],
    );
    pub(crate) global SIGNATURE: [Field; KEY_LIMBS_4096] = [
        0x4a95b6e9ea8bc7be53348a5220e7af,
        0xd2890d088dc2665aa0403448a03cc9,
        0x3b1ffa05f64a93ec346368662ca3d,
        0x355eda4239573daf2c2328f9da52f8,
        0x3f39745027ef3bbc260d2ecbec0161,
        0xe5e014c73152baf38b870085291ea2,
        0xce9dbd2920d366e056867abad6902a,
        0xde62c3d6b0f836ea1e29619c347996,
        0xc52ec0eafbbb1cc1af52bbd323290d,
        0x5c469e00626b924047548cf63effd2,
        0x4a16768e6254d4edf678bbd4526ac3,
        0x6577e4d9e7d3d669ae62696133e17f,
        0xfd37819803a31ed04d4aeb2d0a527a,
        0x54419d7092063832dab761921e55eb,
        0xccd4bc16e881b60e017b4cd9037bd4,
        0xfe5de8094f9225a0c6db54223fb8de,
        0x64e5880714741330d2e37748955902,
        0xac685111d97c59d4966db179b94048,
        0xa4a47a8044af026cb8fd1508ca0283,
        0xbac4e873fba7cd24bdfd0955eac084,
        0xa1a38d425f19edd49e4bae19440fa8,
        0x9b592791a485548cbe5b06a80df7c6,
        0x2e528fdd803ae0286d02d4c6f06e79,
        0x38e8ca7f647948face671c8ba1e09d,
        0x2ee4aaf230f3261d01810c4f24a04e,
        0xa670d3c02092a9cf3673160b9ce4ac,
        0x7a64f5a002285cbcff6538a6381ebd,
        0xac6c12a99de1183cc4f85f347941a3,
        0xbf382570db7239311986094400aea8,
        0x49e21774ba0babe334de84624e27d7,
        0xfdafde19bf77be6674fa8c45ae67e3,
        0xefb30c61b7cb28d3fd875d16e1b7af,
        0x37a2f38b6e1cd9dbfb655d240cacd2,
        0x20f2e05747542ec20a74cf5275cf7c,
        0x7ef0,
    ];
}

pub(crate) mod PartialHash {
    pub(crate) global DATA: [u8; 192] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
        94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130,
        131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
        149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
        167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184,
        185, 186, 187, 188, 189, 190, 191,
    ];
}
