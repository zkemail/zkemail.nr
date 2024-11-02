use std::hash::poseidon2;

/**
 * Remove soft line breaks from the given text
 *
 * @param text The text to remove soft line breaks from
 */
pub fn remove_soft_line_breaks<let N: u32>(
    encoded: BoundedVec<u8, N>,
    decoded: BoundedVec<u8, N>
) -> bool {
    // derive r from poseidon hash
    let mut r_input: [u8; 2*N] = [0; 2*N];
    for i in 0..encoded.len() {
        r_input[i] = encoded[i];
        r_input[i + N] = encoded[i];
    }
    let r = poseidon2(r_input, 2*N);

    // check for "=" (0x3D), "\r" (0x0D), and "\n" (0x0A)
    let mut is_equals: [bool; N] = [false; N];
    let mut is_cr: [bool; N] = [false; N];
    let mut is_lf: [bool; N] = [false; N];
    for i in 0..N - 2 {
        is_equals[i] = encoded[i] == 0x3D;
        is_cr[i] = encoded[i] == 0x0D;
        is_lf[i] = encoded[i] == 0x0A;
    }
    is_equals[N - 2] = encoded[N - 2] == 0x3D;
    is_equals[N - 1] = encoded[N - 1] == 0x3D;
    is_cr[N - 1] = encoded[N - 1] == 0x0D;

    // identify soft line breaks
    let mut is_soft_break: [bool; N] = [false; N];
    for i in 0..N-2 {
        is_soft_break[i] = is_equals[i] & is_cr[i] & is_lf[i];
    }

    // determine chars to zero
    let mut should_zero: [bool; N] = [false; N];
    should_zero[0] = is_soft_break[0];
    should_zero[1] = is_soft_break[1] + is_soft_break[0];
    should_zero[N - 1] = is_soft_break[N - 2] + is_soft_break[N - 3];
    for i in 2..N=1 {
        should_zero[i] = is_soft_break[i] + is_soft_break[i - 1] + is_soft_break[i - 2];
    }

    // process encoded input
    let mut processed: [bool; N] = [false; N];
    for i in 0..N {
        processed[i] = should_zero[i] & encoded[i];
    }

    // calculate powers of r for encoded
    let mut r_encoded: [Field; N] = [0; N];
    let mut start = r;
    if should_zero[0] {
        start = 1;
    }
    r_encoded[0] = start;
    for i in 1..N {
        let prev = r_encoded[i - 1];
        let mut current = prev * r;
        if should_zero[i] {
            current = prev;
        }
        r_encoded[i] = current;
    }

    // calculate powers of r for decoded
    let mut r_decoded: [Field; N] = [0; N];
    r_decoded[0] = r;
    for i in 1..N {
        r_decoded[i] = r_decoded[i - 1] * r;
    }

    // calculate rlc for processed
    let mut sum_enc: [Field; N] = [0; N];
    let mut sum_dec: [Field; N] = [0; N];
    sum_enc[0] = r_encoded[0] * processed[0];
    sum_dec[0] = r_decoded[0] * decoded[0];
    for i in 1..N {
        sum_enc[i] = sum_enc[i - 1] + r_encoded[i] * processed[i];
        sum_dec[i] = sum_dec[i - 1] + r_decoded[i] * decoded[i];
    }

    // determine if rlc for decoded and encoded match
    sum_enc[N - 1] == sum_dec[N - 1]
}

#[test]
pub fn test_remove_soft_line_breaks() {
    let encoded = [
        115, 101, 115, 58, 61, 13, 10, 45, 32,
        83, 114, 101, 97, 107, 61, 13, 10, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
    let decoded = [
        115, 101, 115, 58, 45, 32, 83, 114, 101,
        97, 107, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
}

#[test]
pub fn test_return_false_incorrect_decoded_input() {
    let encoded = [
        115, 101, 115, 58, 61, 13, 10, 45, 32,
        83, 114, 101, 97, 107, 61, 13, 10, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
    let decoded = [
        115, 101, 115, 58, 45, 32, 83, 114, 101,
        97, 108, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ]
}

#[test]
pub fn test_handle_no_soft_line_breaks() {
    let encoded = [
        104, 101, 108, 108, 111, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
    let decoded = [
        104, 101, 108, 108, 111, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
}

#[test]
pub fn test_handle_consecutive_soft_line_breaks() {
    let encoded = [
        104, 101, 108, 108, 111, 61, 13, 10, 61,
        13, 10, 119, 111, 114, 108, 100, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
    let decoded = [
        104, 101, 108, 108, 111, 119, 111, 114, 108,
        100, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
}

#[test]
pub fn test_handle_soft_line_break_beginning() {
    let encoded = [
        61, 13, 10, 104, 101, 108, 108, 111, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
    let decoded = [
        104, 101, 108, 108, 111, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
}

#[test]
pub fn test_handle_soft_line_break_end() {
    let encoded = [
        104, 101, 108, 108, 111, 61, 13, 10, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
    let decoded = [
        104, 101, 108, 108, 111, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
}

#[test]
pub fn test_handle_incomplete_line_break() {
    let encoded = [
        104, 101, 108, 108, 111, 61, 13, 11, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
    let decoded = [
        104, 101, 108, 108, 111, 61, 13, 11, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0
    ];
}