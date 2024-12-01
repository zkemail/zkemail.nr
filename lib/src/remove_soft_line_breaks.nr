use crate::{CR, LF};
use nodash::array::pack_bytes;
use std::hash::poseidon2::Poseidon2;

/**
 * Computes R by packing bytes into fields before hashing to reduce the work
 *
 * @param encoded The encoded input array
 * @param decoded The decoded input array
 * @returns the poseidon hash of the bytes packed into field elements
 */
fn compressed_r<let N: u32>(encoded: [u8; N], decoded: [u8; N]) -> Field {
    let encoded_packed = pack_bytes(encoded);
    let decoded_packed = pack_bytes(decoded);
    let mut input: [Field; 2 * (N / 31 + 1)] = [0; 2 * (N / 31 + 1)];
    for i in 0..encoded_packed.len() {
        input[i] = encoded_packed[i];
        input[i + N / 31 + 1] = decoded_packed[i];
    }
    Poseidon2::hash(input, input.len())
}

/**
 * Find the indexes where the RLC computation should zero out
 *
 * @param encoded The encoded input array
 * @returns indexes where the RLC computation should zero out
 */
pub fn find_zeroes<let N: u32>(encoded: [u8; N]) -> [bool; N] {
    // identify soft line breaks
    let mut is_break: [bool; N] = [false; N];
    for i in 0..N - 2 {
        is_break[i] = (encoded[i] == 0x3D) & (encoded[i + 1] == CR) & (encoded[i + 2] == LF);
    }

    // find indexes of chars to zero
    let mut should_zero: [bool; N] = [false; N];
    should_zero[0] = is_break[0];
    should_zero[1] = is_break[1] + is_break[0];
    should_zero[N - 1] = is_break[N - 3];
    for i in 2..N - 1 {
        should_zero[i] = is_break[i] + is_break[i - 1] + is_break[i - 2];
    }

    should_zero
}

pub fn powers_of_r<let N: u32>(
    encoded: [u8; N],
    decoded: [u8; N],
    should_zero: [bool; N],
) -> ([Field; N], [Field; N]) {
    // compute r
    let r = compressed_r(encoded, decoded);

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

    (r_encoded, r_decoded)
}

/**
 * Remove soft line breaks from the given text
 *
 * @param text The text to remove soft line breaks from
 */
pub fn remove_soft_line_breaks<let N: u32>(encoded: [u8; N], decoded: [u8; N]) -> bool {
    // find indexes to zero out
    let should_zero = find_zeroes(encoded);

    // process encoded input
    let mut processed: [u8; N] = [0; N];
    for i in 0..N {
        processed[i] = (1 - should_zero[i] as u8) * encoded[i];
    }

    // calculate powers of r for encoded
    let (r_encoded, r_decoded) = powers_of_r(encoded, decoded, should_zero);

    // calculate rlc for processed
    let mut sum_enc: Field = r_encoded[0] * processed[0] as Field;
    let mut sum_dec: Field = r_decoded[0] * decoded[0] as Field;
    for i in 1..N {
        sum_enc = sum_enc + r_encoded[i] * processed[i] as Field;
        sum_dec = sum_dec + r_decoded[i] * decoded[i] as Field;
    }
    sum_enc == sum_dec
}

// test vectors copied from https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/tests/remove-soft-line-breaks.test.ts
#[test]
pub fn test_remove_soft_line_breaks() {
    let encoded = [
        115, 101, 115, 58, 61, 13, 10, 45, 32, 83, 114, 101, 97, 107, 61, 13, 10, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let decoded = [
        115, 101, 115, 58, 45, 32, 83, 114, 101, 97, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ];
    let res = remove_soft_line_breaks(encoded, decoded);
    assert(res, "Expected to remove soft line breaks");
}

#[test]
pub fn test_return_false_incorrect_decoded_input() {
    let encoded = [
        115, 101, 115, 58, 61, 13, 10, 45, 32, 83, 114, 101, 97, 107, 61, 13, 10, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let decoded = [
        115, 101, 115, 58, 45, 32, 83, 114, 101, 97, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ];
    let res = remove_soft_line_breaks(encoded, decoded);
    assert(!res, "Expected to return false for incorrect decoded input");
}

#[test]
pub fn test_handle_no_soft_line_breaks() {
    let encoded = [
        104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let decoded = [
        104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let res = remove_soft_line_breaks(encoded, decoded);
    assert(res, "Expected to handle no soft line breaks");
}

#[test]
pub fn test_handle_consecutive_soft_line_breaks() {
    let encoded = [
        104, 101, 108, 108, 111, 61, 13, 10, 61, 13, 10, 119, 111, 114, 108, 100, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let decoded = [
        104, 101, 108, 108, 111, 119, 111, 114, 108, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let res = remove_soft_line_breaks(encoded, decoded);
    assert(res, "Expected to handle consecutive soft line breaks");
}

#[test]
pub fn test_handle_soft_line_break_beginning() {
    let encoded = [
        61, 13, 10, 104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let decoded = [
        104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let res = remove_soft_line_breaks(encoded, decoded);
    assert(res, "Expected to handle soft line break at beginning");
}

#[test]
pub fn test_handle_soft_line_break_end() {
    let encoded = [
        104, 101, 108, 108, 111, 61, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let decoded = [
        104, 101, 108, 108, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let res = remove_soft_line_breaks(encoded, decoded);
    assert(res, "Expected to handle soft line break at end");
}

#[test]
pub fn test_handle_incomplete_line_break() {
    let encoded = [
        104, 101, 108, 108, 111, 61, 13, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let decoded = [
        104, 101, 108, 108, 111, 61, 13, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];
    let res = remove_soft_line_breaks(encoded, decoded);
    assert(res, "Expected to handle incomplete line break");
}
