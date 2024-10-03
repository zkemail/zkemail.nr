use std::runtime::is_unconstrained;
use std::hash::sha256_compression;

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L23
// Convert 64-byte array to array of 16 u32s
pub fn msg_u8_to_u32(msg: [u8; BLOCK_SIZE]) -> [u32; 16] {
    let mut msg32: [u32; 16] = [0; 16];

    for i in 0..16 {
        let mut msg_field: Field = 0;
        for j in 0..4 {
            msg_field = msg_field * 256 + msg[64 - 4*(i + 1) + j] as Field;
        }
        msg32[15 - i] = msg_field as u32;
    }

    msg32
}

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L38
unconstrained fn build_msg_block_iter<let N: u32>(msg: [u8; N], message_size: u32, msg_start: u32) -> ([u8; BLOCK_SIZE], u32) {
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    // We insert `BLOCK_SIZE` bytes (or up to the end of the message)
    let block_input = if msg_start + BLOCK_SIZE > message_size {
        if message_size < msg_start {
            // This function is sometimes called with `msg_start` past the end of the message.
            // In this case we return an empty block and zero pointer to signal that the result should be ignored.
            0
        } else {
            message_size - msg_start
        }
    } else {
        BLOCK_SIZE
    };
    for k in 0..block_input {
        msg_block[k] = msg[msg_start + k];
    }
    (msg_block, block_input)
}

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L59
// Verify the block we are compressing was appropriately constructed
fn verify_msg_block<let N: u32>(
    msg: [u8; N],
    message_size: u32,
    msg_block: [u8; 64],
    msg_start: u32
) -> u32 {
    let mut msg_byte_ptr: u32 = 0; // Message byte pointer
    let mut msg_end = msg_start + BLOCK_SIZE;
    if msg_end > N {
        msg_end = N;
    }

    for k in msg_start..msg_end {
        if k < message_size {
            assert_eq(msg_block[msg_byte_ptr], msg[k]);
            msg_byte_ptr = msg_byte_ptr + 1;
        }
    }

    msg_byte_ptr
}

global BLOCK_SIZE = 64;
global ZERO = 0;

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L86-L116
/**
 * Partially computes a SHA256 hash of a message but does not finalize
 * @notice can be used for post-partial hashing where client proves part of hash and relies on server to finish
 *
 * @param N: the maximum length of the message to hash
 * @param msg: the preimage to begin hashing
 * @param message_size: the actual length of the preimage to hash
 * @return the intermediate hash state
 */
pub fn partial_sha256_var_start<let N: u32>(msg: [u8; N]) -> [u32; 8] {
    let num_blocks = N / BLOCK_SIZE;
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut h: [u32; 8] = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]; // Intermediate hash, starting with the canonical initial value
    let mut msg_byte_ptr = 0; // Pointer into msg_block

    for i in 0..num_blocks {
        let msg_start = BLOCK_SIZE * i;
        let (new_msg_block, new_msg_byte_ptr) = unsafe {
            build_msg_block_iter(msg, N, msg_start)
        };
        if msg_start < N {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            // Verify the block we are compressing was appropriately constructed
            let new_msg_byte_ptr = verify_msg_block(msg, N, msg_block, msg_start);
            if msg_start < N {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start < N {
            msg_byte_ptr = new_msg_byte_ptr;
        }

        // If the block is filled, compress it.
        // An un-filled block is handled after this loop.
        if (msg_start < N) & (msg_byte_ptr == BLOCK_SIZE) {
            h = sha256_compression(msg_u8_to_u32(msg_block), h);
        }
    }

    h
}

// https://github.com/noir-lang/noir/blob/76eec710ff73e5e45fdddcd41ae2cd74e879cfa5/noir_stdlib/src/hash/sha256.nr#L85
/**
 * Given some state of a partially computed sha256 hash and remaining preimage, complete the hash
 * @notice used for traditional partial hashing
 *
 * @param N - the maximum length of the message to hash
 * @param h - the intermediate hash state
 * @param msg - the remaining preimage to hash
 * @param message_size - the size of the remaining preimage
 * @param real_message_size -= the total size of the preimage
 * @return finalized sha256 hash
 */
pub fn partial_sha256_var_end<let N: u32>(mut h: [u32; 8], msg: [u8; N], message_size: u64, real_message_size: u64) -> [u8; 32] {
    let message_size = message_size as u32; // noir stdlib uses u64
    let real_message_size = real_message_size as u32; // noir stdlib uses u64

    let num_blocks = N / BLOCK_SIZE;
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut msg_byte_ptr = 0; // Pointer into msg_block

    for i in 0..num_blocks {
        let msg_start = BLOCK_SIZE * i;
        let (new_msg_block, new_msg_byte_ptr) = unsafe {
            build_msg_block_iter(msg, message_size, msg_start)
        };
        if msg_start < message_size {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            // Verify the block we are compressing was appropriately constructed
            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start < message_size {
            msg_byte_ptr = new_msg_byte_ptr;
        }

        // If the block is filled, compress it.
        // An un-filled block is handled after this loop.
        if (msg_start < message_size) & (msg_byte_ptr == BLOCK_SIZE) {
            h = sha256_compression(msg_u8_to_u32(msg_block), h);
        }
    }

    let modulo = N % BLOCK_SIZE;
    // Handle setup of the final msg block.
    // This case is only hit if the msg is less than the block size,
    // or our message cannot be evenly split into blocks.
    if modulo != 0 {
        let msg_start = BLOCK_SIZE * num_blocks;
        let (new_msg_block, new_msg_byte_ptr) = unsafe {
            build_msg_block_iter(msg, message_size, msg_start)
        };

        if msg_start < message_size {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start < message_size {
            msg_byte_ptr = new_msg_byte_ptr;
        }
    }

    if msg_byte_ptr == BLOCK_SIZE {
        msg_byte_ptr = 0;
    }

    // This variable is used to get around the compiler under-constrained check giving a warning.
    // We want to check against a constant zero, but if it does not come from the circuit inputs
    // or return values the compiler check will issue a warning.
    let zero = msg_block[0] - msg_block[0];

    // Pad the rest such that we have a [u32; 2] block at the end representing the length
    // of the message, and a block of 1 0 ... 0 following the message (i.e. [1 << 7, 0, ..., 0]).
    msg_block[msg_byte_ptr] = 1 << 7;
    let last_block = msg_block;
    msg_byte_ptr = msg_byte_ptr + 1;

    unsafe {
        let (new_msg_block, new_msg_byte_ptr) = pad_msg_block(msg_block, msg_byte_ptr);
        msg_block = new_msg_block;
        if is_unconstrained() {
            msg_byte_ptr = new_msg_byte_ptr;
        }
    }

    if !is_unconstrained() {
        for i in 0..64 {
            assert_eq(msg_block[i], last_block[i]);
        }

        // If i >= 57, there aren't enough bits in the current message block to accomplish this, so
        // the 1 and 0s fill up the current block, which we then compress accordingly.
        // Not enough bits (64) to store length. Fill up with zeros.
        for _i in 57..64 {
            if msg_byte_ptr <= 63 & msg_byte_ptr >= 57 {
                assert_eq(msg_block[msg_byte_ptr], zero);
                msg_byte_ptr += 1;
            }
        }
    }

    if msg_byte_ptr >= 57 {
        h = sha256_compression(msg_u8_to_u32(msg_block), h);

        msg_byte_ptr = 0;
    }

    msg_block = unsafe {
        attach_len_to_msg_block(msg_block, msg_byte_ptr, real_message_size)
    };

    if !is_unconstrained() {
        for i in 0..56 {
            if i < msg_byte_ptr {
                assert_eq(msg_block[i], last_block[i]);
            } else {
                assert_eq(msg_block[i], zero);
            }
        }

        let len = 8 * real_message_size;
        let len_bytes: [u8; 8] = (len as Field).to_be_bytes();
        for i in 56..64 {
            assert_eq(msg_block[i], len_bytes[i - 56]);
        }
    }

    hash_final_block(msg_block, h)
}

unconstrained fn pad_msg_block(
    mut msg_block: [u8; BLOCK_SIZE],
    mut msg_byte_ptr: u32
) -> ([u8; BLOCK_SIZE], u32) {
    // If i >= 57, there aren't enough bits in the current message block to accomplish this, so
    // the 1 and 0s fill up the current block, which we then compress accordingly.
    if msg_byte_ptr >= 57 {
        // Not enough bits (64) to store length. Fill up with zeros.
        for i in msg_byte_ptr..BLOCK_SIZE {
            msg_block[i] = 0;
        }
        (msg_block, BLOCK_SIZE)
    } else {
        (msg_block, msg_byte_ptr)
    }
}

unconstrained fn attach_len_to_msg_block(mut msg_block: [u8; BLOCK_SIZE], mut msg_byte_ptr: u32, message_size: u32) -> [u8; BLOCK_SIZE] {
    // We assume that `msg_byte_ptr` is less than 57 because if not then it is reset to zero before calling this function.
    // In any case, fill blocks up with zeros until the last 64 (i.e. until msg_byte_ptr = 56).

    for i in msg_byte_ptr..56 {
        msg_block[i] = 0;
    }

    let len = 8 * message_size;
    let len_bytes: [u8; 8] = (len as Field).to_be_bytes();
    for i in 0..8 {
        msg_block[56 + i] = len_bytes[i];
    }
    msg_block
}

fn hash_final_block(msg_block: [u8; BLOCK_SIZE], mut state: [u32; 8]) -> [u8; 32] {
    let mut out_h: [u8; 32] = [0; 32]; // Digest as sequence of bytes

    // Hash final padded block
    state = sha256_compression(msg_u8_to_u32(msg_block), state);

    // Return final hash as byte array
    for j in 0..8 {
        let h_bytes: [u8; 4] = (state[7 - j] as Field).to_le_bytes();
        for k in 0..4 {
            out_h[31 - 4*j - k] = h_bytes[k];
        }
    }

    out_h
}

// #[test]
fn test_partial_hash() {
    let data = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
        94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130,
        131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
        149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
        167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184,
        185, 186, 187, 188, 189, 190, 191
    ];
    let mut data0 = [0; 128];
    for i in 0..data0.len() {
        data0[i] = data[i];
    }
    let mut data1 = [0; 64];
    for i in 0..data1.len() {
        data1[i] = data[data0.len() + i];
    }
    let state = partial_sha256_var_start(data0);
    let hash = partial_sha256_var_end(state, data1, data1.len() as u64, data.len() as u64);
    let correct_hash = std::hash::sha256_var(data, data.len() as u64);
    assert_eq(hash, correct_hash);
}

// #[test]
fn test_partial_hash2() {
    let data = [
        84, 104, 101, 32, 84, 105, 109, 101, 115, 32, 48, 51, 47, 74, 97,
        110, 47, 50, 48, 48, 57, 32, 67, 104, 97, 110, 99, 101, 108, 108,
        111, 114, 32, 111, 110, 32, 98, 114, 105, 110, 107, 32, 111, 102,
        32, 115, 101, 99, 111, 110, 100, 32, 98, 97, 105, 108, 111, 117,
        116, 32, 102, 111, 114, 32, 98, 97, 110, 107, 115, 13, 10, 13, 10,
        49, 53, 32, 121, 101, 97, 114, 115, 32, 97, 103, 111, 44, 32, 83,
        97, 116, 111, 115, 104, 105, 32, 109, 105, 110, 101, 100, 32, 116,
        104, 101, 32, 102, 105, 114, 115, 116, 32, 98, 108, 111, 99, 107,
        32, 111, 102, 32, 116, 104, 101, 32, 66, 105, 116, 99, 111, 105,
        110, 32, 98, 108, 111, 99, 107, 99, 104, 97, 105, 110, 32, 61,
        13, 10, 65, 102, 116, 101, 114, 32, 116, 104, 101, 32, 66, 105,
        116, 99, 111, 105, 110, 32, 119, 104, 105, 116, 101, 32, 112, 97,
        112, 101, 114, 32, 97, 112, 112, 101, 97, 114, 101, 100, 32, 111,
        110, 32, 79, 99, 116, 111, 98, 101, 114, 32, 51, 49, 44, 32, 50,
        48, 48, 56, 44, 32, 111, 110, 32, 97, 32, 61, 13, 10, 99, 114,
        121, 112, 116, 111, 103, 114, 97, 112, 104, 121, 32, 109, 97, 105,
        108, 105, 110, 103, 32, 108, 105, 115, 116, 44, 32, 116, 104, 101,
        32, 71, 101, 110, 101, 115, 105, 115, 32, 66, 108, 111, 99, 107,
        32, 61, 69, 50, 61, 56, 48, 61, 57, 52, 32, 116, 104, 101, 32, 102,
        105, 114, 115, 116, 32, 98, 105, 116, 99, 111, 105, 110, 32, 61,
        13, 10, 98, 108, 111, 99, 107, 32, 97, 110, 100, 32, 116, 104, 101,
        32, 98, 97, 115, 105, 115, 32, 111, 102, 32, 116, 104, 101, 32,
        101, 110, 116, 105, 114, 101, 32, 66, 105, 116, 99, 111, 105, 110,
        32, 116, 114, 97, 100, 105, 110, 103, 32, 115, 121, 115, 116, 101,
        109, 32, 105, 110, 32, 112, 108, 97, 99, 101, 32, 116, 111, 32,
        61, 13, 10, 116, 104, 105, 115, 32, 100, 97, 121, 32, 61, 69, 50,
        61, 56, 48, 61, 57, 52, 32, 119, 97, 115, 32, 109, 105, 110, 101,
        100, 32, 111, 110, 32, 74, 97, 110, 117, 97, 114, 121, 32, 51, 44,
        32, 50, 48, 48, 57, 46, 61, 50, 48, 13, 10, 13, 10, 84, 104, 101,
        32, 71, 101, 110, 101, 115, 105, 115, 32, 66, 108, 111, 99, 107, 32,
        105, 115, 32, 97, 108, 115, 111, 32, 107, 110, 111, 119, 110, 32,
        97, 115, 32, 66, 108, 111, 99, 107, 32, 48, 32, 111, 114, 32, 66,
        108, 111, 99, 107, 32, 49, 44, 32, 97, 110, 100, 32, 105, 115, 32,
        115, 116, 105, 108, 108, 32, 105, 110, 32, 61, 13, 10, 116, 104,
        101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 110, 101, 116, 119,
        111, 114, 107, 44, 32, 119, 104, 101, 114, 101, 32, 105, 116, 32,
        119, 105, 108, 108, 32, 114, 101, 109, 97, 105, 110, 32, 97, 115,
        32, 108, 111, 110, 103, 32, 97, 115, 32, 116, 104, 101, 114, 101,
        32, 105, 115, 32, 97, 32, 99, 111, 109, 112, 117, 116, 101, 114,
        32, 61, 13, 10, 114, 117, 110, 110, 105,
        110, 103, 32, 116, 104,
        101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 115, 111, 102, 116,
        119, 97, 114, 101, 46, 61, 50, 48, 13, 10, 13, 10, 65, 108, 108,
        32, 110, 111, 100, 101, 115, 32, 105, 110, 32, 116, 104, 101, 32,
        66, 105, 116, 99, 111, 105, 110, 32, 110, 101, 116, 119, 111, 114,
        107, 32, 99, 97, 110, 32, 99, 111, 110, 115, 117, 108, 116, 32, 105,
        116, 44, 32, 101, 118, 101, 110, 32, 105, 102, 32, 105, 116, 32,
        105, 115, 32, 97, 116, 32, 116, 104, 101, 32, 61, 13, 10, 111, 116,
        104, 101, 114, 32, 101, 110, 100, 32, 111, 102, 32, 116, 104, 101,
        32, 110, 101, 116, 119, 111, 114, 107, 32, 119, 105, 116, 104, 32,
        104, 117, 110, 100, 114, 101, 100, 115, 32, 111, 102, 32, 116, 104,
        111, 117, 115, 97, 110, 100, 115, 32, 111, 102, 32, 98, 108, 111,
        99, 107, 115, 46, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];
    let mut data0 = [0; 192];
    for i in 0..data0.len() {
        data0[i] = data[i];
    }
    let mut data1 = [0; 64];
    for i in 0..data1.len() {
        data1[i] = data[data0.len() + i];
    }
    let state = partial_sha256_var_start(data0);
    let hash = partial_sha256_var_end(state, data1, data1.len() as u64, data.len() as u64);
    let correct_hash = std::hash::sha256_var(data, data.len() as u64);
    assert_eq(hash, correct_hash);
}

#[test]
fn test_partial_hash_email_body() {
    let body = [
        84, 104, 101, 32, 84, 105, 109, 101, 115, 32, 48, 51, 47, 74, 97,
        110, 47, 50, 48, 48, 57, 32, 67, 104, 97, 110, 99, 101, 108, 108,
        111, 114, 32, 111, 110, 32, 98, 114, 105, 110, 107, 32, 111, 102,
        32, 115, 101, 99, 111, 110, 100, 32, 98, 97, 105, 108, 111, 117,
        116, 32, 102, 111, 114, 32, 98, 97, 110, 107, 115, 13, 10, 13, 10,
        49, 53, 32, 121, 101, 97, 114, 115, 32, 97, 103, 111, 44, 32, 83,
        97, 116, 111, 115, 104, 105, 32, 109, 105, 110, 101, 100, 32, 116,
        104, 101, 32, 102, 105, 114, 115, 116, 32, 98, 108, 111, 99, 107,
        32, 111, 102, 32, 116, 104, 101, 32, 66, 105, 116, 99, 111, 105,
        110, 32, 98, 108, 111, 99, 107, 99, 104, 97, 105, 110, 32, 61,
        13, 10, 65, 102, 116, 101, 114, 32, 116, 104, 101, 32, 66, 105,
        116, 99, 111, 105, 110, 32, 119, 104, 105, 116, 101, 32, 112, 97,
        112, 101, 114, 32, 97, 112, 112, 101, 97, 114, 101, 100, 32, 111,
        110, 32, 79, 99, 116, 111, 98, 101, 114, 32, 51, 49, 44, 32, 50,
        48, 48, 56, 44, 32, 111, 110, 32, 97, 32, 61, 13, 10, 99, 114,
        121, 112, 116, 111, 103, 114, 97, 112, 104, 121, 32, 109, 97, 105,
        108, 105, 110, 103, 32, 108, 105, 115, 116, 44, 32, 116, 104, 101,
        32, 71, 101, 110, 101, 115, 105, 115, 32, 66, 108, 111, 99, 107,
        32, 61, 69, 50, 61, 56, 48, 61, 57, 52, 32, 116, 104, 101, 32, 102,
        105, 114, 115, 116, 32, 98, 105, 116, 99, 111, 105, 110, 32, 61,
        13, 10, 98, 108, 111, 99, 107, 32, 97, 110, 100, 32, 116, 104, 101,
        32, 98, 97, 115, 105, 115, 32, 111, 102, 32, 116, 104, 101, 32,
        101, 110, 116, 105, 114, 101, 32, 66, 105, 116, 99, 111, 105, 110,
        32, 116, 114, 97, 100, 105, 110, 103, 32, 115, 121, 115, 116, 101,
        109, 32, 105, 110, 32, 112, 108, 97, 99, 101, 32, 116, 111, 32,
        61, 13, 10, 116, 104, 105, 115, 32, 100, 97, 121, 32, 61, 69, 50,
        61, 56, 48, 61, 57, 52, 32, 119, 97, 115, 32, 109, 105, 110, 101,
        100, 32, 111, 110, 32, 74, 97, 110, 117, 97, 114, 121, 32, 51, 44,
        32, 50, 48, 48, 57, 46, 61, 50, 48, 13, 10, 13, 10, 84, 104, 101,
        32, 71, 101, 110, 101, 115, 105, 115, 32, 66, 108, 111, 99, 107, 32,
        105, 115, 32, 97, 108, 115, 111, 32, 107, 110, 111, 119, 110, 32,
        97, 115, 32, 66, 108, 111, 99, 107, 32, 48, 32, 111, 114, 32, 66,
        108, 111, 99, 107, 32, 49, 44, 32, 97, 110, 100, 32, 105, 115, 32,
        115, 116, 105, 108, 108, 32, 105, 110, 32, 61, 13, 10, 116, 104,
        101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 110, 101, 116, 119,
        111, 114, 107, 44, 32, 119, 104, 101, 114, 101, 32, 105, 116, 32,
        119, 105, 108, 108, 32, 114, 101, 109, 97, 105, 110, 32, 97, 115,
        32, 108, 111, 110, 103, 32, 97, 115, 32, 116, 104, 101, 114, 101,
        32, 105, 115, 32, 97, 32, 99, 111, 109, 112, 117, 116, 101, 114,
        32, 61, 13, 10, 114, 117, 110, 110, 105,
        110, 103, 32, 116, 104,
        101, 32, 66, 105, 116, 99, 111, 105, 110, 32, 115, 111, 102, 116,
        119, 97, 114, 101, 46, 61, 50, 48, 13, 10, 13, 10, 65, 108, 108,
        32, 110, 111, 100, 101, 115, 32, 105, 110, 32, 116, 104, 101, 32,
        66, 105, 116, 99, 111, 105, 110, 32, 110, 101, 116, 119, 111, 114,
        107, 32, 99, 97, 110, 32, 99, 111, 110, 115, 117, 108, 116, 32, 105,
        116, 44, 32, 101, 118, 101, 110, 32, 105, 102, 32, 105, 116, 32,
        105, 115, 32, 97, 116, 32, 116, 104, 101, 32, 61, 13, 10, 111, 116,
        104, 101, 114, 32, 101, 110, 100, 32, 111, 102, 32, 116, 104, 101,
        32, 110, 101, 116, 119, 111, 114, 107, 32, 119, 105, 116, 104, 32,
        104, 117, 110, 100, 114, 101, 100, 115, 32, 111, 102, 32, 116, 104,
        111, 117, 115, 97, 110, 100, 115, 32, 111, 102, 32, 98, 108, 111,
        99, 107, 115, 46, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];
    let actual_message_size = 740;
    let mut precomputed: [u8; 576] = [0; 576];
    for i in 0..576 {
        precomputed[i] = body[i];
    }
    let mut remaining: [u8; 192] = [0; 192];
    for i in 0..192 {
        remaining[i] = body[precomputed.len() + i];
    }
    let remaining_len = actual_message_size - precomputed.len();
    let state = partial_sha256_var_start(precomputed);
    println(remaining_len);
    // for i in 0..state.len() {
    //     let x: [u8; 4] = (state[i] as Field).to_le_bytes();
    //     println(x);
    // }
    // println(state);
    // let hash = partial_sha256_var_end(state, remaining, remaining_len as u64, actual_message_size as u64);
    // // let correct_hash = std::hash::sha256_var(body, 572);
    // let correct_hash = std::hash::sha256::sha256_var(body, actual_message_size as u64);
    // assert_eq(hash, correct_hash);
}
