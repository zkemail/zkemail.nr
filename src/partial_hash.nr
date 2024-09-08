// copied from Noir std lib. Refactored to make hashing a 2-step process.

use std::runtime::is_unconstrained;
use std::hash::sha256_compression;

// Convert 64-byte array to array of 16 u32s
fn msg_u8_to_u32(msg: [u8; 64]) -> [u32; 16] {
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

unconstrained fn build_msg_block_iter<let N: u32>(msg: [u8; N], message_size: u64, msg_start: u32) -> ([u8; 64], u64) {
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut msg_byte_ptr: u64 = 0; // Message byte pointer
    let mut msg_end = msg_start + BLOCK_SIZE;
    if msg_end > N {
        msg_end = N;
    }
    for k in msg_start..msg_end {
        if k as u64 < message_size {
            msg_block[msg_byte_ptr] = msg[k];
            msg_byte_ptr = msg_byte_ptr + 1;
        }
    }
    (msg_block, msg_byte_ptr)
}

// Verify the block we are compressing was appropriately constructed
fn verify_msg_block<let N: u32>(
    msg: [u8; N],
    message_size: u64,
    msg_block: [u8; 64],
    msg_start: u32
) -> u64 {
    let mut msg_byte_ptr: u64 = 0; // Message byte pointer
    let mut msg_end = msg_start + BLOCK_SIZE;
    let mut extra_bytes = 0;
    if msg_end > N {
        msg_end = N;
        extra_bytes = msg_end - N;
    }

    for k in msg_start..msg_end {
        if k as u64 < message_size {
            assert_eq(msg_block[msg_byte_ptr], msg[k]);
            msg_byte_ptr = msg_byte_ptr + 1;
        }
    }

    msg_byte_ptr
}

global BLOCK_SIZE = 64;
global ZERO = 0;

pub fn partial_sha256_var<let N: u32>(msg: [u8; N], message_size: u32) -> [u32; 8] {
    let message_size = message_size as u64; // noir stdlib uses u64

    let num_blocks = N / BLOCK_SIZE;
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut h: [u32; 8] = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]; // Intermediate hash, starting with the canonical initial value
    let mut msg_byte_ptr = 0; // Pointer into msg_block

    for i in 0..num_blocks {
        let msg_start = BLOCK_SIZE * i;
        let (new_msg_block, new_msg_byte_ptr) = /*unsafe*/ {
            build_msg_block_iter(msg, message_size, msg_start)
        };
        if msg_start as u64 < message_size {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            // Verify the block we are compressing was appropriately constructed
            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start as u64 < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start as u64 < message_size {
            msg_byte_ptr = new_msg_byte_ptr;
        }

        // If the block is filled, compress it.
        // An un-filled block is handled after this loop.
        if msg_byte_ptr == 64 {
            h = sha256_compression(msg_u8_to_u32(msg_block), h);
        }
    }

    h
}

// Variable size SHA-256 hash
pub fn finish_sha256_var<let N: u32>(mut h: [u32; 8], msg: [u8; N], message_size: u32, real_message_size: u32) -> [u8; 32] {
    let message_size = message_size as u64; // noir stdlib uses u64
    let real_message_size = real_message_size as u64; // noir stdlib uses u64

    let num_blocks = N / BLOCK_SIZE;
    let mut msg_block: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
    let mut msg_byte_ptr = 0; // Pointer into msg_block

    for i in 0..num_blocks {
        let msg_start = BLOCK_SIZE * i;
        let (new_msg_block, new_msg_byte_ptr) = /*unsafe*/ {
            build_msg_block_iter(msg, message_size, msg_start)
        };
        if msg_start as u64 < message_size {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            // Verify the block we are compressing was appropriately constructed
            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start as u64 < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start as u64 < message_size {
            msg_byte_ptr = new_msg_byte_ptr;
        }

        // If the block is filled, compress it.
        // An un-filled block is handled after this loop.
        if msg_byte_ptr == 64 {
            h = sha256_compression(msg_u8_to_u32(msg_block), h);
        }
    }

    let modulo = N % BLOCK_SIZE;
    // Handle setup of the final msg block.
    // This case is only hit if the msg is less than the block size,
    // or our message cannot be evenly split into blocks.
    if modulo != 0 {
        let msg_start = BLOCK_SIZE * num_blocks;
        let (new_msg_block, new_msg_byte_ptr) = /*unsafe*/ {
            build_msg_block_iter(msg, message_size, msg_start)
        };

        if msg_start as u64 < message_size {
            msg_block = new_msg_block;
        }

        if !is_unconstrained() {
            let new_msg_byte_ptr = verify_msg_block(msg, message_size, msg_block, msg_start);
            if msg_start as u64 < message_size {
                msg_byte_ptr = new_msg_byte_ptr;
            }
        } else if msg_start as u64 < message_size {
            msg_byte_ptr = new_msg_byte_ptr;
        }
    }

    if msg_byte_ptr == BLOCK_SIZE as u64 {
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

    /*unsafe*/
    {
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

    msg_block = /*unsafe*/ {
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
        let len_bytes = (len as Field).to_be_bytes(8);
        for i in 56..64 {
            assert_eq(msg_block[i], len_bytes[i - 56]);
        }
    }

    hash_final_block(msg_block, h)
}

unconstrained fn pad_msg_block(mut msg_block: [u8; 64], mut msg_byte_ptr: u64) -> ([u8; 64], u64) {
    // If i >= 57, there aren't enough bits in the current message block to accomplish this, so
    // the 1 and 0s fill up the current block, which we then compress accordingly.
    if msg_byte_ptr >= 57 {
        // Not enough bits (64) to store length. Fill up with zeros.
        if msg_byte_ptr < 64 {
            for _ in 57..64 {
                if msg_byte_ptr <= 63 {
                    msg_block[msg_byte_ptr] = 0;
                    msg_byte_ptr += 1;
                }
            }
        }
    }
    (msg_block, msg_byte_ptr)
}

unconstrained fn attach_len_to_msg_block(mut msg_block: [u8; 64], mut msg_byte_ptr: u64, message_size: u64) -> [u8; 64] {
    let len = 8 * message_size;
    let len_bytes = (len as Field).to_be_bytes(8);
    for _i in 0..64 {
        // In any case, fill blocks up with zeros until the last 64 (i.e. until msg_byte_ptr = 56).
        if msg_byte_ptr < 56 {
            msg_block[msg_byte_ptr] = 0;
            msg_byte_ptr = msg_byte_ptr + 1;
        } else if msg_byte_ptr < 64 {
            for j in 0..8 {
                msg_block[msg_byte_ptr + j] = len_bytes[j];
            }
            msg_byte_ptr += 8;
        }
    }
    msg_block
}

fn hash_final_block(msg_block: [u8; 64], mut state: [u32; 8]) -> [u8; 32] {
    let mut out_h: [u8; 32] = [0; 32]; // Digest as sequence of bytes

    // Hash final padded block
    state = sha256_compression(msg_u8_to_u32(msg_block), state);

    // Return final hash as byte array
    for j in 0..8 {
        let h_bytes = (state[7 - j] as Field).to_le_bytes(4);
        for k in 0..4 {
            out_h[31 - 4*j - k] = h_bytes[k];
        }
    }

    out_h
}

#[test]
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
    let state = partial_sha256_var(data0, data0.len());
    let hash = finish_sha256_var(state, data1, data1.len(), data.len());
    let correct_hash = std::hash::sha256_var(data, data.len() as u64);
    assert_eq(hash, correct_hash);
}
