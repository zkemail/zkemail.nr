use dep::zkemail::{standard_outputs, KEY_LIMBS_2048};

pub fn serialize_output(
    sha256_state: [u32; 8],
    final_hash: [u8; 32],
    pubkey: [Field; KEY_LIMBS_2048],
    signature: [Field; KEY_LIMBS_2048]
) -> [Field; 7] {
    let serialized_final_hash: [Field; 2] = serialize_bytes(final_hash);
    let serialized_sha256_state: [Field; 3] = serialize_u32(sha256_state);
    let standard_outputs = standard_outputs(pubkey, signature);
    [
        standard_outputs[0], standard_outputs[1],
        serialized_sha256_state[0], serialized_sha256_state[1], serialized_sha256_state[2],
        serialized_final_hash[0], serialized_final_hash[1]
    ]
}

pub fn serialize_u32<let LIMBS: u32, let SEQUENCE_LENGTH: u32>(sequence: [u32; SEQUENCE_LENGTH]) -> [Field; LIMBS] {
     let mut limbs: [Field; LIMBS] = [0; LIMBS];

    for i in 0..LIMBS {
        let mut chunk = 0;
        let mut v = 1;
        for j in 0..3 {
            let index = i * 3 + j;
            if index < SEQUENCE_LENGTH {
                chunk += sequence[index] as Field * v;
                v *= 2.pow_32(32); // 2^32 is used as the base to shift 4 bytes for each u32 value.
            }
        }
        limbs[i] = chunk;
    }

    limbs
}

pub fn serialize_bytes<let LIMBS: u32, let SEQUENCE_LENGTH: u32>(sequence: [u8; SEQUENCE_LENGTH]) -> [Field; LIMBS] {
    let mut limbs: [Field; LIMBS] = [0; LIMBS];
    for i in 0..LIMBS {
        let mut chunk = 0;
        let mut v = 1;
        for j in 0..31 {
            let index = i * 31 + j;
            if index < SEQUENCE_LENGTH {
                chunk += sequence[index] as Field * v;
                v *= 256;
            }
        }
        limbs[i] = chunk;
    }
    limbs
}