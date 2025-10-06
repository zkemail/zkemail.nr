use crate::KEY_LIMBS_2048;
use poseidon::poseidon;

// Hash 18 x 120-bit limbs into a single Field - compatible with https://github.com/zkemail/zk-email-verify/blob/62dd54871857697a6f2fb9c0a8ea72e38c7eb293/packages/circuits/utils/hash.circom#L15
pub fn poseidon_large(limbs120x18: [Field; KEY_LIMBS_2048]) -> Field {
    let limbs121x17 = limbs120x18_to_limbs121x17(limbs120x18);
    let poseidon_input = fold_limbs121(limbs121x17);
    poseidon::bn254::hash_9(poseidon_input)
}

// Compute 2^n as u128 (n is small: <= 121)
fn pow2_u128(n: u32) -> u128 {
    let mut result: u128 = 1;
    for _ in 0..n {
        result = result * 2;
    }
    result
}

// Build 17 contiguous 121-bit limbs from 18 x 120-bit limbs (little-endian)
pub fn limbs120x18_to_limbs121x17(limbs120x18: [Field; KEY_LIMBS_2048]) -> [Field; 17] {
    let mut limbs121x17 = [0; 17];
    for j in 0..17 {
        let a0: u128 = limbs120x18[j] as u128;
        let a1: u128 = if j + 1 < KEY_LIMBS_2048 {
            limbs120x18[j + 1] as u128
        } else {
            0
        };

        // Compute lower contribution: a0 >> j  => a0 / 2^j
        let lower: u128 = a0 / pow2_u128(j);

        // Mask for (1 + j) bits from next limb: (2^(1+j)) - 1
        let high_mask: u128 = pow2_u128(1 + j) - 1;
        let take_from_next: u128 = a1 & high_mask;

        // Left shift by (120 - j): multiply by 2^(120 - j)
        let high: u128 = take_from_next * pow2_u128(120 - j);

        limbs121x17[j] = (lower + high) as Field;
    }
    limbs121x17
}

// Fold K x 121-bit limbs into K_out Poseidon inputs
pub fn fold_limbs121<let K: u32, let K_out: u32>(limbs121: [Field; K]) -> [Field; K_out] {
    assert(K >= 2, "K must be >= 2");
    assert(K_out >= 1, "K_out must be >= 1");
    assert(K_out <= K, "K_out must be <= K");

    let base_121 = 2.pow_32(121);
    let mut input = [0; K_out];
    for i in 0..K_out {
        if i == K_out - 1 {
            input[i] = limbs121[K - 1];
        } else {
            input[i] = limbs121[2 * i] + base_121 * limbs121[2 * i + 1]; // 2 * i + 1 < K
        }
    }
    input
}
