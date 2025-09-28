use crate::{KEY_LIMBS_1024, KEY_LIMBS_2048, RSA_EXPONENT};
use bignum::{params::BigNumParams, RuntimeBigNum};
use poseidon::poseidon;
use rsa::{rsa::verify_sha256_pkcs1v15, types::{RBN1024, RBN2048}};
use sha256::sha256_var;

pub struct RSAPubkey<let KEY_LIMBS: u32> {
    modulus: [Field; KEY_LIMBS],
    redc: [Field; KEY_LIMBS],
}

impl<let KEY_LIMBS: u32> RSAPubkey<KEY_LIMBS> {

    pub fn new(modulus: [Field; KEY_LIMBS], redc: [Field; KEY_LIMBS]) -> Self {
        let pubkey = Self { modulus, redc };
        pubkey
    }
}

impl RSAPubkey<KEY_LIMBS_1024> {
    pub fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_1024],
    ) -> [u8; 32] {
        // hash the header
        let header_hash = sha256_var(header.storage(), header.len() as u64);

        let params: BigNumParams<KEY_LIMBS_1024, 1024> = BigNumParams::new(
            false,
            convert_field_to_u128(self.modulus),
            convert_field_to_u128(self.redc),
        );

        let signature: RBN1024 =
            RuntimeBigNum::from_array(params, convert_field_to_u128(signature));
        signature.validate_in_range();

        // verify the DKIM signature over the header
        assert(verify_sha256_pkcs1v15(header_hash, signature, RSA_EXPONENT));

        header_hash
    }

    pub fn hash(self) -> Field {
        // validate
        self.validate_in_range();
        let mut dkim_preimage = [0; 9];
        // compose first 4 limbs of modulus and redc
        for i in 0..4 {
            let modulus_hi = self.modulus[i * 2] * 2.pow_32(120);
            let redc_hi = self.redc[i * 2] * 2.pow_32(120);
            dkim_preimage[i] = modulus_hi + self.modulus[i * 2 + 1];
            dkim_preimage[i + 4] = redc_hi + self.redc[i * 2 + 1];
        }
        // compose last two elements of redc and modulus together
        let modulus_hi = self.modulus[8] * 2.pow_32(120);
        dkim_preimage[8] = modulus_hi + self.redc[8];
        // hash the pubkey
        poseidon::bn254::hash_9(dkim_preimage)
    }

    pub fn validate_in_range(self) {
        for i in 0..(KEY_LIMBS_1024 - 1) {
            self.modulus[i].assert_max_bit_size::<120>();
            self.redc[i].assert_max_bit_size::<120>();
        }
        self.modulus[KEY_LIMBS_1024 - 1].assert_max_bit_size::<1024 - ((KEY_LIMBS_1024 - 1) * 120)>();
        self.redc[KEY_LIMBS_1024 - 1].assert_max_bit_size::<120>();
    }
}

impl RSAPubkey<KEY_LIMBS_2048> {
    pub fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_2048],
    ) -> [u8; 32] {
        // hash the header
        let header_hash = sha256_var(header.storage(), header.len() as u64);

        let params: BigNumParams<KEY_LIMBS_2048, 2048> = BigNumParams::new(
            false,
            convert_field_to_u128(self.modulus),
            convert_field_to_u128(self.redc),
        );

        let signature: RBN2048 =
            RuntimeBigNum::from_array(params, convert_field_to_u128(signature));
        signature.validate_in_range();

        // verify the DKIM signature over the header
        assert(verify_sha256_pkcs1v15(header_hash, signature, RSA_EXPONENT));

        header_hash
    }

    // compatible with https://github.com/zkemail/zk-email-verify/blob/62dd54871857697a6f2fb9c0a8ea72e38c7eb293/packages/circuits/utils/hash.circom#L15
    pub fn hash(self) -> Field {
        // validate range
        self.validate_in_range();
        // Build 17 contiguous 121-bit chunks from the 18 x 120-bit limbs
        let chunks_121 = modulus_limbs_to_chunks_121(self.modulus);

        // Merge pairs per PoseidonLarge template (17 -> 9 inputs)
        let poseidon_input = merge_chunks_121_for_poseidon(chunks_121);

        poseidon::bn254::hash_9(poseidon_input)
    }

    pub fn validate_in_range(self) {
        for i in 0..(KEY_LIMBS_2048 - 1) {
            self.modulus[i].assert_max_bit_size::<120>();
            self.redc[i].assert_max_bit_size::<120>();
        }
        self.modulus[KEY_LIMBS_2048 - 1].assert_max_bit_size::<2048 - ((KEY_LIMBS_2048 - 1) * 120)>();
        self.redc[KEY_LIMBS_2048 - 1].assert_max_bit_size::<120>(); // we get 2053 sometimes?
    }
}

// convert a Field array to a u128 array with generic number of limbs
fn convert_field_to_u128<let KEY_LIMBS: u32>(signature: [Field; KEY_LIMBS]) -> [u128; KEY_LIMBS] {
    let mut u128_signature: [u128; KEY_LIMBS] = [0; KEY_LIMBS];
    for i in 0..KEY_LIMBS {
        u128_signature[i] = signature[i] as u128;
    }
    u128_signature
}

// Compute 2^n as u128 (n is small: <= 121)
fn pow2_u128(n: u32) -> u128 {
    let mut result: u128 = 1;
    for _ in 0..n {
        result = result * 2;
    }
    result
}

// Build 17 contiguous 121-bit chunks from 18 x 120-bit limbs (little-endian)
fn modulus_limbs_to_chunks_121(modulus: [Field; KEY_LIMBS_2048]) -> [Field; 17] {
    let mut chunks_121 = [0; 17];
    for j in 0..17 {
        let a0: u128 = modulus[j] as u128;
        let a1: u128 = if j + 1 < KEY_LIMBS_2048 {
            modulus[j + 1] as u128
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

        chunks_121[j] = (lower + high) as Field;
    }
    chunks_121
}

// Merge 17 x 121-bit chunks into 9 Poseidon inputs as per PoseidonLarge
fn merge_chunks_121_for_poseidon(chunks_121: [Field; 17]) -> [Field; 9] {
    let base_121 = 2.pow_32(121);
    let mut input = [0; 9];
    for i in 0..9 {
        if i == 8 {
            input[i] = chunks_121[16];
        } else {
            input[i] = chunks_121[2 * i] + base_121 * chunks_121[2 * i + 1];
        }
    }
    input
}
