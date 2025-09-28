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

    pub fn hash(self) -> Field {
        // validate range
        self.validate_in_range();

        // Reconstruct the modulus as 17 chunks of 121 bits (little-endian in chunks)
        // Each 121-bit chunk c_j pulls lower (120 - j) bits from limb j (shifted right by j)
        // and upper (1 + j) bits from limb j+1 (shifted left by 120 - j).
        // This exactly partitions the 2048-bit modulus across 17 x 121-bit chunks.
        let mut chunks_121 = [0; 17];
        for j in 0..17 {
            let a0: u128 = self.modulus[j] as u128;
            let a1: u128 = if j + 1 < KEY_LIMBS_2048 {
                self.modulus[j + 1] as u128
            } else {
                0
            };

            let shift_j: u32 = j;
            let lower: u128 = a0 >> (shift_j as u8); // take lower (120 - j) bits contribution

            let width_next: u32 = 1 + j; // bits taken from next limb
            let high_mask: u128 = ((1 as u128) << (width_next as u8)) - (1 as u128);
            let take_from_next: u128 = a1 & high_mask; // at most 17 bits

            let left_shift: u32 = 120 - j; // place into high bits of the 121-bit chunk
            let high: u128 = take_from_next << (left_shift as u8);

            let chunk_val: u128 = lower + high; // fits within 121 bits
            chunks_121[j] = chunk_val as Field;
        }

        // Merge pairs per PoseidonLarge template with bitsPerChunk = 121 and chunkSize = 17
        // poseidonInput has size ceil(17 / 2) = 9
        let base_121 = 2.pow_32(121);
        let mut poseidon_input = [0; 9];
        for i in 0..9 {
            if i == 8 {
                // last odd element
                poseidon_input[i] = chunks_121[16];
            } else {
                poseidon_input[i] = chunks_121[2 * i] + base_121 * chunks_121[2 * i + 1];
            }
        }

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
