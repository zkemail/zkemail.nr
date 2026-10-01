use crate::{
    hash::{poseidon_large, poseidon_large_padded_1024},
    KEY_LIMBS_1024,
    KEY_LIMBS_2048,
    RSA_EXPONENT,
};
use bignum::{params::BigNumParams, RuntimeBigNum};
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

    pub fn hash(self) -> [Field; 2] {
        // validate
        self.validate_in_range();
        [poseidon_large_padded_1024(self.modulus), poseidon_large_padded_1024(self.redc)]
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

    pub fn hash(self) -> [Field; 2] {
        // validate range
        self.validate_in_range();
        [poseidon_large(self.modulus), poseidon_large(self.redc)]
    }

    pub fn validate_in_range(self) {
        for i in 0..(KEY_LIMBS_2048 - 1) {
            self.modulus[i].assert_max_bit_size::<120>();
            self.redc[i].assert_max_bit_size::<120>();
        }
        self.modulus[KEY_LIMBS_2048 - 1].assert_max_bit_size::<2048 - ((KEY_LIMBS_2048 - 1) * 120)>();
        // REASON: poseidon_large (hash.nr) repacks the 18 x 120-bit limbs into 17 x 121-bit limbs,
        // i.e. it only hashes the low 17 x 121 - 17 x 120 = 17 bits of the top limb. With a 120-bit
        // bound here, bits 17..119 of redc[17] could be changed without changing hash()[1], which
        // undoes the redc binding added in #62. Do NOT loosen this back to 120 bits.
        // An honest redc is floor(2^(2 * 2048 + BARRETT_REDUCTION_OVERFLOW_BITS) / n) with n >= 2^2047:
        // at most 2,053 bits for overflow bits = 4 (noir-bignum v0.6) and 2,055 bits for overflow
        // bits = 6 (noir-bignum >= v0.9), i.e. <= 15 bits in this limb, so 17 bits never rejects a
        // valid key. Test: test_redc_top_limb_bits_outside_hash_are_rejected_2048.
        self.redc[KEY_LIMBS_2048 - 1].assert_max_bit_size::<17>();
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
