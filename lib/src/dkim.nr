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
    pub(crate) modulus: [Field; KEY_LIMBS],
    pub(crate) redc: [Field; KEY_LIMBS],
}

impl<let KEY_LIMBS: u32> RSAPubkey<KEY_LIMBS> {

    pub fn new(modulus: [Field; KEY_LIMBS], redc: [Field; KEY_LIMBS]) -> Self {
        let pubkey = Self { modulus, redc };
        pubkey
    }

    // the signature as a BigNum under this key, required to be less than the modulus
    fn signature_bignum<let MOD_BITS: u32>(
        self,
        signature: [Field; KEY_LIMBS],
    ) -> RuntimeBigNum<KEY_LIMBS, MOD_BITS> {
        let params: BigNumParams<KEY_LIMBS, MOD_BITS> = BigNumParams::new(
            false,
            convert_field_to_u128(self.modulus),
            convert_field_to_u128(self.redc),
        );

        let signature = RuntimeBigNum::from_array(params, convert_field_to_u128(signature));
        signature.validate_in_field();
        signature
    }
}

impl RSAPubkey<KEY_LIMBS_1024> {
    pub fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_1024],
    ) -> [u8; 32] {
        // hash the header
        let header_hash = sha256_var(header.storage(), header.len());

        // verify the DKIM signature over the header
        self.verify_digest_sha256_pkcs1v15(header_hash, signature)
    }

    /// Verify a PKCS#1 v1.5 SHA-256 signature over a precomputed digest. The caller must
    /// constrain the digest to the signed message.
    pub fn verify_digest_sha256_pkcs1v15(
        self,
        digest: [u8; 32],
        signature: [Field; KEY_LIMBS_1024],
    ) -> [u8; 32] {
        let signature: RBN1024 = self.signature_bignum(signature);
        assert(verify_sha256_pkcs1v15(digest, signature, RSA_EXPONENT));
        digest
    }

    /// Returns [modulus hash, redc hash]. Only the modulus hash identifies the key: BigNum uses
    /// redc only to compute witnesses and never checks it against the modulus.
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
        let header_hash = sha256_var(header.storage(), header.len());

        // verify the DKIM signature over the header
        self.verify_digest_sha256_pkcs1v15(header_hash, signature)
    }

    /// Verify a PKCS#1 v1.5 SHA-256 signature over a precomputed digest. The caller must
    /// constrain the digest to the signed message.
    pub fn verify_digest_sha256_pkcs1v15(
        self,
        digest: [u8; 32],
        signature: [Field; KEY_LIMBS_2048],
    ) -> [u8; 32] {
        let signature: RBN2048 = self.signature_bignum(signature);
        assert(verify_sha256_pkcs1v15(digest, signature, RSA_EXPONENT));
        digest
    }

    /// Returns [modulus hash, redc hash]. Only the modulus hash identifies the key: BigNum uses
    /// redc only to compute witnesses and never checks it against the modulus.
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
        // poseidon_large repacks the 18 x 120-bit limbs into 17 x 121-bit limbs, so it hashes only
        // the low 17 bits of the top limb. With a 120-bit bound, bits 17..119 of redc[17] could
        // change without changing hash()[1]. An honest redc, floor(2^(2 * 2048 + 6) / n) with
        // n >= 2^2047, has at most 2055 bits, i.e. at most 15 bits in this limb.
        self.redc[KEY_LIMBS_2048 - 1].assert_max_bit_size::<17>();
    }
}

// convert a Field array to a u128 array with generic number of limbs
fn convert_field_to_u128<let KEY_LIMBS: u32>(signature: [Field; KEY_LIMBS]) -> [u128; KEY_LIMBS] {
    let mut u128_signature: [u128; KEY_LIMBS] = [0; KEY_LIMBS];
    for i in 0..KEY_LIMBS {
        u128_signature[i] = signature[i] as u128;
        assert(u128_signature[i] as Field == signature[i], "Limb does not fit in u128");
    }
    u128_signature
}
