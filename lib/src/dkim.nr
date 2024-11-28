use std::hash::{sha256_var, pedersen_hash};
use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::{rsa::verify_sha256_pkcs1v15, types::{RBN1024, RBN2048}};
use crate::{KEY_LIMBS_1024, KEY_LIMBS_2048, RSA_EXPONENT};

pub struct RSAPubkey<let KEY_LIMBS: u32> {
    modulus: [Field; KEY_LIMBS],
    redc: [Field; KEY_LIMBS],
}

impl<let KEY_LIMBS: u32> RSAPubkey<KEY_LIMBS> {

    pub fn new(modulus: [Field; KEY_LIMBS], redc: [Field; KEY_LIMBS]) -> Self {
        Self { modulus, redc }
    }
}

impl RSAPubkey<KEY_LIMBS_1024> {
    pub fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_1024],
    ) {
        // hash the header
        let header_hash = sha256_var(header.storage(), header.len() as u64);

        let params: BigNumParams<KEY_LIMBS_1024, 1024> =
            BigNumParams::new(false, self.modulus, self.redc);

        let signature: RBN1024 = RuntimeBigNum::from_array(params, signature);

        // verify the DKIM signature over the header
        assert(verify_sha256_pkcs1v15(header_hash, signature, RSA_EXPONENT));
    }

    pub fn hash(self) -> Field {
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
        pedersen_hash(dkim_preimage)
    }
}

impl RSAPubkey<KEY_LIMBS_2048> {
    pub fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_2048],
    ) {
        // hash the header
        let header_hash = sha256_var(header.storage(), header.len() as u64);

        let params: BigNumParams<KEY_LIMBS_2048, 2048> =
            BigNumParams::new(false, self.modulus, self.redc);

        let signature: RBN2048 = RuntimeBigNum::from_array(params, signature);

        // verify the DKIM signature over the header
        assert(verify_sha256_pkcs1v15(header_hash, signature, RSA_EXPONENT));
    }

    pub fn hash(self) -> Field {
        let mut dkim_preimage = [0; 18];
        // compose limbs
        for i in 0..18 {
            let modulus_hi = self.modulus[i * 2] * 2.pow_32(120);
            let redc_hi = self.redc[i * 2] * 2.pow_32(120);
            dkim_preimage[i] = modulus_hi + self.modulus[i * 2 + 1];
            dkim_preimage[i + 9] = redc_hi + self.redc[i * 2 + 1];
        }
        // hash the pubkey
        pedersen_hash(dkim_preimage)
    }
}
