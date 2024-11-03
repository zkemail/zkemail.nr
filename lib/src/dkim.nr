use crate::{KEY_LIMBS_1024, KEY_LIMBS_2048, RSA_EXPONENT};
use rsa::{
    bignum::{params::BigNumParams, runtime_bignum::RuntimeBigNum},
    types::{BN1024, BN2048, RSA, RSA1024, RSA2048},
};
use std::hash::{pedersen_hash, sha256_var};

pub struct RSAPubkey<let KEY_LIMBS: u32> {
    modulus: [Field; KEY_LIMBS],
    redc: [Field; KEY_LIMBS],
}

impl<let KEY_LIMBS: u32> RSAPubkey<KEY_LIMBS> {
    fn hash(self) -> Field {
        pedersen_hash(self.modulus)
    }
}

impl RSAPubkey<KEY_LIMBS_1024> {
    fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_1024],
    ) {
        // hash the header
        let header_hash = sha256_var(header.storage, header.len() as u64);

        // instantiate the pubkey as bn params
        // todo: instantiate outside of circuit
        let pubkey_params = BigNumParams::new(false, self.modulus, self.redc);

        // instantiate BN for the signature
        let signature_bn: BN1024 = RuntimeBigNum::from_array(pubkey_params, signature);

        // verify the DKIM signature over the header
        let rsa: RSA1024 = RSA {};
        assert(rsa.verify_sha256_pkcs1v15(header_hash, signature_bn, RSA_EXPONENT));
    }
}

impl RSAPubkey<KEY_LIMBS_2048> {
    fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_2048],
    ) {
        // hash the header
        let header_hash = sha256_var(header.storage, header.len() as u64);
        // instantiate the BNInstance for the pubkey
        // todo: make as BigNumInstance from the outset to reduce some work
        let pubkey_params = BigNumParams::new(false, self.modulus, self.redc);

        // instantiate BN for the signature
        let signature_bn: BN2048 = RuntimeBigNum::from_array(pubkey_params, signature);

        // verify the DKIM signature over the header
        let rsa: RSA2048 = RSA {};
        assert(rsa.verify_sha256_pkcs1v15(header_hash, signature_bn, RSA_EXPONENT));
    }
}
