use dep::std::{collections::bounded_vec::BoundedVec, hash::{sha256_var, pedersen_hash}, panic::panic};
use dep::bignum::{params::BigNumParams, RuntimeBigNum};
use dep::rsa::{rsa::verify_sha256_pkcs1v15, types::{RBN1024, RBN2048}};
use crate::{KEY_LIMBS_1024, KEY_LIMBS_2048, RSA_EXPONENT};


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
        signature: [Field; KEY_LIMBS_1024]
    ) {
        // hash the header
        let header_hash = sha256_var(header.storage, header.len() as u64);

        let params: BigNumParams<KEY_LIMBS_1024, 1024> =
            BigNumParams::new(false, self.modulus, self.redc);

        let signature: RBN1024 = RuntimeBigNum::from_array(params, signature);

        // verify the DKIM signature over the header
        assert(verify_sha256_pkcs1v15(header_hash, signature, RSA_EXPONENT));
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

        let params: BigNumParams<KEY_LIMBS_2048, 2048> =
            BigNumParams::new(false, self.modulus, self.redc);

        let signature: RBN2048 = RuntimeBigNum::from_array(params, signature);

        // verify the DKIM signature over the header
        assert(verify_sha256_pkcs1v15(header_hash, signature, RSA_EXPONENT));
    }
}