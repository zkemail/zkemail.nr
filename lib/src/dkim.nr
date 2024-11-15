use crate::{KEY_BYTES_1024, KEY_BYTES_2048, KEY_LIMBS_1024, KEY_LIMBS_2048, RSA_EXPONENT};
use dep::rsa::{bignum::{BigNum, fields::{Params1024, Params2048}, runtime_bignum::BigNumInstance}, types::RSA};
use dep::std::{collections::bounded_vec::BoundedVec, hash::{pedersen_hash, sha256_var}};

type BN1024 = BigNum<KEY_LIMBS_1024, Params1024>;
type RSA1024 = RSA<BN1024, BigNumInstance<KEY_LIMBS_1024, Params1024>, KEY_BYTES_1024>;
type BN2048 = BigNum<KEY_LIMBS_2048, Params2048>;
type RSA2048 = RSA<BN2048, BigNumInstance<KEY_LIMBS_2048, Params2048>, KEY_BYTES_2048>;

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
        // instantiate the BNInstance for the pubkey
        // todo: make as BigNumInstance from the outset to reduce some work
        let pubkey: BigNumInstance<KEY_LIMBS_1024, Params1024> = BigNumInstance::new(self.modulus, self.redc);

        // instantiate BN for the signature
        let signature: BN1024 = BigNum::from_array(signature);

        // verify the DKIM signature over the header
        let rsa: RSA1024 = RSA {};
        assert(rsa.verify_sha256_pkcs1v15(pubkey, header_hash, signature, RSA_EXPONENT));
    }
}

impl RSAPubkey<KEY_LIMBS_2048> {
    fn verify_dkim_signature<let MAX_HEADER_LENGTH: u32>(
        self,
        header: BoundedVec<u8, MAX_HEADER_LENGTH>,
        signature: [Field; KEY_LIMBS_2048]
    ) {
        // hash the header
        let header_hash = sha256_var(header.storage, header.len() as u64);
        // instantiate the BNInstance for the pubkey
        // todo: make as BigNumInstance from the outset to reduce some work
        let pubkey: BigNumInstance<KEY_LIMBS_2048, Params2048> = BigNumInstance::new(self.modulus, self.redc);

        // instantiate BN for the signature
        let signature: BN2048 = BigNum::from_array(signature);

        // verify the DKIM signature over the header
        let rsa: RSA2048 = RSA {};
        assert(rsa.verify_sha256_pkcs1v15(pubkey, header_hash, signature, RSA_EXPONENT));
    }
}
