use dep::zkemail::{
    KEY_LIMBS_2048, dkim::RSAPubkey,
    headers::{body_hash::get_body_hash, email_address::get_email_address}, standard_outputs, Sequence,
    MAX_EMAIL_ADDRESS_LENGTH
};
use dep::std::{collections::bounded_vec::BoundedVec, hash::sha256_var};

global MAX_EMAIL_HEADER_LENGTH: u32 = 512;
global MAX_EMAIL_BODY_LENGTH: u32 = 1024;

/**
 * Verify an arbitrary email signed by a 2048-bit RSA DKIM signature and extract sender and recipient addresses
 * @dev example of only constraining access to the header too
 *
 * @param header - The email header, 0-padded at end to the MAX_EMAIL_HEADER_LENGTH
 * @param pubkey - The DKIM RSA Public Key modulus and reduction parameter
 * @param signature - The DKIM RSA Signature
 * @param from_header_sequence - The index and length of the "From" header field
 * @param from_address_sequence - The index and length of the "From" email address
 * @param to_header_sequence - The index and length of the "To" header field
 * @param to_address_sequence - The index and length of the "To" email address
 * @return - 
 *         0: Pedersen hash of DKIM public key (root of trust)
 *         1: Pedersen hash of DKIM signature (email nullifier)
 */
fn main(
    header: BoundedVec<u8, MAX_EMAIL_HEADER_LENGTH>,
    pubkey: RSAPubkey<KEY_LIMBS_2048>,
    signature: [Field; KEY_LIMBS_2048],
    from_header_sequence: Sequence,
    from_address_sequence: Sequence,
    to_header_sequence: Sequence,
    to_address_sequence: Sequence
) -> pub ([Field; 2], BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>, BoundedVec<u8, MAX_EMAIL_ADDRESS_LENGTH>) {
    // check the body and header lengths are within bounds
    assert(header.len() <= MAX_EMAIL_HEADER_LENGTH);

    // verify the dkim signature over the header
    pubkey.verify_dkim_signature(header, signature);

    // extract to and from email addresses
    let from = comptime {
        "from".as_bytes()
    };
    let to = comptime {
        "to".as_bytes()
    };
    // 16k gate cost? has to be able to be brought down
    let from_address = get_email_address(header, from_header_sequence, from_address_sequence, from);
    let to_address = get_email_address(header, to_header_sequence, to_address_sequence, to);

    // hash the pubkey and signature for the standard outputs
    let standard_out = standard_outputs(pubkey.modulus, signature);
    (standard_out, from_address, to_address)
}
