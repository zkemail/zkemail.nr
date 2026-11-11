use crate::{
    BODY_HASH_BASE64_LENGTH, headers::constrain_header_field, MAX_DKIM_HEADER_FIELD_LENGTH,
    Sequence,
};
use base64::BASE64_DECODER;

// ON DKIM-SIGNATURE PARSING:
// In the current version, DKIM-SIGNATURE tags are mostly ignored:
// c= is ignored, meaning we assume the canonicalization is relaxed. This can cause denial of service issues
// v= is ignored, meaning we do not check for a valid version of dkim signing
// l= is ignored, meaning we otherwise constrain the body length to be safe
// x= is ignored, meaning we accept signatures without expiration
// sdid= is ignored, meaning that we don't explicitly bind dkim keys to exact signing domains
// See line 42 of this file for parsing bh=;
// You will need to implement your own parsing for the tags' expected values

/**
 * Constrained access to the body hash in the header
 * 
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header as validated in the DKIM signature
 * @param dkim_header_field_sequence - The sequence of the DKIM header field
 * @param body_hash_index - The index of the body hash in the header
 */
pub fn get_body_hash<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    dkim_header_field_sequence: Sequence,
    body_hash_index: u32,
) -> [u8; 32] {
    // constrain the access of dkim signature field
    let header_field_name: [u8; 14] = comptime { "dkim-signature".as_bytes() };
    constrain_header_field::<MAX_HEADER_LENGTH, MAX_DKIM_HEADER_FIELD_LENGTH, 14>(
        header,
        dkim_header_field_sequence,
        header_field_name,
    );
    // REASON: the DKIM-Signature being verified is always the LAST field of the signed header:
    // RFC 6376 s3.7 appends it, canonicalized and with b= emptied, after the h= fields and without a
    // trailing CRLF (helpers' mailauth builds the buffer the same way). Other DKIM-Signature fields
    // can only appear earlier, when listed in h= (e.g. a second d=*.gappssmtp.com or ESP
    // signature). Their bh= was computed for their own c= / l= tags, not for the verified signature,
    // so it must not be usable here. Requiring the field to end the header pins it to the verified
    // signature; it never rejects an honestly generated input.
    assert(
        dkim_header_field_sequence.end_index() == header.len(),
        "DKIM-Signature field must be the last header field",
    );
    // constrain access to the body hash
    let start_range = body_hash_index > dkim_header_field_sequence.index;
    // The terminating ';' at index + 44 must also be inside the authenticated field. The storage
    // array may contain arbitrary bytes after header.len(), including a forged terminator.
    let end_range =
        body_hash_index + BODY_HASH_BASE64_LENGTH < dkim_header_field_sequence.end_index();
    assert(start_range & end_range, "Body hash index accessed outside of DKIM header field");

    // check bh prefix: "bh=" must start a tag, i.e. follow the field's ':' or a tag-separating ';',
    // optionally with one space or a fold (CRLF + SP/HTAB, kept by c=simple canonicalization).
    // NOTE: the 7 bytes before the value are read once. Every accepted form ends in "bh=", and
    // the bytes before it are compared as packed Fields (bytes are < 256, so packing is
    // injective): one equality per form instead of one per byte.
    // NOTE: these 7 bytes can't start before the field: "bh=" can't overlap the 15-byte
    // "dkim-signature:" name (checked above), so body_hash_index - 7 >= field index + 11. A
    // body_hash_index too small for the subtraction makes the circuit fail, never pass.
    let mut b: [Field; 7] = [0; 7];
    for i in 0..7 {
        b[i] = header.get_unchecked(body_hash_index - 7 + i) as Field;
    }
    let ends_with_bh = b[4] * 0x10000 + b[5] * 0x100 + b[6] == 0x62683d; // "bh="
    let sep2 = b[2] * 0x100 + b[3];
    // REASON: ":bh=" / ": bh=" only mean "first tag" right after the "dkim-signature:" name.
    // ':' is legal inside tag values: z= copies sender-controlled header fields as "Name:value"
    // with '=' escaped as "=3D", so a copied "Date:bh..." reads "e:bh=3D..." mid-field, and the
    // unanchored 5-byte check matched it. NOTE: defense in depth. A real z= value can't end its 44
    // bytes with the literal '=' padding the base64 decoder requires followed by ';', so this was
    // not reachable end to end; the anchor makes the check mean what it says. The two forms are
    // also matched as separate flags: OR-ing them per byte accepted mixes such as "::bh=".
    // The byte before ":bh=" is the last byte of the name, already matched case-insensitively
    // (c=simple keeps e.g. "DKIM-SIGNATURE:bh="), so it is not compared again.
    let name_end = dkim_header_field_sequence.index + 15; // "dkim-signature:" is 15 bytes
    let found_first = ((b[3] == 0x3a) & (body_hash_index == name_end + 3)) // ":bh="
        | ((sep2 == 0x3a20) & (body_hash_index == name_end + 4)); // ": bh="
    // "; bh=" and ";bh="
    let found_subsequent = (sep2 == 0x3b20) | (b[3] == 0x3b);
    // ";\r\n\tbh=" / ";\r\n bh=" (folded after the separator)
    let found_folded =
        (b[0] * 0x10000 + b[1] * 0x100 + b[2] == 0x3b0d0a) & ((b[3] - 0x20) * (b[3] - 0x09) == 0);
    assert(
        ends_with_bh & (found_first | found_subsequent | found_folded),
        "No ':bh=' or '; bh=' prefix found before body hash",
    );

    // check that bh is followed by ;
    let bh_suffix: u8 = comptime { ";".as_bytes()[0] };
    assert(
        header.get_unchecked(body_hash_index + BODY_HASH_BASE64_LENGTH) == bh_suffix,
        "No ';' suffix found at asserted bh index",
    );
    // get the body hash
    get_body_hash_unsafe(header, body_hash_index)
}

/**
 * Get the body hash from the header without validating the access index. Does not validate body
 * hash is valid base64 sequence (https://github.com/noir-lang/noir_base64/blob/4431d08ac661ada9d8d18b115487ff0190b43856/src/lib.nr#L209-L232)
 *
 * @param MAX_HEADER_LENGTH - The maximum length of the email header
 * @param header - The email header as validated in the DKIM signature
 * @param body_hash_index - The asserted index to find the body hash at
 */
pub fn get_body_hash_unsafe<let MAX_HEADER_LENGTH: u32>(
    header: BoundedVec<u8, MAX_HEADER_LENGTH>,
    body_hash_index: u32,
) -> [u8; 32] {
    // get the body hash
    let mut body_hash_encoded: [u8; BODY_HASH_BASE64_LENGTH] = [0; BODY_HASH_BASE64_LENGTH];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        body_hash_encoded[i] = header.get_unchecked(body_hash_index + i);
    }
    // return the decoded body hash
    // idk why encode vs decode...
    BASE64_DECODER::decode(body_hash_encoded)
}
