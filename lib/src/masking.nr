/**
 * Byte masking for a header or body text
 * @dev uses fixed sized arrays for masks since saves constraints and shouldn't have security cost
 *
 * @param TEXT_LEN - The length of the text to mask
 * @param text - The text to mask
 * @param mask - The mask to apply to the text
 * @return - The masked text. Bytes at index >= text.len() are always 0, whatever the mask says
 */
pub fn mask_text<let TEXT_LEN: u32>(
    text: BoundedVec<u8, TEXT_LEN>,
    mask: [bool; TEXT_LEN],
) -> [u8; TEXT_LEN] {
    let mut masked_text = [0; TEXT_LEN];
    // REASON: bytes at index >= text.len() are BoundedVec padding. Nothing constrains them
    // (sha256_var and the DKIM check only read the first len bytes), so a prover can put any
    // bytes there. Without the `in_bounds` term they were output as if they were part of the
    // signed text whenever mask[i] was set. Do not drop it to save constraints.
    // NOTE: in_bounds is a flag cleared at i == text.len() rather than i < text.len(): one
    // equality per byte instead of a range comparison. It is the same value because
    // text.len() <= TEXT_LEN (if they are equal, every byte stays in bounds).
    let mut in_bounds = true;
    for i in 0..TEXT_LEN {
        if i == text.len() {
            in_bounds = false;
        }
        masked_text[i] = text.get_unchecked(i) * ((mask[i] & in_bounds) as u8);
    }
    masked_text
}
