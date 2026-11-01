/**
 * Byte masking for a header or body text
 * @dev uses fixed sized arrays for masks since saves constraints and shouldn't have security cost
 *
 * @param TEXT_LEN - The length of the text to mask
 * @param text - The text to mask
 * @param mask - The mask to apply to the text
 * @return - The masked text
 */
pub fn mask_text<let TEXT_LEN: u32>(
    text: BoundedVec<u8, TEXT_LEN>,
    mask: [bool; TEXT_LEN],
) -> [u8; TEXT_LEN] {
    let mut masked_text = [0; TEXT_LEN];
    // bytes past text.len() are not covered by the signature, so never reveal them. Track this
    // with a flag cleared at text.len(), which is cheaper than comparing i < text.len()
    let mut active = true;
    for i in 0..TEXT_LEN {
        if i == text.len() {
            active = false;
        }
        masked_text[i] = text.get_unchecked(i) * (mask[i] & active) as u8;
    }
    masked_text
}
