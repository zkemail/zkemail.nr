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
    // probably fine to just iterate through whole thing without an if statement
    for i in 0..TEXT_LEN {
        masked_text[i] = (text.get_unchecked(i) * mask[i] as u8);
    }
    masked_text
}
