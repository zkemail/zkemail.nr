pub fn mask_text<let N: u32>(text: [u8; N], mask: [bool; N]) -> [u8; N] {
    let mut masked_text: [u8; N] = [0; N];
    for i in 0..N {
        masked_text[i] = text[i] * mask[i] as u8;
    }
    masked_text
}