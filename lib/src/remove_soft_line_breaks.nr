/**
 * Remove soft line breaks from the given text
 *
 * @param text The text to remove soft line breaks from
 */
pub fn remove_soft_line_breaks<let LENGTH: u32>(text: BoundedVec<u8, LENGTH>) -> BoundedVec<u8, LENGTH> {
    let mut result = BoundedVec::new();
    for i in 0..LENGTH {
        if i < text.len() {
            // check if 
        }
    }
}