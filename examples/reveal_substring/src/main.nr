use zkemail::Sequence;

global MAX_LEN: u32 = 16000;
global MAX_SUBSTR_LEN: u32 = 13;

// fn main(haystack: BoundedVec<u8, MAX_LEN>, needle: BoundedVec<u8, MAX_SUBSTR_LEN>, should_check_uniqueness: bool) {
//     let found = reveal_substring::<MAX_LEN, MAX_SUBSTR_LEN>(haystack, needle, should_check_uniqueness);
//     assert(found == true);
// }

fn main(
    haystack: BoundedVec<u8, MAX_LEN>,
    substr: BoundedVec<u8, MAX_SUBSTR_LEN>,
    substr_sequence: Sequence,
    should_check_uniqueness: bool,
) {
    // let found = reveal_substring_custom::<MAX_LEN, MAX_SUBSTR_LEN>(haystack.storage, substr_sequence, should_check_uniqueness);
    // assert(true == substr);
}

#[test]
fn test_simple_substr() {
    let haystack_text = "the quick brown fox jumped over the lazy dog".as_bytes();
    let substring = " the lazy dog".as_bytes();

    let mut haystack_padded: [u8; MAX_LEN] = [0; MAX_LEN];
    for i in 0..44 {
        haystack_padded[i] = haystack_text[i];
    }

    let mut substring_padded: [u8; MAX_SUBSTR_LEN] = [0; MAX_SUBSTR_LEN];
    for i in 0..13 {
        substring_padded[i] = substring_padded[i];
    }

    let substr_sequence = Sequence { index: 36, length: substring.len() };

    let haystack_vec = BoundedVec { storage: haystack_padded, len: haystack_text.len() };

    let substr_vec = BoundedVec { storage: substring_padded, len: substring.len() };

    // main(haystack_vec, needle_vec, true);
    main(haystack_vec, substr_vec, substr_sequence, false);
}
