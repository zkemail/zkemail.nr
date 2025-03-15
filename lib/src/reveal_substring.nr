use string_search::{StringBody, SubString};
use crate::Sequence;

global CHUNK_SIZE: u32 = 31;

type RevealBody<let MAX_LEN: u32> =  StringBody<((MAX_LEN + (CHUNK_SIZE - 1)) / CHUNK_SIZE) * CHUNK_SIZE, (((MAX_LEN + (CHUNK_SIZE - 1)) / CHUNK_SIZE) * CHUNK_SIZE) / 31, MAX_LEN>;
type RevealSubstring<let MAX_SUBSTR_LEN: u32> = SubString<((MAX_SUBSTR_LEN + (CHUNK_SIZE - 1)) / CHUNK_SIZE) * CHUNK_SIZE, ((((MAX_SUBSTR_LEN + (CHUNK_SIZE - 1)) / CHUNK_SIZE) * CHUNK_SIZE) / 31) - 1, MAX_SUBSTR_LEN>;

pub fn reveal_substring<let MAX_LEN: u32, let MAX_SUBSTR_LEN: u32>(
    mut text: BoundedVec<u8, MAX_LEN>,
    substr: BoundedVec<u8, MAX_SUBSTR_LEN>,
    should_check_uniqueness: bool,
) -> bool {
    assert(MAX_SUBSTR_LEN < MAX_LEN, "Substr length exceeds max length");

    let haystack: RevealBody<MAX_LEN> = StringBody::new(text.storage, text.len);
    let needle: RevealSubstring<MAX_SUBSTR_LEN> = SubString::new(substr.storage, substr.len);

    let (result, match_position): (bool, u32) = haystack.substring_match(needle);

    // 0 out the first substring. Cheaper if outside the conditional
    for i in 0..MAX_SUBSTR_LEN {
        let mut index = match_position + i;
        if i > substr.len {
            index = match_position;
        }
        text.set(index, 0);
    }

    if should_check_uniqueness {
        // repeat string search
        let zeroed_haystack: RevealBody<MAX_LEN> = StringBody::new(text.storage, text.len);
        let duplicate_result = zeroed_haystack.substring_match(needle).0;
        assert(duplicate_result == false, "Other occurence of substring found.");
    }
    result
}



pub fn reveal_substring_custom<let MAX_LEN: u32, let MAX_SUBSTR_LEN: u32>(
    text: [u8; MAX_LEN],
    substr_sequence: Sequence,
    should_check_uniqueness: bool
) -> BoundedVec<u8, MAX_SUBSTR_LEN> {

    assert(MAX_SUBSTR_LEN < MAX_LEN, "Substr length exceeds max length");
    
    let mut extracted_substring: [u8; MAX_SUBSTR_LEN] = [0; MAX_SUBSTR_LEN];

    for i in 0..MAX_SUBSTR_LEN {
        // let index = substr_start_index as u32 + i;
        // let mut value = text.get_unchecked(index);
        // if index > substr_sequence.end_index() {
        //     value = 0;
        // }
        let val = text[substr_sequence.index];
    }


    BoundedVec {
        storage: extracted_substring,
        len: substr_sequence.length
    }
}