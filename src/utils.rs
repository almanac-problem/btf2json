use std::collections::HashMap;

pub fn print_bytes(data: &[u8]) {
    for &b in data {
        if b.is_ascii_graphic() {
            print!("{}", b as char);
        } else {
            print!("\\x{:02x}", b);
        }
    }
    println!();
}

// LLM Generated Utility function
pub fn most_common<T: Eq + std::hash::Hash>(vec: Vec<T>) -> Option<T> {
    let mut counts = HashMap::new();

    for item in vec {
        *counts.entry(item).or_insert(0) += 1;
    }

    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(item, _)| item)
}
