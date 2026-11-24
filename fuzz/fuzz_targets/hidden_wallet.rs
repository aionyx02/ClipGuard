#![no_main]
//! Hidden characters, wallet addresses, pastejack comparison.
use libfuzzer_sys::fuzz_target;
use paste_warden_core::{hidden, pastejack, wallet};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = hidden::analyze(&text);
    for m in wallet::find_all(&text) {
        let _ = &m;
    }
    let _ = wallet::parse(&text);
    // Split the input into "selection" and "page-written" halves.
    let mid = text.len() / 2;
    let mid = (0..=mid).rev().find(|i| text.is_char_boundary(*i)).unwrap_or(0);
    let (a, b) = text.split_at(mid);
    let _ = pastejack::compare(a, b);
    let _ = pastejack::preview(&text, 80);
});
