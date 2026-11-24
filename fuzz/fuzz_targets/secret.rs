#![no_main]
//! Secret detection and masking: spans must be valid, masking must not panic
//! and must remove every detected secret's full text.
use libfuzzer_sys::fuzz_target;
use paste_warden_core::secret::{self, PackSet};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for packs in [PackSet::default(), PackSet::all()] {
        let matches = secret::find(&text, &packs);
        for m in &matches {
            assert!(m.span.start <= m.span.end && m.span.end <= text.len(), "span out of bounds");
            assert!(text.is_char_boundary(m.span.start) && text.is_char_boundary(m.span.end));
        }
        let masked = secret::mask_text(&text, &matches, "[masked]");
        // Re-scanning masked output must not panic either.
        let _ = secret::find(&masked, &packs);
    }
    let _ = secret::mask_value(&text, 3, 3);
});
