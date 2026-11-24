#![no_main]
//! Pure policy helpers that parse or cut user / clipboard data.
use libfuzzer_sys::fuzz_target;
use paste_warden_core::limits;
use paste_warden_core::policy::paste::{PasteGuardSettings, normalize_app_name};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let p = limits::prefix(&text);
    assert!(text.starts_with(p));
    let _ = PasteGuardSettings::from_json(Some(&text));
    let _ = normalize_app_name(&text);
});
