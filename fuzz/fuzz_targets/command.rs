#![no_main]
//! Command detection: analyze, normalize, explain, decode, host extraction.
use libfuzzer_sys::fuzz_target;
use paste_warden_core::command;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = command::analyze(&text);
    let normalized = command::normalize(&text);
    // Normalization is a pure function of its input.
    assert_eq!(normalized, command::normalize(&text));
    let _ = command::explain(&text);
    let _ = command::decode_encoded(&text);
    for host in command::download_hosts(&text) {
        let _ = command::is_official_host(&host);
    }
});
