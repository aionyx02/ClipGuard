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
    let d = command::deobfuscate(&text);
    assert!(d.layers.len() <= 64, "too many deobfuscation steps");
    let _ = command::analyze_in(&text, &paste_warden_core::Context::default());
    for host in command::download_hosts(&text) {
        let _ = command::is_official_host(&host);
    }
});
