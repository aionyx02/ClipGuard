//! The workspace trims `regex` features for WASM size (phase-2.md §2.6). Some
//! engine patterns are compiled with `Regex::new(..).ok()` and would silently
//! disable a check if a Unicode feature went missing, so assert every Unicode
//! class the engine relies on still compiles.

#[test]
fn unicode_classes_used_by_the_engine_compile() {
    for pattern in [
        r"\A\p{L}\z",
        r"\A\p{P}\z",
        r"\A\p{M}\z",
        r"\A[\p{Lo}\p{Mn}\p{Mc}\p{Me}]\z",
        r"[\p{L}&&[\x{0}-\x{FFFF}]]+",
        r"(?i)powershell",
        r"\w+\s\d",
    ] {
        assert!(regex::Regex::new(pattern).is_ok(), "{pattern} no longer compiles");
    }
}
