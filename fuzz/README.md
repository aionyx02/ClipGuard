# fuzz

`cargo-fuzz` targets for every public entry point of `paste-warden-core` that
takes clipboard text. Clipboard content is attacker-controlled, so the engine
must never panic, hang, or return out-of-bounds spans (CLAUDE.md red lines).

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run command -- -max_total_time=60
cargo +nightly fuzz run secret -- -max_total_time=60
cargo +nightly fuzz run hidden_wallet -- -max_total_time=60
cargo +nightly fuzz run policy -- -max_total_time=60
```

CI runs each target for 60 s (`.github/workflows/fuzz.yml`). Crashes land in
`fuzz/artifacts/<target>/`; turn each into a corpus case or unit test when fixed.
