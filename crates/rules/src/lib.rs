//! Rule files (`rules/`): formats, loading, validation and compilation.
//!
//! Detection data lives in `rules/` so it can be reviewed, signed and patched
//! (by humans or the blue-team agent) without touching engine code.
//! - [`secret`]: `rules/*.json` secret rules (API keys, PII packs), format 1 (see
//!   docs/spec/detection-rules.md §5.4).
//! - [`command`]: command-detection data (known programs, official installer hosts,
//!   bait keywords, LOLBin specs) in `rules/command/`.
#![forbid(unsafe_code)]

pub mod command;
pub mod secret;
