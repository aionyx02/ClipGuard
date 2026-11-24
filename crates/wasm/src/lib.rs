//! WASM wrapper around paste-warden-core for browsers, extensions and
//! userscripts (docs/plan/phase-2.md §2.6), plus the shared string API the
//! Python binding reuses.
//!
//! - [`api`] (= crate `paste-warden-report`): safe, string-in / string-out implementation (Report JSON §2.2,
//!   UTF-8 → UTF-16 span conversion, masking, `ui-*` messages).
//! - `bindgen` (default feature): wasm-bindgen exports for the main `.wasm` build.
//! - `raw` (`raw-abi` feature): C-ABI exports for the wasm2js fallback (S2:
//!   wasm-bindgen's externref output cannot be converted by wasm2js).
//!
//! `unsafe` is denied everywhere except the raw ABI module, which must hand out
//! and take back raw pointers into linear memory.
#![deny(unsafe_code)]

/// The shared string API lives in `paste-warden-report`; re-exported as `api`.
pub use paste_warden_report as api;

#[cfg(feature = "bindgen")]
mod bindgen;

#[cfg(feature = "raw-abi")]
pub mod raw;
