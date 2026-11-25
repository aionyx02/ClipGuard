//! PasteWarden desktop app (Tauri v2, docs/plan/phase-4.md).
//!
//! - [`worker`]: `pw-work`, every core state machine (§4.2)
//! - [`model`]: the JSON contract with the frontend and the UI sink trait
//! - [`commands`], [`ui`], [`app`]: Tauri commands, events, tray, windows
//! - [`persist`], [`bridge`], [`host_impl`]: `paste_warden_platform::{store,
//!   nmh, <os>::host}` as the worker sees them

pub mod app;
pub mod bridge;
pub mod commands;
pub mod host_impl;
pub mod model;
pub mod persist;
pub mod ui;
pub mod worker;

#[cfg(test)]
mod config_tests;

pub use app::run;

/// One diagnostic line on stderr, prefixed `paste-warden:`. Only fixed text,
/// ids, counts and states: never clipboard text, window titles, secrets,
/// labels, URLs or hosts (P3). Write errors are ignored (a Windows GUI
/// process has no stderr).
#[macro_export]
macro_rules! diag {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "paste-warden: {}", format_args!($($t)*));
    }};
}
