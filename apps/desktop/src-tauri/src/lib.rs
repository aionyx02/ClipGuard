//! PasteWarden desktop app (Tauri v2, docs/plan/phase-4.md).
//!
//! - [`worker`]: `pw-work`, every core state machine (§4.2)
//! - [`model`]: the JSON contract with the frontend and the UI sink trait
//! - [`commands`], [`ui`], [`app`]: Tauri commands, events, tray, windows
//! - [`persist`], [`bridge`], [`host_impl`]: interfaces the main session
//!   wires to `paste_warden_platform::{store, nmh, probe, <os>::host}`

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
