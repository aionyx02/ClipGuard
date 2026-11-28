//! macOS integration (docs/plan/phase-4.md §4.9.1, docs/spikes/s4-macos-monitor.md).
//!
//! AppKit / CoreGraphics calls are `unsafe`; like `windows`, this module is
//! allowed to use it. Every `unsafe` block states why it is sound, and
//! clipboard text only ever lives in zeroized buffers.
//!
//! - [`clipboard`] / [`monitor`]: the `pw-clip` polling thread and the writer
//! - [`foreground`]: activation history (observer registered on main)
//! - [`input`]: idle time for the wallet-swap timing
//! - [`permissions`]: Accessibility, Secure Input
//! - [`paste_tap`]: the `pw-hook` CGEventTap
//! - [`host`]: the `Host` the desktop worker drives (wires all of the above)
#![allow(unsafe_code)]

pub mod clipboard;
pub mod foreground;
pub mod host;
pub mod input;
pub mod monitor;
pub mod paste_tap;
pub mod permissions;

pub use clipboard::{ClipError, PasteboardAccess, PasteboardSource};
pub use monitor::{ClipSink, ClipboardHandle, ClipboardMonitor, MonitorOptions, StartError};
