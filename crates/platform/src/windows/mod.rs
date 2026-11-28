//! Windows integration (docs/plan/phase-4.md, docs/spikes/s3-windows-monitor.md).
//!
//! Win32 calls are `unsafe`; this module is the only place in the workspace
//! outside FFI bindings that allows it. Every `unsafe` block states why it is
//! sound, and none of them handles clipboard text outside zeroized buffers.
//!
//! - [`monitor`] / [`clipboard`]: the `pw-clip` thread (C1)
//! - [`foreground`]: `EVENT_SYSTEM_FOREGROUND` on `pw-clip`, UWP resolution,
//!   integrity level (C2)
//! - [`paste_hook`]: the `pw-hook` `WH_KEYBOARD_LL` thread (C3)
//! - [`send`]: tagged paste replay and the `VK_F24` probe
//! - [`session`]: lock screen / secure desktop (probe pause conditions)
//! - [`input`]: idle time for the wallet-swap timing
//! - [`host`]: [`start_host`], the [`crate::host::Host`] for `pw-work`
#![allow(unsafe_code)]

pub mod clipboard;
pub mod foreground;
pub mod host;
pub mod input;
pub mod monitor;
pub mod paste_hook;
pub mod process;
pub mod send;
pub mod session;

pub use clipboard::ClipError;
pub use host::{WindowsHost, start_host};
pub use monitor::{
    ClipSink, ClipboardHandle, ClipboardMonitor, MonitorOptions, SessionSink, StartError,
};
pub use paste_hook::{HookMsg, HookStartError, PasteHook};
