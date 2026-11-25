//! Windows integration (docs/plan/phase-4.md, docs/spikes/s3-windows-monitor.md).
//!
//! Win32 calls are `unsafe`; this module is the only place in the workspace
//! outside FFI bindings that allows it. Every `unsafe` block states why it is
//! sound, and none of them handles clipboard text outside zeroized buffers.
#![allow(unsafe_code)]

pub mod clipboard;
pub mod monitor;
pub mod process;

pub use clipboard::ClipError;
pub use monitor::{ClipSink, ClipboardHandle, ClipboardMonitor, StartError};
