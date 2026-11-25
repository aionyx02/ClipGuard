//! OS integration: clipboard monitoring, foreground window, paste hook,
//! keyring, native messaging (docs/plan/phase-4.md).
//!
//! - [`clipboard`]: platform-independent event types and pure helpers
//!   (de-duplication, self-write cache, source URL parsing)
//! - `windows`: the Win32 side (Windows only)
//!
//! Detection logic stays in `paste-warden-core` (P7); this crate only reads
//! and writes OS state and turns it into events.

pub mod clipboard;

#[cfg(windows)]
pub mod windows;
