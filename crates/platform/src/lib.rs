//! OS integration: clipboard monitoring, foreground window, paste hook,
//! keyring, native messaging (docs/plan/phase-4.md).
//!
//! - [`clipboard`]: platform-independent event types and pure helpers
//!   (de-duplication, self-write cache, source URL parsing)
//! - `windows`: the Win32 side (Windows only)
//! - `macos`: the AppKit / CoreGraphics side (macOS only, phase-4.md §4.9.1)
//! - `linux`: Wayland data-control / X11 XFixes (Linux only, phase-4.md
//!   §4.9.2); its protocol-independent parts also build in tests elsewhere
//!
//! Detection logic stays in `paste-warden-core` (P7); this crate only reads
//! and writes OS state and turns it into events.

pub mod clipboard;

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(any(target_os = "linux", test))]
pub mod linux;
