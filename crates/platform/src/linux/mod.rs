//! Linux integration (docs/plan/phase-4.md §4.9.2, docs/spikes/s5-linux-monitor.md).
//!
//! No `unsafe`: Wayland and X11 are spoken by pure-Rust clients
//! (`wayland-client`, `x11rb`) and pipes / poll go through `rustix`.
//! Clipboard text only ever lives in zeroized buffers.
//!
//! Pure, tested on every OS:
//! - [`backend`]: backend selection and the capability report
//! - [`text`]: MIME / TARGETS decisions, UTF-8 prefix decoding, read limits
//! - [`transfer`]: stale-reply filter and INCR reassembly
//! - [`foreground`]: foreground history, `WM_CLASS` parsing
//! - [`host`]: `ProtectionStatus` mapping (pure); `start_host` (Linux only)
//!
//! Linux only:
//! - [`monitor`]: `ClipboardMonitor` / `ClipboardHandle` (the public API)
//! - `wayland`: ext / wlr data-control reader and writer
//! - `x11`: XFixes reader, selection owner
//! - [`tracker`]: `_NET_ACTIVE_WINDOW` and `zwlr_foreign_toplevel` trackers
//!
//! Not done in 4b (phase-4.md §4.9.2): paste interception, PRIMARY, the
//! GNOME "check clipboard" action.

pub mod backend;
pub mod foreground;
pub mod host;
pub mod text;
pub mod transfer;

#[cfg(target_os = "linux")]
pub mod io;
#[cfg(target_os = "linux")]
pub mod monitor;
#[cfg(target_os = "linux")]
pub mod tracker;
#[cfg(target_os = "linux")]
mod wayland;
#[cfg(target_os = "linux")]
mod x11;

pub use backend::{Backend, Capability, Env, ForegroundSource, LinuxStatus, Reason, Selection};
pub use foreground::{ForegroundApp, ForegroundHistory, SharedForeground};
#[cfg(target_os = "linux")]
pub use monitor::{
    ClipError, ClipSink, ClipboardHandle, ClipboardMonitor, MonitorOptions, Snapshot, StartError,
    env_from_process, probe,
};
#[cfg(target_os = "linux")]
pub use tracker::ForegroundTracker;
