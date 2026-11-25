//! The interface the desktop worker (`pw-work`, docs/plan/phase-4.md §4.2)
//! drives on every platform. Each OS module provides a `start_host` that
//! returns a [`Host`] and sends [`HostEvent`]s to a sink:
//!
//! - `windows::host::start_host` (4a)
//! - `macos::host::start_host`, `linux::host::start_host` (4b)
//!
//! The worker holds all core state machines and never touches OS APIs
//! directly; the host never analyzes anything (P7).
//!
//! Privacy (P3): window titles and clipboard text never appear in `Debug`
//! output or errors.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::clipboard::ClipEvent;
use crate::gate::PasteGate;
use crate::status::ProtectionStatus;

/// Longest window title kept (phase-4.md §4.3).
pub const WINDOW_TITLE_MAX_CHARS: usize = 256;

/// A window (Windows `HWND`), app (macOS pid) or X11 window id, as i64.
/// 0 means unknown.
pub type WindowId = i64;

/// The foreground at a change (§4.4 entry guard, §4.8.2).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ForegroundInfo {
    pub window: WindowId,
    /// Top-level owner (`GetAncestor(GA_ROOTOWNER)`); same as `window` where
    /// the OS has no such notion.
    pub root: WindowId,
    /// Window class (Windows), bundle id (macOS), `WM_CLASS` / `app_id` (Linux).
    pub class: Option<String>,
    /// At most [`WINDOW_TITLE_MAX_CHARS`] chars.
    pub title: Option<String>,
    /// Executable name without extension (Windows), bundle id (macOS),
    /// `comm` (Linux).
    pub process: Option<String>,
    /// Runs at a higher integrity level than us (Windows §4.8.2; query
    /// failure counts as elevated). Always false elsewhere.
    pub elevated: bool,
}

impl fmt::Debug for ForegroundInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForegroundInfo")
            .field("window", &self.window)
            .field("root", &self.root)
            .field("class", &self.class)
            .field("has_title", &self.title.is_some())
            .field("process", &self.process)
            .field("elevated", &self.elevated)
            .finish()
    }
}

/// Why the hook swallowed a paste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwallowReason {
    /// The clipboard changed and is not analyzed yet: the worker waits up to
    /// `PENDING_ANALYSIS_TIMEOUT_MS` and re-sends a tagged paste on Allow.
    Pending,
    /// The analyzed clipboard must be confirmed (secret / registered secret).
    Intercept,
}

/// Everything a host reports to the worker.
#[derive(Debug)]
pub enum HostEvent {
    Clip(ClipEvent),
    Foreground(ForegroundInfo),
    /// A paste shortcut was swallowed while `target` was in front.
    PasteSwallowed {
        target: WindowId,
        reason: SwallowReason,
    },
    /// The hook saw our tagged probe key (Windows `VK_F24`, §4.4).
    ProbeAnswered,
    /// The OS disabled the hook / tap on its own (macOS
    /// `TapDisabledByTimeout` / `ByUserInput`).
    HookDisabled,
    /// Session locked (true) / unlocked (false), `WTS_SESSION_LOCK` etc.
    SessionLocked(bool),
    /// Enter was swallowed for the window with an open confirmation.
    EnterSwallowed {
        target: WindowId,
    },
    /// What [`Host::status`] reports has changed on its own (macOS: Secure
    /// Input, Accessibility, pasteboard access). The worker re-reads
    /// [`Host::status`]; it also re-reads it on every tick, so a host that
    /// cannot tell does not have to send this.
    StatusChanged,
}

/// Receives [`HostEvent`]s on the host's own threads. Must not block.
pub type EventSink = Box<dyn FnMut(HostEvent) + Send>;

/// A failed host operation. Never carries clipboard text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// The platform cannot do this at all (e.g. interception on Wayland).
    Unsupported,
    /// The clipboard could not be opened, read or written.
    Clipboard,
    /// The host thread did not answer in time.
    Timeout,
    /// Installing the hook / tap failed (permissions, OS refusal).
    Hook,
    /// The host has stopped.
    Stopped,
}

/// The clipboard's text formats before a masked paste (§5.3), opaque to the
/// worker.
pub struct HostSnapshot(pub Box<dyn Any + Send>);

impl fmt::Debug for HostSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostSnapshot(..)")
    }
}

/// Result of [`Host::check_hook`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookCheck {
    /// A probe was sent; [`HostEvent::ProbeAnswered`] should follow within
    /// `HOOK_PROBE_DEADLINE_MS` (Windows).
    ProbeSent,
    /// The OS says the hook works (macOS).
    Healthy,
    /// The OS says the hook does not work (macOS: tap disabled).
    Lost,
    /// No hook on this platform or it is turned off.
    NotApplicable,
}

/// Start options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOptions {
    /// Install the paste hook / tap (`PasteGuardSettings::can_intercept`).
    pub intercept: bool,
    /// The app version differs from the last run (macOS ad-hoc signature,
    /// §4.9.1).
    pub version_changed: bool,
}

/// One platform's OS side (§4.2 `pw-clip` + `pw-hook`).
pub trait Host: Send + Sync {
    /// The atomics the hook reads; the worker publishes decisions here.
    fn gate(&self) -> &Arc<PasteGate>;

    /// What this platform can do right now, as far as the host knows
    /// (permissions, protocols, hook installed). The worker overlays its own
    /// knowledge (probe failures, elevated foreground, settings).
    fn status(&self) -> ProtectionStatus;

    /// Writes plain text; returns the clipboard sequence after the write.
    fn write_text(&self, text: &str) -> Result<u32, HostError>;
    /// Empties the clipboard; returns the sequence after clearing.
    fn clear(&self) -> Result<u32, HostError>;
    /// The whole clipboard text (for restore / masked paste), unbounded by
    /// the analysis limit but bounded by the platform reader.
    fn read_full(&self) -> Option<Zeroizing<String>>;
    fn snapshot(&self) -> Result<HostSnapshot, HostError>;
    fn restore(&self, snap: HostSnapshot) -> Result<u32, HostError>;

    /// Brings `target` to the front and sends a tagged paste shortcut
    /// (`SELF_INPUT_TAG`), which the hook lets through.
    fn paste_into(&self, target: WindowId) -> Result<(), HostError>;

    /// Milliseconds since the last user input (wallet swap timing). `None`
    /// when the platform cannot tell (Linux): core then treats the input
    /// time as unknown.
    fn idle_ms(&self) -> Option<u64>;

    /// Installs or removes the hook (settings change).
    fn set_intercept(&self, enabled: bool) -> Result<(), HostError>;
    /// Health check, called every `HOOK_PROBE_INTERVAL_MS`.
    fn check_hook(&self) -> HookCheck;
    /// Reinstalls the hook after a failed probe.
    fn reinstall_hook(&self) -> Result<(), HostError>;
    /// A secure desktop (UAC prompt) is active: probes would fail (§4.4).
    fn secure_desktop_active(&self) -> bool {
        false
    }

    /// Debug builds only (§4.8.4 item 6): drop / restore the hook without
    /// telling the worker.
    #[cfg(debug_assertions)]
    fn debug_drop_hook(&self) {}
    #[cfg(debug_assertions)]
    fn debug_restore_hook(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreground_debug_hides_title() {
        let f = ForegroundInfo {
            title: Some("secret-window-title".into()),
            ..Default::default()
        };
        assert!(!format!("{f:?}").contains("secret-window-title"));
    }
}
