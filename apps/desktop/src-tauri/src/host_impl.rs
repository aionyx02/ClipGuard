//! Platform selection (phase-4.md §4.2, §4.9). Android is out of scope
//! (§4.9.5).
//!
//! Each host sends the current clipboard as its first event
//! (`RUN_INITIAL_CHECK`, legacy #9): the Windows and macOS monitors analyze
//! it right after start, the Linux monitor reports its first selection
//! change. The worker never reads the clipboard on its own at start-up.

use std::sync::Arc;

use paste_warden_platform::gate::PasteGate;
use paste_warden_platform::host::{
    EventSink, HookCheck, Host, HostError, HostOptions, HostSnapshot, WindowId,
};
use paste_warden_platform::status::{Capability, ProtectionStatus, Reason};
use zeroize::Zeroizing;

/// Starts this platform's host (`pw-clip` + `pw-hook`).
pub fn start_host(sink: EventSink, opts: HostOptions) -> Result<Box<dyn Host>, HostError> {
    #[cfg(windows)]
    return paste_warden_platform::windows::host::start_host(sink, opts);
    #[cfg(target_os = "macos")]
    return paste_warden_platform::macos::host::start_host(sink, opts);
    #[cfg(target_os = "linux")]
    return paste_warden_platform::linux::host::start_host(sink, opts);
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (sink, opts);
        Err(HostError::Unsupported)
    }
}

/// Stand-in when the host cannot start: every area unavailable
/// ([`Reason::HostFailed`]), nothing read or written, so the tray shows
/// "failed" instead of pretending.
pub struct NullHost {
    gate: Arc<PasteGate>,
}

impl NullHost {
    pub fn new() -> NullHost {
        NullHost {
            gate: Arc::new(PasteGate::new()),
        }
    }
}

impl Default for NullHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Host for NullHost {
    fn gate(&self) -> &Arc<PasteGate> {
        &self.gate
    }
    fn status(&self) -> ProtectionStatus {
        let u = Capability::Unavailable(Reason::HostFailed);
        ProtectionStatus {
            watch: u,
            write: u,
            foreground: u,
            intercept: u,
        }
    }
    fn write_text(&self, _text: &str) -> Result<u32, HostError> {
        Err(HostError::Stopped)
    }
    fn clear(&self) -> Result<u32, HostError> {
        Err(HostError::Stopped)
    }
    fn read_full(&self) -> Option<Zeroizing<String>> {
        None
    }
    fn snapshot(&self) -> Result<HostSnapshot, HostError> {
        Err(HostError::Stopped)
    }
    fn restore(&self, _snap: HostSnapshot) -> Result<u32, HostError> {
        Err(HostError::Stopped)
    }
    fn paste_into(&self, _target: WindowId) -> Result<(), HostError> {
        Err(HostError::Stopped)
    }
    fn idle_ms(&self) -> Option<u64> {
        None
    }
    fn set_intercept(&self, _enabled: bool) -> Result<(), HostError> {
        Ok(())
    }
    fn check_hook(&self) -> HookCheck {
        HookCheck::NotApplicable
    }
    fn reinstall_hook(&self) -> Result<(), HostError> {
        Err(HostError::Stopped)
    }
}

#[cfg(test)]
mod tests {
    use paste_warden_platform::status::TrayState;

    use super::*;

    #[test]
    fn null_host_reports_host_failed() {
        let s = NullHost::new().status();
        for (_, c) in s.areas() {
            assert_eq!(c, Capability::Unavailable(Reason::HostFailed));
        }
        assert_eq!(s.tray_state(), TrayState::Failed);
    }
}
