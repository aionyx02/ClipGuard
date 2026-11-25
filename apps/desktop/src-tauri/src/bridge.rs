//! Optional collaborators of the worker that are written in parallel:
//! the Native Messaging bridge and the hook-probe scheduler.

use paste_warden_core::policy::paste::PasteGuardSettings;

// ---------------------------------------------------------------------------
// Native Messaging (phase-4.md §4.3, §4.4)

/// What the desktop app tells `paste-warden-nmh` (via the named pipe / Unix
/// socket). Only policy and counts: no clipboard text, no secrets, no HMAC key
/// (T16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmhState {
    pub intercept_registered: bool,
    pub intercept_detected: bool,
    pub allowlist: Vec<String>,
    pub registered_count: usize,
}

impl NmhState {
    pub fn new(paste: &PasteGuardSettings, registered_count: usize) -> Self {
        NmhState {
            intercept_registered: paste.intercept_registered,
            intercept_detected: paste.intercept_detected,
            allowlist: paste.allowed_apps.clone(),
            registered_count,
        }
    }
}

/// INTEGRATION POINT: implemented with `paste_warden_platform::nmh` by the
/// main session. The IPC server runs on its own thread and answers `hello` /
/// `policy.get` from the last published state; `verdict` messages are only
/// logged (§4.5 "重複警告"), so the worker never waits on the bridge.
pub trait NmhBridge: Send {
    /// Called at start and whenever the published state changes.
    fn publish(&mut self, state: &NmhState);
}

// ---------------------------------------------------------------------------
// Hook health check (phase-4.md §4.4 "hook 健康檢查", §4.8.4)

/// Probe interval (§4.3 `HOOK_PROBE_INTERVAL_MS`).
pub const HOOK_PROBE_INTERVAL_MS: u64 = 30_000;
/// Probe deadline (§4.3 `HOOK_PROBE_DEADLINE_MS`).
pub const HOOK_PROBE_DEADLINE_MS: u64 = 1_000;
/// Consecutive failures before `HookLost` (§4.3 `HOOK_PROBE_FAIL_THRESHOLD`).
pub const HOOK_PROBE_FAIL_THRESHOLD: u32 = 2;

/// What the worker should do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStep {
    Idle,
    /// Call `Host::check_hook`.
    Check,
    /// The probe was not answered in time: call `Host::reinstall_hook`.
    Reinstall,
}

/// INTEGRATION POINT: `paste_warden_platform::probe` (written in parallel)
/// replaces [`LocalProbe`]; adapt it to this trait or switch the worker to it.
pub trait HookProbe: Send {
    /// `paused`: elevated foreground, session locked, secure desktop, or
    /// interception off. A paused round is skipped and never counts as a
    /// failure.
    fn poll(&mut self, now_ms: u64, paused: bool) -> ProbeStep;
    /// `check_hook` returned `ProbeSent`.
    fn on_probe_sent(&mut self, now_ms: u64);
    /// The probe came back (or the OS says the hook is healthy).
    fn on_answered(&mut self, now_ms: u64);
    /// The OS says the hook does not work (macOS tap disabled).
    fn on_lost(&mut self, now_ms: u64);
    /// `intercept` should show `Degraded(HookLost)`.
    fn hook_lost(&self) -> bool;
}

/// Minimal §4.4 scheduler: probe every 30 s, 1 s deadline, `HookLost` after 2
/// consecutive failures, cleared by the next answer.
#[derive(Debug, Default)]
pub struct LocalProbe {
    next_at: u64,
    sent_at: Option<u64>,
    failures: u32,
}

impl LocalProbe {
    pub fn new(now_ms: u64) -> Self {
        LocalProbe {
            next_at: now_ms.saturating_add(HOOK_PROBE_INTERVAL_MS),
            sent_at: None,
            failures: 0,
        }
    }
}

impl HookProbe for LocalProbe {
    fn poll(&mut self, now_ms: u64, paused: bool) -> ProbeStep {
        if let Some(sent) = self.sent_at {
            if now_ms.saturating_sub(sent) >= HOOK_PROBE_DEADLINE_MS {
                self.sent_at = None;
                self.failures = self.failures.saturating_add(1);
                return ProbeStep::Reinstall;
            }
            return ProbeStep::Idle;
        }
        if now_ms < self.next_at {
            return ProbeStep::Idle;
        }
        self.next_at = now_ms.saturating_add(HOOK_PROBE_INTERVAL_MS);
        if paused {
            ProbeStep::Idle
        } else {
            ProbeStep::Check
        }
    }

    fn on_probe_sent(&mut self, now_ms: u64) {
        self.sent_at = Some(now_ms);
    }

    fn on_answered(&mut self, _now_ms: u64) {
        self.sent_at = None;
        self.failures = 0;
    }

    fn on_lost(&mut self, _now_ms: u64) {
        self.sent_at = None;
        self.failures = self.failures.max(HOOK_PROBE_FAIL_THRESHOLD);
    }

    fn hook_lost(&self) -> bool {
        self.failures >= HOOK_PROBE_FAIL_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_failures_mark_lost_and_an_answer_clears() {
        let mut p = LocalProbe::new(0);
        assert_eq!(p.poll(1_000, false), ProbeStep::Idle);
        assert_eq!(p.poll(30_000, false), ProbeStep::Check);
        p.on_probe_sent(30_000);
        assert_eq!(p.poll(30_500, false), ProbeStep::Idle);
        assert_eq!(p.poll(31_000, false), ProbeStep::Reinstall);
        assert!(!p.hook_lost());
        assert_eq!(p.poll(60_000, false), ProbeStep::Check);
        p.on_probe_sent(60_000);
        assert_eq!(p.poll(61_000, false), ProbeStep::Reinstall);
        assert!(p.hook_lost());
        assert_eq!(p.poll(90_000, false), ProbeStep::Check);
        p.on_answered(90_001);
        assert!(!p.hook_lost());
    }

    #[test]
    fn paused_rounds_are_skipped_not_failed() {
        let mut p = LocalProbe::new(0);
        for i in 1..10 {
            assert_eq!(p.poll(i * HOOK_PROBE_INTERVAL_MS, true), ProbeStep::Idle);
        }
        assert!(!p.hook_lost());
    }
}
