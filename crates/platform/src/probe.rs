//! Hook health check and elevated-window notice (docs/plan/phase-4.md §4.4,
//! §4.8.2, §4.8.4). Platform independent, pure logic: time is passed in as
//! milliseconds from any monotonic clock, nothing touches the OS.
//!
//! - [`ProbeScheduler`]: when `pw-work` sends the tagged probe key (Windows
//!   `VK_F24`), when a missing answer counts as a failure, and when the
//!   failures become `intercept = Degraded(HookLost)`.
//! - [`ElevatedToastGate`] lets the elevated-window notification
//!   (`ui-desktop-toast-elevated-unprotected`) fire at most once per
//!   `(window, clipboard sequence)`.
//! - [`elevated`]: the integrity-level comparison behind
//!   `ForegroundInfo.elevated`, failing closed.

use std::collections::VecDeque;

use crate::host::WindowId;
use crate::status::{Capability, Reason};

/// How often the hook is probed (§4.3).
pub const HOOK_PROBE_INTERVAL_MS: u64 = 30_000;
/// How long the probe key may take to reach the hook callback (§4.3).
pub const HOOK_PROBE_DEADLINE_MS: u64 = 1_000;
/// Consecutive failed probes before the hook counts as lost; the first
/// failure only reinstalls it (§4.3).
pub const HOOK_PROBE_FAIL_THRESHOLD: u32 = 2;
/// `(window, sequence)` pairs the elevated-window notice remembers.
pub const ELEVATED_TOAST_MEMORY: usize = 16;

/// Situations in which a probe cannot reach the hook even though the hook
/// works (§4.4 "為什麼要暫停"): `SendInput` into them is silently dropped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PauseConditions {
    /// The foreground runs at a higher integrity level (UIPI).
    pub elevated_foreground: bool,
    /// `WTS_SESSION_LOCK` was seen without a later unlock.
    pub session_locked: bool,
    /// The input desktop is not the user's default desktop (UAC prompt).
    pub secure_desktop: bool,
}

impl PauseConditions {
    pub fn any(self) -> bool {
        self.elevated_foreground || self.session_locked || self.secure_desktop
    }
}

/// What `pw-work` should do after [`ProbeScheduler::tick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStep {
    /// Nothing to do before [`ProbeScheduler::next_wake`].
    Wait,
    /// Send the probe now (`Host::check_hook`).
    Send,
    /// A probe was due but paused: not sent, not counted.
    Skipped,
    /// The probe was not answered in time: reinstall the hook
    /// (`Host::reinstall_hook`). `lost` is true once the failures reach
    /// [`HOOK_PROBE_FAIL_THRESHOLD`] (the status may have changed).
    Failed { failures: u32, lost: bool },
}

/// The probe schedule of §4.4. One instance per installed hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeScheduler {
    next_at: u64,
    /// Deadline of the probe in flight.
    outstanding: Option<u64>,
    failures: u32,
    skipped: u64,
}

impl ProbeScheduler {
    /// The first probe goes out [`HOOK_PROBE_INTERVAL_MS`] after `now`.
    pub fn new(now: u64) -> ProbeScheduler {
        ProbeScheduler {
            next_at: now.saturating_add(HOOK_PROBE_INTERVAL_MS),
            outstanding: None,
            failures: 0,
            skipped: 0,
        }
    }

    /// The hook was (re)installed on purpose (start-up, settings): forget
    /// the history and start a fresh interval.
    pub fn reset(&mut self, now: u64) {
        *self = ProbeScheduler::new(now);
    }

    /// Advances the schedule. Call at [`Self::next_wake`] (calling more
    /// often is harmless).
    pub fn tick(&mut self, now: u64, pause: PauseConditions) -> ProbeStep {
        if let Some(deadline) = self.outstanding {
            if now < deadline {
                return ProbeStep::Wait;
            }
            self.outstanding = None;
            self.next_at = now.saturating_add(HOOK_PROBE_INTERVAL_MS);
            if pause.any() {
                // The window turned elevated / locked while the probe was in
                // flight: the missing answer says nothing about the hook.
                self.skipped = self.skipped.saturating_add(1);
                return ProbeStep::Skipped;
            }
            self.failures = self.failures.saturating_add(1);
            return ProbeStep::Failed {
                failures: self.failures,
                lost: self.is_lost(),
            };
        }
        if now < self.next_at {
            return ProbeStep::Wait;
        }
        self.next_at = now.saturating_add(HOOK_PROBE_INTERVAL_MS);
        if pause.any() {
            self.skipped = self.skipped.saturating_add(1);
            return ProbeStep::Skipped;
        }
        self.outstanding = Some(now.saturating_add(HOOK_PROBE_DEADLINE_MS));
        ProbeStep::Send
    }

    /// The platform has no probe right now (`HookCheck::NotApplicable`, or
    /// sending failed): drop the probe in flight without counting it.
    pub fn cancel(&mut self) {
        self.outstanding = None;
    }

    /// The hook saw the probe (`HostEvent::ProbeAnswered`). Returns true when
    /// this clears a [`Reason::HookLost`]. Answers with no probe in flight
    /// (late, or a stray tagged key) change nothing.
    pub fn on_answer(&mut self) -> bool {
        if self.outstanding.take().is_none() {
            return false;
        }
        let was_lost = self.is_lost();
        self.failures = 0;
        was_lost
    }

    /// When `tick` next has something to do.
    pub fn next_wake(&self) -> u64 {
        self.outstanding.unwrap_or(self.next_at)
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Probes not sent (or not judged) because of [`PauseConditions`].
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    pub fn is_lost(&self) -> bool {
        self.failures >= HOOK_PROBE_FAIL_THRESHOLD
    }

    /// The `intercept` capability as far as the probe knows.
    pub fn capability(&self) -> Capability {
        if self.is_lost() {
            Capability::Degraded(Reason::HookLost)
        } else {
            Capability::Active
        }
    }
}

/// §4.8.2: notify once per `(window, clipboard sequence)` when an analyzed
/// clipboard that must be confirmed meets an elevated foreground window.
#[derive(Debug, Default, Clone)]
pub struct ElevatedToastGate {
    shown: VecDeque<(WindowId, u32)>,
}

impl ElevatedToastGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Call on every foreground change. `intercept` is true when the
    /// clipboard at `seq` was analyzed as `Decision::Intercept`. Returns
    /// true when the notification should be shown (it still goes through
    /// the throttle).
    pub fn should_notify(
        &mut self,
        window: WindowId,
        elevated: bool,
        seq: u32,
        intercept: bool,
    ) -> bool {
        if !elevated || !intercept || self.shown.contains(&(window, seq)) {
            return false;
        }
        if self.shown.len() == ELEVATED_TOAST_MEMORY {
            self.shown.pop_front();
        }
        self.shown.push_back((window, seq));
        true
    }
}

/// Whether a window whose process has integrity level `theirs` runs above
/// us (`ours`). A failed query (`None` on either side) counts as elevated:
/// telling the user once too often beats a silent gap (§4.8.2).
pub fn elevated(ours: Option<u32>, theirs: Option<u32>) -> bool {
    match (ours, theirs) {
        (Some(o), Some(t)) => t > o,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: PauseConditions = PauseConditions {
        elevated_foreground: false,
        session_locked: false,
        secure_desktop: false,
    };

    /// Runs the scheduler to the next probe and returns its time.
    fn to_send(s: &mut ProbeScheduler, pause: PauseConditions) -> (u64, ProbeStep) {
        let t = s.next_wake();
        (t, s.tick(t, pause))
    }

    #[test]
    fn healthy_hook_never_degrades() {
        let mut s = ProbeScheduler::new(0);
        assert_eq!(s.tick(HOOK_PROBE_INTERVAL_MS - 1, NONE), ProbeStep::Wait);
        for _ in 0..10 {
            let (t, step) = to_send(&mut s, NONE);
            assert_eq!(step, ProbeStep::Send);
            assert_eq!(s.tick(t + 1, NONE), ProbeStep::Wait);
            assert!(!s.on_answer());
            assert_eq!(s.capability(), Capability::Active);
        }
        assert_eq!(s.failures(), 0);
    }

    #[test]
    fn first_failure_reinstalls_second_is_lost() {
        let mut s = ProbeScheduler::new(0);
        let (t, step) = to_send(&mut s, NONE);
        assert_eq!(step, ProbeStep::Send);
        assert_eq!(
            s.tick(t + HOOK_PROBE_DEADLINE_MS - 1, NONE),
            ProbeStep::Wait
        );
        let deadline = t + HOOK_PROBE_DEADLINE_MS;
        assert_eq!(
            s.tick(deadline, NONE),
            ProbeStep::Failed {
                failures: 1,
                lost: false
            }
        );
        assert_eq!(s.capability(), Capability::Active, "one failure is quiet");
        assert_eq!(s.next_wake(), deadline + HOOK_PROBE_INTERVAL_MS);

        let (t, step) = to_send(&mut s, NONE);
        assert_eq!(step, ProbeStep::Send);
        assert_eq!(
            s.tick(t + HOOK_PROBE_DEADLINE_MS, NONE),
            ProbeStep::Failed {
                failures: 2,
                lost: true
            }
        );
        assert_eq!(s.capability(), Capability::Degraded(Reason::HookLost));
        // About a minute from the hook dropping to the UI showing it (§4.8.4 #6).
        assert_eq!(
            t + HOOK_PROBE_DEADLINE_MS,
            2 * (HOOK_PROBE_INTERVAL_MS + HOOK_PROBE_DEADLINE_MS)
        );

        // The next answered probe clears it.
        let (_, step) = to_send(&mut s, NONE);
        assert_eq!(step, ProbeStep::Send);
        assert!(s.on_answer(), "clears HookLost");
        assert_eq!(s.capability(), Capability::Active);
        assert_eq!(s.failures(), 0);
    }

    #[test]
    fn success_between_failures_resets_the_count() {
        let mut s = ProbeScheduler::new(0);
        let (t, _) = to_send(&mut s, NONE);
        assert!(matches!(
            s.tick(t + HOOK_PROBE_DEADLINE_MS, NONE),
            ProbeStep::Failed { failures: 1, .. }
        ));
        to_send(&mut s, NONE);
        assert!(!s.on_answer());
        let (t, _) = to_send(&mut s, NONE);
        assert_eq!(
            s.tick(t + HOOK_PROBE_DEADLINE_MS, NONE),
            ProbeStep::Failed {
                failures: 1,
                lost: false
            }
        );
    }

    #[test]
    fn each_pause_condition_skips_without_counting() {
        let conditions = [
            PauseConditions {
                elevated_foreground: true,
                ..NONE
            },
            PauseConditions {
                session_locked: true,
                ..NONE
            },
            PauseConditions {
                secure_desktop: true,
                ..NONE
            },
        ];
        for pause in conditions {
            let mut s = ProbeScheduler::new(0);
            // Two minutes of an elevated terminal / lock screen (§4.8.4 #1, #5).
            for round in 1..=4u64 {
                let (_, step) = to_send(&mut s, pause);
                assert_eq!(step, ProbeStep::Skipped, "{pause:?}");
                assert_eq!(s.skipped(), round);
            }
            assert_eq!(s.failures(), 0);
            assert_eq!(s.capability(), Capability::Active);
            // Resumes normally afterwards.
            let (_, step) = to_send(&mut s, NONE);
            assert_eq!(step, ProbeStep::Send);
        }
    }

    #[test]
    fn pause_during_flight_is_not_a_failure() {
        let mut s = ProbeScheduler::new(0);
        let (t, step) = to_send(&mut s, NONE);
        assert_eq!(step, ProbeStep::Send);
        let pause = PauseConditions {
            elevated_foreground: true,
            ..NONE
        };
        assert_eq!(
            s.tick(t + HOOK_PROBE_DEADLINE_MS, pause),
            ProbeStep::Skipped
        );
        assert_eq!(s.failures(), 0);
        assert_eq!(s.skipped(), 1);
    }

    #[test]
    fn stray_answers_and_cancel() {
        let mut s = ProbeScheduler::new(0);
        assert!(!s.on_answer(), "no probe in flight");
        let (t, _) = to_send(&mut s, NONE);
        s.cancel();
        assert_eq!(s.tick(t + HOOK_PROBE_DEADLINE_MS, NONE), ProbeStep::Wait);
        assert_eq!(s.failures(), 0);
        s.reset(t);
        assert_eq!(s.next_wake(), t + HOOK_PROBE_INTERVAL_MS);
        // Huge times do not overflow.
        let mut s = ProbeScheduler::new(u64::MAX - 1);
        assert_eq!(s.next_wake(), u64::MAX);
        assert_eq!(s.tick(u64::MAX, NONE), ProbeStep::Send);
        assert!(matches!(
            s.tick(u64::MAX, NONE),
            ProbeStep::Failed { failures: 1, .. }
        ));
    }

    #[test]
    fn elevated_notice_once_per_window_and_sequence() {
        let mut g = ElevatedToastGate::new();
        assert!(!g.should_notify(10, false, 1, true), "not elevated");
        assert!(!g.should_notify(10, true, 1, false), "nothing to protect");
        assert!(g.should_notify(10, true, 1, true));
        assert!(!g.should_notify(10, true, 1, true), "switching back");
        assert!(g.should_notify(11, true, 1, true), "another window");
        assert!(!g.should_notify(10, true, 1, true), "first window again");
        assert!(g.should_notify(10, true, 2, true), "new clipboard");
    }

    #[test]
    fn elevated_notice_memory_is_bounded() {
        let mut g = ElevatedToastGate::new();
        for w in 0..(ELEVATED_TOAST_MEMORY as i64 + 1) {
            assert!(g.should_notify(w, true, 1, true));
        }
        assert_eq!(g.shown.len(), ELEVATED_TOAST_MEMORY);
        // The oldest was forgotten.
        assert!(g.should_notify(0, true, 1, true));
    }

    #[test]
    fn integrity_comparison_fails_closed() {
        const MEDIUM: u32 = 0x2000;
        const HIGH: u32 = 0x3000;
        assert!(!elevated(Some(MEDIUM), Some(MEDIUM)));
        assert!(elevated(Some(MEDIUM), Some(HIGH)));
        assert!(!elevated(Some(HIGH), Some(MEDIUM)));
        assert!(elevated(Some(MEDIUM), None), "query failed");
        assert!(elevated(None, Some(MEDIUM)), "own level unknown");
        assert!(elevated(None, None));
    }
}
