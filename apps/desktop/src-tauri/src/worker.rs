//! `pw-work` (docs/plan/phase-4.md §4.2): owns every core state machine, turns
//! [`HostEvent`]s and UI commands into decisions, publishes them to the
//! [`PasteGate`](paste_warden_platform::gate::PasteGate) and the UI.
//!
//! The worker never touches OS APIs directly (only through [`Host`]) and never
//! renders text for people, except the localized PEM placeholder that "paste
//! masked" writes to the clipboard. Time is passed in (`now_ms`, monotonic), so
//! everything here is unit-tested with a fake host.
//!
//! Privacy (P3): clipboard text lives in [`Zeroizing`] buffers for the duration
//! of one call; only masked text and message ids leave the worker.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use paste_warden_core::policy::entry::{self, EntryWarningGate};
use paste_warden_core::policy::guard::{ClipboardAction, ClipboardGuardState};
use paste_warden_core::policy::paste::{
    self, MAX_ALLOWED_APPS, MAX_APP_NAME_LENGTH, PENDING_TIMEOUT_MS, PasteGuardSettings,
    PasteSecrets, PasteTarget, PendingPaste, REGISTERED_MASK,
};
use paste_warden_core::policy::registered::{
    self, MAX_LABEL_LENGTH, RegisteredMatch, RegisteredSecretStore, RegistrationField,
};
use paste_warden_core::policy::throttle::{
    NotificationDecision, NotificationLevel, NotificationThrottle,
};
use paste_warden_core::policy::windows::WindowsRules;
use paste_warden_core::secret::{self, SecretKind, SecretMatch};
use paste_warden_core::wallet::{SwapDetector, WalletSwap};
use paste_warden_core::{Context, Engine, Level, Message, Platform, Report, Source, limits};
use paste_warden_platform::clipboard::{ClipEvent, ClipText};
use paste_warden_platform::gate::Decision;
use paste_warden_platform::host::{
    ForegroundInfo, HookCheck, Host, HostEvent, HostOptions, HostSnapshot, SwallowReason, WindowId,
};
use paste_warden_platform::probe::{ElevatedToastGate, PauseConditions, ProbeScheduler, ProbeStep};
use paste_warden_platform::status::{Capability, ProtectionStatus, Reason};
use zeroize::Zeroizing;

use crate::bridge::{NmhBridge, NmhState};
use crate::model::{
    AppSettings, CmdResult, CommandError, ConfirmPayload, Line, LocalePref, Notice, RegisteredId,
    SecretInfo, SettingsPayload, StatusPayload, ThemePref, UiSink,
};
use crate::persist::{MAX_REGISTERED_SECRETS, PersistError, Persistence};

/// The hook swallowed a paste before the change was analyzed: wait this long
/// for the analysis, then give up without re-sending (fail closed, §4.3).
pub const PENDING_ANALYSIS_TIMEOUT_MS: u64 = 2_000;
/// Delay before the clipboard is switched back after a masked paste (§5.3).
pub const MASKED_PASTE_RESTORE_DELAY_MS: u64 = 600;
/// The worker wakes at least this often (host status, probe schedule).
pub const TICK_MS: u64 = 1_000;
/// Longest masked preview sent to the confirm window.
pub const CONFIRM_PREVIEW_MAX_CHARS: usize = 400;
/// Secrets listed in one notification (legacy `SecretGuard.MaxListed`).
pub const NOTIFY_MAX_SECRETS: usize = 3;
/// Command / hidden-char reasons listed in one notification.
pub const NOTIFY_MAX_REASONS: usize = 2;
/// A foreground change this soon before a clipboard event counts as after
/// the copy: the source falls back to the window in front before it
/// (§4.3 source order; custom, above `CLIPBOARD_READ_DELAY_MS` = 25 plus the
/// macOS / Linux 100 ms foreground poll).
pub const FOREGROUND_SETTLE_MS: u64 = 150;

pub type Reply<T> = SyncSender<T>;

/// `paste_choice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteChoice {
    Cancel,
    Masked,
    Original,
}

impl PasteChoice {
    pub fn parse(s: &str) -> Option<PasteChoice> {
        match s {
            "cancel" => Some(PasteChoice::Cancel),
            "masked" => Some(PasteChoice::Masked),
            "original" => Some(PasteChoice::Original),
            _ => None,
        }
    }
}

/// UI commands (Tauri `invoke` and the tray), already shape-checked; the
/// worker re-validates values against core.
pub enum UiCommand {
    GetStatus(Reply<StatusPayload>),
    GetSettings(Reply<SettingsPayload>),
    /// The open confirmation, if any (the confirm window asks on mount).
    GetPendingPaste(Reply<Option<ConfirmPayload>>),
    SetLocale(LocalePref, Reply<CmdResult<()>>),
    SetTheme(ThemePref, Reply<CmdResult<()>>),
    SetPasteGuard {
        registered: bool,
        detected: bool,
        reply: Reply<CmdResult<()>>,
    },
    /// Tray check item: flips `registered` (true) or `detected` (false).
    TogglePasteGuard {
        registered: bool,
    },
    AllowlistAdd(String, Reply<CmdResult<()>>),
    AllowlistRemove(String, Reply<CmdResult<()>>),
    CompleteOnboarding(Reply<CmdResult<()>>),
    RegisterSecret {
        secret: Zeroizing<String>,
        confirm: Zeroizing<String>,
        label: String,
        /// Wall-clock time for `createdAtMs`.
        now_wall_ms: u64,
        reply: Reply<CmdResult<RegisteredId>>,
    },
    ListSecrets(Reply<CmdResult<Vec<SecretInfo>>>),
    RemoveSecret(String, Reply<CmdResult<()>>),
    /// Deletes every registered secret: the way out when the keyring lost
    /// the key (`store-error-key-missing`) or `secrets.json` is corrupt.
    ForgetSecrets(Reply<CmdResult<()>>),
    PasteChoice(PasteChoice, Reply<CmdResult<()>>),
    Restore(Reply<CmdResult<()>>),
    /// Removes the hook, then stops the worker (legacy: unhook before exit).
    Shutdown(Reply<()>),
    #[cfg(debug_assertions)]
    DebugDropHook,
    #[cfg(debug_assertions)]
    DebugRestoreHook,
}

pub enum WorkerMsg {
    Host(HostEvent),
    Ui(UiCommand),
}

/// Fixed per run.
pub struct WorkerConfig {
    /// `windows_rules()`, `macos_rules()` or `linux_rules()`.
    pub rules: &'static WindowsRules,
    pub platform: Platform,
    /// Process names / bundle ids of our own windows (paste is never
    /// intercepted there).
    pub own_ids: Vec<String>,
    /// `zh-TW` or `en`, for `LocalePref::System`.
    pub system_locale: &'static str,
}

/// Settings loaded before the host starts (the host needs `HostOptions`).
pub struct Boot {
    pub settings: AppSettings,
    pub paste: PasteGuardSettings,
    pub registered: Result<RegisteredSecretStore, PersistError>,
    pub version_changed: bool,
    /// Problems to tell the user once the UI is up.
    pub problems: Vec<PersistError>,
    /// Legacy (C#) data was deleted at start (Windows, §4.5): ask the user
    /// once to register their secrets again.
    pub legacy_cleaned: bool,
}

impl Boot {
    /// Loads everything and records `app_version` as the last run's version.
    pub fn load(persist: &mut dyn Persistence, app_version: &str) -> Boot {
        let (mut settings, e1) = persist.load_settings();
        let (paste, e2) = persist.load_paste_guard();
        let registered = persist.load_registered();
        let version_changed = settings.last_version.as_deref() != Some(app_version);
        let mut problems: Vec<PersistError> = [e1, e2].into_iter().flatten().collect();
        if let Err(e) = &registered
            && *e != PersistError::NoSecretService
        {
            problems.push(e.clone());
        }
        if version_changed {
            settings.last_version = Some(app_version.to_owned());
            if let Err(e) = persist.save_settings(&settings) {
                problems.push(e);
            }
        }
        Boot {
            settings,
            paste,
            registered,
            version_changed,
            problems,
            legacy_cleaned: false,
        }
    }

    fn has_registered(&self) -> bool {
        self.registered
            .as_ref()
            .is_ok_and(|s| !s.entries().is_empty())
    }

    pub fn host_options(&self) -> HostOptions {
        HostOptions {
            intercept: self.paste.can_intercept(self.has_registered()),
            version_changed: self.version_changed,
        }
    }
}

/// The analyzed clipboard.
#[derive(Debug, Clone, Default)]
struct ClipState {
    seq: u32,
    decision: Option<Decision>,
    kinds: Vec<SecretKind>,
}

struct Confirm {
    target: WindowId,
    opened_at: u64,
    payload: ConfirmPayload,
}

struct MaskedRestore {
    due: u64,
    snap: HostSnapshot,
    masked_seq: u32,
    /// The user copied something else meanwhile: do not switch back.
    superseded: bool,
}

/// See the module docs.
pub struct Worker {
    host: Arc<dyn Host>,
    ui: Box<dyn UiSink>,
    persist: Box<dyn Persistence>,
    nmh: Option<Box<dyn NmhBridge>>,
    probe: ProbeScheduler,
    cfg: WorkerConfig,

    settings: AppSettings,
    paste: PasteGuardSettings,
    registered: Result<RegisteredSecretStore, PersistError>,
    version_changed: bool,
    engine: Engine,

    guard: ClipboardGuardState,
    throttle: NotificationThrottle<Notice>,
    throttle_due: Option<u64>,
    entry_gate: EntryWarningGate,
    swap: SwapDetector,
    pending: PendingPaste,
    clip: ClipState,
    fg: ForegroundInfo,
    /// The foreground before `fg`, and when `fg` came to the front.
    fg_prev: ForegroundInfo,
    fg_since: u64,
    session_locked: bool,
    elevated_gate: ElevatedToastGate,

    stale: Option<(WindowId, u64)>,
    confirm: Option<Confirm>,
    masked_restore: Option<MaskedRestore>,

    intercept_installed: bool,
    status: ProtectionStatus,
}

impl Worker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        boot: Boot,
        host: Arc<dyn Host>,
        ui: Box<dyn UiSink>,
        persist: Box<dyn Persistence>,
        nmh: Option<Box<dyn NmhBridge>>,
        cfg: WorkerConfig,
        now_ms: u64,
    ) -> Worker {
        let intercept_installed = boot.host_options().intercept;
        let engine = Engine::new(boot.settings.engine.clone());
        let mut w = Worker {
            host,
            ui,
            persist,
            nmh,
            probe: ProbeScheduler::new(now_ms),
            cfg,
            settings: boot.settings,
            paste: boot.paste,
            registered: boot.registered,
            version_changed: boot.version_changed,
            engine,
            guard: ClipboardGuardState::new(),
            throttle: NotificationThrottle::default(),
            throttle_due: None,
            entry_gate: EntryWarningGate::new(),
            swap: SwapDetector::new(),
            pending: PendingPaste::new(),
            clip: ClipState::default(),
            fg: ForegroundInfo::default(),
            fg_prev: ForegroundInfo::default(),
            fg_since: 0,
            session_locked: false,
            elevated_gate: ElevatedToastGate::new(),
            stale: None,
            confirm: None,
            masked_restore: None,
            intercept_installed,
            status: ProtectionStatus::default(),
        };
        w.status = w.compute_status();
        w.ui.status_changed(&w.status);
        let payload = w.settings_payload();
        w.ui.settings_changed(&payload);
        w.ui.restore_available(false);
        w.publish_nmh();
        for p in boot.problems {
            w.notify(problem_notice(&p), now_ms);
        }
        if boot.legacy_cleaned {
            w.notify(
                notice(
                    NotificationLevel::Warning,
                    "ui-desktop-toast-legacy-removed-title",
                    &["ui-desktop-toast-legacy-removed-body"],
                ),
                now_ms,
            );
        }
        w
    }

    // -----------------------------------------------------------------------
    // Loop

    /// Runs until `Shutdown` or until every sender is gone. `clock` returns
    /// monotonic milliseconds.
    pub fn run(mut self, rx: Receiver<WorkerMsg>, clock: impl Fn() -> u64) {
        loop {
            let now = clock();
            let wait = self.next_wake(now).saturating_sub(now);
            match rx.recv_timeout(Duration::from_millis(wait)) {
                Ok(msg) => {
                    let now = clock();
                    // A bug must not end protection silently; state machines
                    // stay usable after a panic in one event.
                    let keep = catch_unwind(AssertUnwindSafe(|| self.handle(msg, now)));
                    if matches!(keep, Ok(false)) {
                        break;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            let now = clock();
            let _ = catch_unwind(AssertUnwindSafe(|| self.tick(now)));
        }
        let _ = self.host.set_intercept(false);
    }

    /// When the next timer is due.
    pub fn next_wake(&self, now: u64) -> u64 {
        let mut at = now.saturating_add(TICK_MS);
        let mut consider = |t: u64| at = at.min(t);
        if let Some(t) = self.throttle_due {
            consider(t);
        }
        if let Some((_, since)) = self.stale {
            consider(since.saturating_add(PENDING_ANALYSIS_TIMEOUT_MS));
        }
        if let Some(c) = &self.confirm {
            consider(c.opened_at.saturating_add(PENDING_TIMEOUT_MS));
        }
        if let Some(m) = &self.masked_restore {
            consider(m.due);
        }
        if self.intercept_installed {
            consider(self.probe.next_wake());
        }
        at.max(now)
    }

    /// Handles one message. `false` = stop.
    pub fn handle(&mut self, msg: WorkerMsg, now: u64) -> bool {
        let keep = match msg {
            WorkerMsg::Host(ev) => {
                self.on_host(ev, now);
                true
            }
            WorkerMsg::Ui(cmd) => self.on_ui(cmd, now),
        };
        self.refresh_status();
        keep
    }

    /// Timers: throttle, stale paste, confirmation timeout, masked restore,
    /// hook probe, host status.
    pub fn tick(&mut self, now: u64) {
        if self.throttle_due.is_some_and(|t| t <= now) {
            self.throttle_due = None;
            let d = self.throttle.flush(now);
            self.apply(d, now);
        }
        if let Some((_, since)) = self.stale
            && now.saturating_sub(since) >= PENDING_ANALYSIS_TIMEOUT_MS
        {
            self.stale = None;
            self.notify(
                notice(
                    NotificationLevel::Warning,
                    "ui-desktop-toast-not-pasted-title",
                    &["ui-desktop-toast-paste-timeout"],
                ),
                now,
            );
        }
        if self
            .confirm
            .as_ref()
            .is_some_and(|c| now.saturating_sub(c.opened_at) >= PENDING_TIMEOUT_MS)
        {
            self.resolve_confirm(PasteChoice::Cancel, now);
        }
        if self.masked_restore.as_ref().is_some_and(|m| m.due <= now)
            && let Some(m) = self.masked_restore.take()
            && !m.superseded
            && self.host.restore(m.snap).is_err()
        {
            self.notify(
                notice(
                    NotificationLevel::Warning,
                    "ui-desktop-toast-still-masked-title",
                    &["ui-desktop-toast-still-masked-body"],
                ),
                now,
            );
        }
        self.run_probe(now);
        self.refresh_status();
    }

    // -----------------------------------------------------------------------
    // Host events

    fn on_host(&mut self, ev: HostEvent, now: u64) {
        match ev {
            HostEvent::Clip(c) => self.on_clip(c, now),
            HostEvent::Foreground(f) => self.on_foreground(f, now),
            HostEvent::PasteSwallowed { target, reason } => self.on_swallowed(target, reason, now),
            HostEvent::ProbeAnswered => {
                // `true` = this cleared a HookLost; `refresh_status` shows it.
                let _ = self.probe.on_answer();
            }
            HostEvent::HookDisabled => {
                let _ = self.host.reinstall_hook();
            }
            HostEvent::StatusChanged => {
                // `handle` re-reads the status afterwards; Secure Input may
                // have just turned on with a secret on the clipboard.
                self.maybe_notify_elevated(now);
            }
            HostEvent::SessionLocked(locked) => self.session_locked = locked,
            HostEvent::EnterSwallowed { .. } => {
                // The confirm window lost focus; bring it back.
                if let Some(c) = &self.confirm {
                    self.ui.open_confirm(&c.payload);
                }
            }
        }
    }

    /// The window in front when the clipboard changed: a foreground change
    /// in the last [`FOREGROUND_SETTLE_MS`] most likely came after the copy.
    fn foreground_at_change(&self, now: u64) -> &ForegroundInfo {
        if now.saturating_sub(self.fg_since) < FOREGROUND_SETTLE_MS {
            &self.fg_prev
        } else {
            &self.fg
        }
    }

    /// Source order (§4.3): the clipboard's source URL, its owner, then the
    /// foreground before the change.
    fn context(&self, t: &ClipText, now: u64) -> Context {
        let app_id = t
            .owner_process
            .clone()
            .or_else(|| self.foreground_at_change(now).process.clone())
            .filter(|p| !p.is_empty());
        Context {
            source: Some(Source {
                app_id,
                url: t.source_url.clone(),
                ..Default::default()
            }),
            platform: self.cfg.platform,
        }
    }

    fn registered_matches(&self, text: &str) -> Vec<RegisteredMatch> {
        match &self.registered {
            Ok(store) => store.find(text),
            Err(_) => Vec::new(),
        }
    }

    fn on_clip(&mut self, ev: ClipEvent, now: u64) {
        self.throttle.on_clipboard_changed();
        match ev {
            ClipEvent::Empty { sequence, .. } => {
                if let Some(m) = &mut self.masked_restore
                    && m.masked_seq != sequence
                {
                    m.superseded = true;
                }
                self.guard.on_clipboard_empty();
                self.set_clip(sequence, Vec::new());
            }
            ClipEvent::Text(t) => self.on_text(t, now),
        }
        self.resolve_stale(now);
    }

    fn on_text(&mut self, t: ClipText, now: u64) {
        if !t.self_write
            && let Some(m) = &mut self.masked_restore
            && m.masked_seq != t.sequence
        {
            m.superseded = true;
        }
        let ctx = self.context(&t, now);
        let mut report: Option<Report> = None;
        let engine = &self.engine;
        let host = &self.host;
        let action = self.guard.on_clipboard_text(
            &t.text,
            |s| {
                let r = engine.analyze(s, &ctx);
                let v = r.command.verdict.clone();
                report = Some(r);
                v
            },
            || host.read_full().map(|z| String::clone(&z)),
        );

        if action == ClipboardAction::Quarantine {
            // Cleared: nothing to paste, nothing to intercept.
            self.set_clip(t.sequence, Vec::new());
            let _ = self.host.clear();
            self.ui.restore_available(true);
            if !t.self_write {
                let reasons = report
                    .as_ref()
                    .map(|r| r.command.verdict.reasons.clone())
                    .unwrap_or_default();
                let mut body = vec![Line::Msg(Message::new("ui-desktop-toast-quarantine-head"))];
                body.extend(reasons.into_iter().take(NOTIFY_MAX_REASONS).map(Line::Msg));
                body.push(Line::Msg(Message::new("ui-desktop-toast-quarantine-tail")));
                let n = Notice {
                    level: NotificationLevel::Error,
                    title: Line::Msg(Message::new("ui-desktop-toast-quarantine-title")),
                    body,
                };
                self.notify_restorable(n, now);
            }
            return;
        }

        // Trusted (restored) content skips the analyzer; analyze it for
        // secrets anyway.
        let report = report.unwrap_or_else(|| self.engine.analyze(&t.text, &ctx));
        let regs = self.registered_matches(&t.text);
        let mut kinds: Vec<SecretKind> = Vec::new();
        if !regs.is_empty() {
            kinds.push(SecretKind::Registered);
        }
        for s in &report.secrets {
            if !kinds.contains(&s.kind) {
                kinds.push(s.kind);
            }
        }
        self.set_clip(t.sequence, kinds);

        if t.self_write {
            return;
        }
        let swap = self.swap.observe(&t.text, now, self.host.idle_ms());
        let mut notified = false;
        match (action, &swap) {
            (ClipboardAction::WarnSuspicious, None) => {
                let mut body = vec![Line::Msg(Message::new("ui-desktop-toast-suspicious-head"))];
                body.extend(
                    report
                        .command
                        .verdict
                        .reasons
                        .iter()
                        .take(NOTIFY_MAX_REASONS)
                        .cloned()
                        .map(Line::Msg),
                );
                self.notify(
                    Notice {
                        level: NotificationLevel::Warning,
                        title: Line::Msg(Message::new("ui-desktop-toast-suspicious-title")),
                        body,
                    },
                    now,
                );
                notified = true;
            }
            (ClipboardAction::None, None) => {
                if let Some(n) = secret_notice(&regs, &report.secrets) {
                    self.notify(n, now);
                    notified = true;
                }
            }
            _ => {}
        }
        if let Some(s) = swap {
            self.notify(wallet_notice(&s), now);
        } else if !notified && action == ClipboardAction::None && report.hidden.level != Level::None
        {
            let mut body = vec![Line::Msg(Message::new("ui-desktop-toast-hidden-head"))];
            body.extend(report.hidden.reasons.iter().cloned().map(Line::Msg));
            self.notify(
                Notice {
                    level: NotificationLevel::Warning,
                    title: Line::Msg(Message::new("ui-desktop-toast-hidden-title")),
                    body,
                },
                now,
            );
        }
        self.maybe_notify_elevated(now);
    }

    /// Publishes the analyzed clipboard to the gate.
    fn set_clip(&mut self, seq: u32, kinds: Vec<SecretKind>) {
        let decision = self.decision_for(&kinds);
        self.clip = ClipState {
            seq,
            decision: Some(decision),
            kinds,
        };
        self.host.gate().publish(seq, decision);
    }

    fn decision_for(&self, kinds: &[SecretKind]) -> Decision {
        let secrets = PasteSecrets {
            registered: kinds.contains(&SecretKind::Registered),
            detected: kinds.iter().any(|k| *k != SecretKind::Registered),
        };
        // The target allowlist is checked by the hook (`fg_allowed`); here
        // only "does this clipboard need a confirmation at all".
        let nowhere = PasteTarget {
            process: "",
            class: "",
            own: false,
        };
        match paste::decide_with(&self.cfg.rules.paste, secrets, &nowhere, &self.paste) {
            paste::PasteDecision::Allow => Decision::Allow,
            paste::PasteDecision::Intercept => Decision::Intercept,
        }
    }

    /// Re-publishes the current clipboard after settings or secrets changed.
    fn republish(&mut self) {
        if let Some(text) = self.host.read_full() {
            let regs = self.registered_matches(limits::prefix(&text));
            let mut kinds: Vec<SecretKind> = self
                .clip
                .kinds
                .iter()
                .copied()
                .filter(|k| *k != SecretKind::Registered)
                .collect();
            if !regs.is_empty() {
                kinds.insert(0, SecretKind::Registered);
            }
            self.clip.kinds = kinds;
        }
        if self.clip.decision.is_some() {
            let kinds = std::mem::take(&mut self.clip.kinds);
            self.set_clip(self.clip.seq, kinds);
        }
    }

    fn is_own(&self, f: &ForegroundInfo) -> bool {
        f.process.as_deref().is_some_and(|p| {
            let p = paste::normalize_app_name(p);
            self.cfg.own_ids.iter().any(|o| o.eq_ignore_ascii_case(&p))
        })
    }

    fn on_foreground(&mut self, f: ForegroundInfo, now: u64) {
        let class = f.class.as_deref().unwrap_or_default();
        let title = f.title.as_deref().unwrap_or_default();
        let process = f.process.as_deref().unwrap_or_default();
        let target = PasteTarget {
            process,
            class,
            own: self.is_own(&f),
        };
        let allowed = paste::is_allowed_with(&self.cfg.rules.paste, &target, &self.paste);
        let gate = self.host.gate();
        gate.set_fg_root(f.root);
        gate.set_fg_allowed(allowed);

        let entry = entry::classify_with(&self.cfg.rules.entry, class, title, process);
        let warning = entry::decide_for(entry, self.guard.level(), self.guard.quarantine_active());
        let window = f.window;
        if f.window != self.fg.window || f.process != self.fg.process {
            self.fg_prev = std::mem::replace(&mut self.fg, f);
            self.fg_since = now;
        } else {
            self.fg = f;
        }
        if let Some(w) = warning
            && self
                .entry_gate
                .try_enter_entry(entry, window as u64, self.guard.generation())
        {
            let level = if w.level == Level::Malicious {
                NotificationLevel::Error
            } else {
                NotificationLevel::Warning
            };
            self.notify(
                Notice {
                    level,
                    title: Line::Msg(w.title),
                    body: w.body.into_iter().map(Line::Msg).collect(),
                },
                now,
            );
        }
        self.maybe_notify_elevated(now);
    }

    /// §4.8.2: the clipboard needs a confirmation and the foreground is
    /// elevated (or Secure Input is on): tell once per (window, sequence).
    fn maybe_notify_elevated(&mut self, now: u64) {
        if self.clip.decision != Some(Decision::Intercept) || !self.intercept_enabled() {
            return;
        }
        let secure_input =
            self.host.status().intercept == Capability::Degraded(Reason::SecureInput);
        if !self.elevated_gate.should_notify(
            self.fg.window,
            self.fg.elevated || secure_input,
            self.clip.seq,
            true,
        ) {
            return;
        }
        let kind = self
            .clip
            .kinds
            .first()
            .map_or("ui-desktop-kind-api-key", |k| kind_id(*k));
        let (title, body) = if self.fg.elevated {
            (
                "ui-desktop-toast-elevated-title",
                "ui-desktop-toast-elevated-unprotected",
            )
        } else {
            (
                "ui-desktop-toast-secure-input-title",
                "ui-desktop-toast-secure-input-unprotected",
            )
        };
        self.notify(
            Notice {
                level: NotificationLevel::Warning,
                title: Line::Msg(Message::new(title)),
                body: vec![Line::Nested(
                    Message::new(body),
                    vec![("kind", Message::new(kind))],
                )],
            },
            now,
        );
    }

    fn on_swallowed(&mut self, target: WindowId, reason: SwallowReason, now: u64) {
        if self.confirm.is_some() {
            // One confirmation at a time; this paste stays swallowed.
            return;
        }
        match reason {
            SwallowReason::Pending => {
                self.stale = Some((target, now));
                let gate = self.host.gate();
                let seen = gate.clipboard_seq();
                if seen != 0 && seen == gate.verdict().0 {
                    self.resolve_stale(now);
                }
            }
            SwallowReason::Intercept => self.open_confirm(target, now),
        }
    }

    /// The analysis a swallowed paste waited for is done.
    fn resolve_stale(&mut self, now: u64) {
        let Some((target, _)) = self.stale else {
            return;
        };
        match self.clip.decision {
            Some(Decision::Allow) => {
                self.stale = None;
                if self.host.paste_into(target).is_err() {
                    self.notify(not_pasted("ui-desktop-toast-cannot-send"), now);
                }
            }
            Some(Decision::Intercept) => {
                self.stale = None;
                self.open_confirm(target, now);
            }
            Some(Decision::Unknown) | None => {}
        }
    }

    fn root_of(&self, target: WindowId) -> WindowId {
        if self.fg.window == target && self.fg.root != 0 {
            self.fg.root
        } else {
            target
        }
    }

    fn open_confirm(&mut self, target: WindowId, now: u64) {
        let root = self.root_of(target);
        self.pending.intercept(now, root as u64);
        self.host.gate().set_pending_target(root);
        let payload = self.confirm_payload(target);
        self.ui.open_confirm(&payload);
        self.confirm = Some(Confirm {
            target,
            opened_at: now,
            payload,
        });
    }

    fn pem_body_mask(&self) -> String {
        let locale = match self.settings.locale {
            LocalePref::System => self.cfg.system_locale,
            other => other.as_str(),
        };
        paste_warden_report::localizer(locale).format(&secret::pem_body_mask_message())
    }

    /// The clipboard with every detected and registered secret masked.
    fn masked(&self, text: &str) -> Zeroizing<String> {
        let analyzed = limits::prefix(text);
        let report = self.engine.analyze(analyzed, &Context::default());
        let mut all: Vec<SecretMatch> = self
            .registered_matches(analyzed)
            .into_iter()
            .map(|m| SecretMatch {
                kind: SecretKind::Registered,
                rule_id: String::new(),
                label: m.masked(),
                masked: REGISTERED_MASK.to_owned(),
                span: m.start..m.end,
            })
            .collect();
        all.extend(report.secrets);
        let mut out = Zeroizing::new(secret::mask_text(analyzed, &all, &self.pem_body_mask()));
        out.push_str(text.get(analyzed.len()..).unwrap_or_default());
        out
    }

    fn confirm_payload(&self, target: WindowId) -> ConfirmPayload {
        let preview = self
            .host
            .read_full()
            .map(|t| {
                let m = self.masked(&t);
                m.chars()
                    .take(CONFIRM_PREVIEW_MAX_CHARS)
                    .collect::<String>()
            })
            .unwrap_or_default();
        let target_name = (self.fg.window == target || self.fg.root == target)
            .then(|| self.fg.process.clone())
            .flatten();
        ConfirmPayload {
            kinds: self
                .clip
                .kinds
                .iter()
                .map(|k| kind_id(*k).to_owned())
                .collect(),
            masked_preview: preview,
            target_name,
        }
    }

    fn resolve_confirm(&mut self, choice: PasteChoice, now: u64) -> bool {
        let Some(c) = self.confirm.take() else {
            return false;
        };
        self.pending.resolve();
        self.host.gate().set_pending_target(0);
        self.ui.close_confirm();
        match choice {
            PasteChoice::Cancel => {}
            PasteChoice::Original => {
                if self.host.paste_into(c.target).is_err() {
                    self.notify(not_pasted("ui-desktop-toast-cannot-send"), now);
                }
            }
            PasteChoice::Masked => self.paste_masked(c.target, now),
        }
        true
    }

    /// §5.3: write the masked text, paste it into `target`, switch back after
    /// `MASKED_PASTE_RESTORE_DELAY_MS`.
    fn paste_masked(&mut self, target: WindowId, now: u64) {
        let (Some(text), Ok(snap)) = (self.host.read_full(), self.host.snapshot()) else {
            self.notify(not_pasted("ui-desktop-toast-cannot-read"), now);
            return;
        };
        let masked = self.masked(&text);
        drop(text);
        let Ok(masked_seq) = self.host.write_text(&masked) else {
            self.notify(not_pasted("ui-desktop-toast-cannot-write"), now);
            return;
        };
        if self.host.paste_into(target).is_err() {
            self.notify(not_pasted("ui-desktop-toast-cannot-send"), now);
        }
        self.masked_restore = Some(MaskedRestore {
            due: now.saturating_add(MASKED_PASTE_RESTORE_DELAY_MS),
            snap,
            masked_seq,
            superseded: false,
        });
    }

    // -----------------------------------------------------------------------
    // Status

    fn has_registered(&self) -> bool {
        self.registered
            .as_ref()
            .is_ok_and(|s| !s.entries().is_empty())
    }

    fn intercept_enabled(&self) -> bool {
        self.paste.can_intercept(self.has_registered())
    }

    /// Host status overlaid with settings, the probe result and the elevated
    /// foreground (§4.8.1). A platform limit (Wayland / X11: no
    /// interception) wins over "turned off in settings".
    pub fn compute_status(&self) -> ProtectionStatus {
        let mut s = self.host.status();
        let platform_limit = s.intercept.reason().is_some_and(Reason::is_platform_limit);
        if platform_limit {
            // Known limit: keep the host's reason whatever the settings say.
        } else if !self.intercept_enabled() {
            s.intercept = Capability::Unavailable(Reason::DisabledInSettings);
        } else if s.intercept.is_active() {
            if self.probe.is_lost() {
                s.intercept = Capability::Degraded(Reason::HookLost);
            } else if self.fg.elevated {
                s.intercept = Capability::Degraded(Reason::ElevatedForeground);
            }
        }
        s
    }

    fn refresh_status(&mut self) {
        let s = self.compute_status();
        if s != self.status {
            self.status = s;
            self.ui.status_changed(&s);
        }
    }

    fn sync_intercept(&mut self, now: u64) {
        let want = self.intercept_enabled();
        if want != self.intercept_installed {
            self.intercept_installed = want;
            let _ = self.host.set_intercept(want);
            // Installed (or removed) on purpose: a fresh probe history.
            self.probe.reset(now);
        }
    }

    /// §4.4 hook health check through `paste_warden_platform::probe`.
    fn run_probe(&mut self, now: u64) {
        if !self.intercept_installed {
            self.probe.cancel();
            return;
        }
        let pause = PauseConditions {
            elevated_foreground: self.fg.elevated,
            session_locked: self.session_locked,
            secure_desktop: self.host.secure_desktop_active(),
        };
        match self.probe.tick(now, pause) {
            ProbeStep::Wait | ProbeStep::Skipped => {}
            ProbeStep::Send => match self.host.check_hook() {
                // The answer arrives as `HostEvent::ProbeAnswered`.
                HookCheck::ProbeSent => {}
                HookCheck::Healthy => {
                    let _ = self.probe.on_answer();
                }
                // macOS: the tap is missing or disabled. Left in flight, it
                // fails at the deadline and the hook is reinstalled.
                HookCheck::Lost => {}
                HookCheck::NotApplicable => self.probe.cancel(),
            },
            ProbeStep::Failed { failures, lost } => {
                crate::diag!("hook probe failed ({failures}, lost={lost}), reinstalling");
                let _ = self.host.reinstall_hook();
            }
        }
    }

    // -----------------------------------------------------------------------
    // Notifications

    fn notify(&mut self, n: Notice, now: u64) {
        let d = self.throttle.submit(
            paste_warden_core::policy::throttle::Notification {
                level: n.level,
                restorable: false,
                payload: n,
            },
            now,
        );
        self.apply(d, now);
    }

    fn notify_restorable(&mut self, n: Notice, now: u64) {
        let d = self.throttle.submit(
            paste_warden_core::policy::throttle::Notification {
                level: n.level,
                restorable: true,
                payload: n,
            },
            now,
        );
        self.apply(d, now);
    }

    fn apply(&mut self, d: NotificationDecision<Notice>, now: u64) {
        match d.retry_in_ms {
            Some(r) => self.throttle_due = Some(now.saturating_add(r)),
            None if self.throttle.pending().is_none() => self.throttle_due = None,
            None => {}
        }
        if let Some(n) = d.show {
            self.ui.notify(&n.payload);
        }
    }

    // -----------------------------------------------------------------------
    // UI commands

    fn settings_payload(&self) -> SettingsPayload {
        SettingsPayload::new(&self.settings, &self.paste, self.version_changed)
    }

    fn publish_nmh(&mut self) {
        let state = NmhState::new(&self.paste, self.registered.as_ref().ok());
        if let Some(n) = &mut self.nmh {
            n.publish(&state);
        }
    }

    fn save_settings(&mut self, next: AppSettings) -> CmdResult<()> {
        self.persist
            .save_settings(&next)
            .map_err(|e| e.to_command_error())?;
        self.settings = next;
        let p = self.settings_payload();
        self.ui.settings_changed(&p);
        Ok(())
    }

    fn save_paste(&mut self, next: PasteGuardSettings, now: u64) -> CmdResult<()> {
        let next = next.sanitized();
        self.persist
            .save_paste_guard(&next)
            .map_err(|e| e.to_command_error())?;
        self.paste = next;
        self.after_policy_change(now);
        Ok(())
    }

    fn after_policy_change(&mut self, now: u64) {
        self.sync_intercept(now);
        self.republish();
        // The allowlist changed: recompute `fg_allowed` for the foreground.
        let f = self.fg.clone();
        let target = PasteTarget {
            process: f.process.as_deref().unwrap_or_default(),
            class: f.class.as_deref().unwrap_or_default(),
            own: self.is_own(&f),
        };
        let allowed = paste::is_allowed_with(&self.cfg.rules.paste, &target, &self.paste);
        self.host.gate().set_fg_allowed(allowed);
        let p = self.settings_payload();
        self.ui.settings_changed(&p);
        self.publish_nmh();
    }

    fn on_ui(&mut self, cmd: UiCommand, now: u64) -> bool {
        match cmd {
            UiCommand::GetStatus(r) => {
                let _ = r.send(StatusPayload::from(&self.compute_status()));
            }
            UiCommand::GetSettings(r) => {
                let _ = r.send(self.settings_payload());
            }
            UiCommand::GetPendingPaste(r) => {
                let _ = r.send(self.confirm.as_ref().map(|c| c.payload.clone()));
            }
            UiCommand::SetLocale(l, r) => {
                let mut next = self.settings.clone();
                next.locale = l;
                let _ = r.send(self.save_settings(next));
            }
            UiCommand::SetTheme(t, r) => {
                let mut next = self.settings.clone();
                next.theme = t;
                let _ = r.send(self.save_settings(next));
            }
            UiCommand::CompleteOnboarding(r) => {
                let mut next = self.settings.clone();
                next.onboarding_done = true;
                let _ = r.send(self.save_settings(next));
            }
            UiCommand::SetPasteGuard {
                registered,
                detected,
                reply,
            } => {
                let mut next = self.paste.clone();
                next.intercept_registered = registered;
                next.intercept_detected = detected;
                let _ = reply.send(self.save_paste(next, now));
            }
            UiCommand::TogglePasteGuard { registered } => {
                let mut next = self.paste.clone();
                if registered {
                    next.intercept_registered = !next.intercept_registered;
                } else {
                    next.intercept_detected = !next.intercept_detected;
                }
                if self.save_paste(next, now).is_err() {
                    self.notify(
                        notice(
                            NotificationLevel::Warning,
                            "ui-desktop-toast-settings-problem-title",
                            &["ui-desktop-error-save-failed"],
                        ),
                        now,
                    );
                    // Re-sync the tray check marks with the unchanged settings.
                    let p = self.settings_payload();
                    self.ui.settings_changed(&p);
                }
            }
            UiCommand::AllowlistAdd(name, r) => {
                let res = self.allowlist_add(&name, now);
                let _ = r.send(res);
            }
            UiCommand::AllowlistRemove(name, r) => {
                let n = paste::normalize_app_name(&name);
                let mut next = self.paste.clone();
                let before = next.allowed_apps.len();
                next.allowed_apps
                    .retain(|a| !a.eq_ignore_ascii_case(&n) && *a != n);
                let res = if next.allowed_apps.len() == before {
                    Err(CommandError::new("ui-desktop-error-allowlist-missing").field("name"))
                } else {
                    self.save_paste(next, now)
                };
                let _ = r.send(res);
            }
            UiCommand::RegisterSecret {
                secret,
                confirm,
                label,
                now_wall_ms,
                reply,
            } => {
                let res = self.register(&secret, &confirm, &label, now_wall_ms, now);
                drop((secret, confirm));
                let _ = reply.send(res);
            }
            UiCommand::ListSecrets(r) => {
                let res = match &self.registered {
                    Ok(store) => Ok(store
                        .entries()
                        .iter()
                        .map(|e| SecretInfo {
                            id: e.id.to_string(),
                            label: e.label.clone(),
                            length: e.length,
                            created_at_ms: e.created_at_ms,
                        })
                        .collect()),
                    Err(e) => Err(e.to_command_error()),
                };
                let _ = r.send(res);
            }
            UiCommand::RemoveSecret(id, r) => {
                let res = self.remove_secret(&id, now);
                let _ = r.send(res);
            }
            UiCommand::ForgetSecrets(r) => {
                let res = self.forget_secrets(now);
                let _ = r.send(res);
            }
            UiCommand::PasteChoice(choice, r) => {
                let res = if self.resolve_confirm(choice, now) {
                    Ok(())
                } else {
                    Err(CommandError::new("ui-desktop-error-no-pending-paste"))
                };
                let _ = r.send(res);
            }
            UiCommand::Restore(r) => {
                let res = self.restore(now);
                let _ = r.send(res);
            }
            UiCommand::Shutdown(r) => {
                let _ = self.host.set_intercept(false);
                self.intercept_installed = false;
                let _ = r.send(());
                return false;
            }
            #[cfg(debug_assertions)]
            UiCommand::DebugDropHook => self.host.debug_drop_hook(),
            #[cfg(debug_assertions)]
            UiCommand::DebugRestoreHook => self.host.debug_restore_hook(),
        }
        true
    }

    fn allowlist_add(&mut self, name: &str, now: u64) -> CmdResult<()> {
        let n = paste::normalize_app_name(name);
        let len = n.chars().count();
        let err = |id| Err(CommandError::new(id).field("name"));
        if len == 0 {
            return err("ui-desktop-error-allowlist-empty");
        }
        if len > MAX_APP_NAME_LENGTH {
            return err("ui-desktop-error-allowlist-too-long");
        }
        if self
            .paste
            .allowed_apps
            .iter()
            .any(|a| paste::normalize_app_name(a).to_lowercase() == n.to_lowercase())
        {
            return err("ui-desktop-error-allowlist-duplicate");
        }
        if self.paste.allowed_apps.len() >= MAX_ALLOWED_APPS {
            return err("ui-desktop-error-allowlist-full");
        }
        let mut next = self.paste.clone();
        next.allowed_apps.push(n);
        self.save_paste(next, now)
    }

    fn register(
        &mut self,
        secret: &str,
        confirm: &str,
        label: &str,
        now_wall_ms: u64,
        now: u64,
    ) -> CmdResult<RegisteredId> {
        if let Err(e) = registered::validate_registration(secret, confirm) {
            let field = match e.field {
                RegistrationField::Secret => "secret",
                RegistrationField::Confirm => "confirm",
            };
            return Err(CommandError::from_message(&e.message, Some(field)));
        }
        if label.trim().chars().count() > MAX_LABEL_LENGTH {
            return Err(CommandError::from_message(
                &Message::new("ui-desktop-error-label-too-long").arg("max", MAX_LABEL_LENGTH),
                Some("label"),
            ));
        }
        let store = self.registered.as_mut().map_err(|e| e.to_command_error())?;
        if store.entries().len() >= MAX_REGISTERED_SECRETS {
            return Err(CommandError::from_message(
                &Message::new("ui-desktop-error-secrets-full").arg("max", MAX_REGISTERED_SECRETS),
                None,
            ));
        }
        let id = match store.add(Some(label), secret, now_wall_ms) {
            Ok(e) => e.id,
            Err(e) => return Err(CommandError::from_message(&e.message(), Some("secret"))),
        };
        if let Err(e) = self.persist.save_registered(store.entries()) {
            store.remove(id);
            return Err(e.to_command_error());
        }
        self.after_policy_change(now);
        Ok(RegisteredId { id: id.to_string() })
    }

    /// Deletes every registered secret and reloads the (now empty) store,
    /// creating a new key if the old one is gone.
    fn forget_secrets(&mut self, now: u64) -> CmdResult<()> {
        self.persist
            .forget_registered()
            .map_err(|e| e.to_command_error())?;
        self.registered = self.persist.load_registered();
        self.after_policy_change(now);
        match &self.registered {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_command_error()),
        }
    }

    fn remove_secret(&mut self, id: &str, now: u64) -> CmdResult<()> {
        let id: u64 = id
            .parse()
            .map_err(|_| CommandError::new("ui-desktop-error-secret-missing").field("id"))?;
        let store = self.registered.as_mut().map_err(|e| e.to_command_error())?;
        if !store.entries().iter().any(|e| e.id == id) {
            return Err(CommandError::new("ui-desktop-error-secret-missing").field("id"));
        }
        // Save first: the store has no insert to roll back with.
        let remaining: Vec<_> = store
            .entries()
            .iter()
            .filter(|e| e.id != id)
            .cloned()
            .collect();
        self.persist
            .save_registered(&remaining)
            .map_err(|e| e.to_command_error())?;
        store.remove(id);
        self.after_policy_change(now);
        Ok(())
    }

    /// Tray "restore" (§4.4): trust first, then write, then end.
    fn restore(&mut self, now: u64) -> CmdResult<()> {
        let Some(text) = self.guard.begin_restore().map(Zeroizing::new) else {
            return Err(CommandError::new("ui-desktop-error-nothing-to-restore"));
        };
        let ok = self.host.write_text(&text).is_ok();
        drop(text);
        self.guard.end_restore(ok);
        self.ui
            .restore_available(self.guard.quarantined().is_some());
        if ok {
            Ok(())
        } else {
            self.notify(
                notice(
                    NotificationLevel::Warning,
                    "ui-desktop-toast-restore-failed-title",
                    &["ui-desktop-toast-restore-failed-body"],
                ),
                now,
            );
            Err(CommandError::new("ui-desktop-error-restore-failed"))
        }
    }
}

// ---------------------------------------------------------------------------
// Notice builders

fn notice(level: NotificationLevel, title: &'static str, body: &[&'static str]) -> Notice {
    Notice {
        level,
        title: Line::Msg(Message::new(title)),
        body: body.iter().map(|id| Line::Msg(Message::new(id))).collect(),
    }
}

fn not_pasted(body: &'static str) -> Notice {
    notice(
        NotificationLevel::Warning,
        "ui-desktop-toast-not-pasted-title",
        &[body],
    )
}

fn problem_notice(p: &PersistError) -> Notice {
    Notice {
        level: NotificationLevel::Warning,
        title: Line::Msg(Message::new("ui-desktop-toast-settings-problem-title")),
        body: vec![Line::Msg(p.message())],
    }
}

/// Fluent id of a secret kind (`ui-desktop-kind-*`).
pub fn kind_id(k: SecretKind) -> &'static str {
    match k {
        SecretKind::NationalId => "ui-desktop-kind-national-id",
        SecretKind::ResidentCertificate => "ui-desktop-kind-resident-certificate",
        SecretKind::BusinessId => "ui-desktop-kind-business-id",
        SecretKind::CreditCard => "ui-desktop-kind-credit-card",
        SecretKind::MobilePhone => "ui-desktop-kind-mobile-phone",
        SecretKind::ApiKey => "ui-desktop-kind-api-key",
        SecretKind::Registered => "ui-desktop-kind-registered",
        SecretKind::PhoneNumber => "ui-desktop-kind-phone-number",
        SecretKind::BankAccount => "ui-desktop-kind-bank-account",
        SecretKind::Mnemonic => "ui-desktop-kind-mnemonic",
    }
}

/// Legacy `SecretGuard.Describe`: masked values and labels only.
fn secret_notice(regs: &[RegisteredMatch], found: &[SecretMatch]) -> Option<Notice> {
    let total = regs.len() + found.len();
    if total == 0 {
        return None;
    }
    let mut body: Vec<Line> = regs.iter().map(|m| Line::Msg(m.masked())).collect();
    body.extend(found.iter().map(|m| {
        Line::Nested(
            Message::new("ui-desktop-toast-secret-line").arg("masked", m.masked.as_str()),
            vec![("label", m.label.clone())],
        )
    }));
    body.truncate(NOTIFY_MAX_SECRETS);
    if total > NOTIFY_MAX_SECRETS {
        body.push(Line::Msg(
            Message::new("ui-desktop-toast-secret-more").arg("count", total - NOTIFY_MAX_SECRETS),
        ));
    }
    body.push(Line::Msg(Message::new("ui-desktop-toast-secret-advice")));
    Some(Notice {
        level: NotificationLevel::Warning,
        title: Line::Msg(Message::new("ui-desktop-toast-secret-title")),
        body,
    })
}

/// Legacy `NotifyWalletSwap`: never shows the addresses (P4).
fn wallet_notice(s: &WalletSwap) -> Notice {
    let ms = usize::try_from(s.elapsed_ms).unwrap_or(usize::MAX);
    let detail = if s.replacement_currency == s.currency {
        Message::new("ui-desktop-toast-wallet-swap-detail")
            .arg("currency", s.currency.as_str())
            .arg("ms", ms)
    } else {
        Message::new("ui-desktop-toast-wallet-swap-detail-other")
            .arg("currency", s.currency.as_str())
            .arg("other", s.replacement_currency.as_str())
            .arg("ms", ms)
    };
    Notice {
        level: NotificationLevel::Error,
        title: Line::Msg(Message::new("ui-desktop-toast-wallet-swap-title")),
        body: vec![
            Line::Msg(detail),
            Line::Msg(Message::new("ui-desktop-toast-wallet-swap-advice")),
        ],
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
