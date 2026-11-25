//! The macOS [`Host`] (phase-4.md §4.2, §4.9.1): wires the `pw-clip` monitor,
//! the foreground history, the `pw-hook` event tap and the permission checks
//! behind the platform-independent interface `pw-work` drives.
//!
//! Threads:
//! - `pw-clip` ([`ClipboardMonitor`]): polls the pasteboard, publishes the
//!   sequence into the [`PasteGate`], sends [`HostEvent::Clip`].
//! - `pw-hook` ([`PasteTap`]): the event tap, only while interception is on.
//! - `pw-host`: forwards [`TapEvent`]s as [`HostEvent`]s, reports
//!   foreground changes every [`FOREGROUND_POLL_MS`] and sends
//!   [`HostEvent::StatusChanged`] when Secure Input, Accessibility or the
//!   pasteboard access changes (checked every [`STATUS_POLL_MS`]).
//! - main (the desktop app's): must call [`register_foreground_observer`]
//!   once and keep the returned observer alive. Without it the foreground
//!   history only knows the app that was in front at that moment, and
//!   [`HostEvent::Foreground`] is never sent.
//!
//! Privacy (P3): no clipboard text or window title is logged or put into an
//! error; macOS window titles are not read at all.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use objc2::MainThreadMarker;
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication};
use zeroize::Zeroizing;

use super::clipboard::{ClipError, PasteboardAccess, PasteboardSource, Snapshot};
use super::foreground::{
    ForegroundApp, ForegroundHistory, ForegroundObserver, SharedForeground, frontmost_app,
};
use super::input;
use super::monitor::{ClipboardHandle, ClipboardMonitor, MonitorOptions};
use super::paste_tap::{self, Modifiers, PasteTap, TAP_EVENT_QUEUE_LEN, TapEvent, post_paste};
use super::permissions::{accessibility_trusted, intercept_state, secure_input_enabled};
use crate::gate::PasteGate;
use crate::host::{
    EventSink, ForegroundInfo, HookCheck, Host, HostError, HostEvent, HostOptions, HostSnapshot,
    SwallowReason, WindowId,
};
use crate::status::{Capability, ProtectionStatus, Reason};

/// How often `pw-host` looks for a foreground change (custom: the observer
/// has no callback into the host; 100 ms is below what a user notices
/// between switching apps and pasting).
pub const FOREGROUND_POLL_MS: u64 = 100;
/// How often `pw-host` checks Secure Input, Accessibility and the pasteboard
/// access for [`HostEvent::StatusChanged`] (custom: the worker re-reads the
/// status every second anyway; this makes a change show at once).
pub const STATUS_POLL_MS: u64 = 250;
/// Longest wait in [`Host::paste_into`] for the target app to come to the
/// front before giving up without pasting (custom).
pub const PASTE_ACTIVATE_TIMEOUT_MS: u64 = 1_000;
/// Poll interval while waiting for the activation (custom).
pub const PASTE_ACTIVATE_POLL_MS: u64 = 10;
/// Pause between the activation and the tagged Cmd+V, so the app's key
/// window is ready (custom).
pub const PASTE_SETTLE_MS: u64 = 50;

/// The process-wide foreground history shared by [`start_host`] and
/// [`register_foreground_observer`], so they can be called in any order.
pub fn shared_foreground() -> SharedForeground {
    static FOREGROUND: OnceLock<SharedForeground> = OnceLock::new();
    Arc::clone(FOREGROUND.get_or_init(ForegroundHistory::shared))
}

/// Call once on the main thread (the desktop app's `setup`) and keep the
/// result alive for the app's lifetime; dropping it unsubscribes. Feeds
/// [`shared_foreground`], which the host started by [`start_host`] reads.
pub fn register_foreground_observer(mtm: MainThreadMarker) -> ForegroundObserver {
    ForegroundObserver::register(shared_foreground(), mtm)
}

/// Where the host reads from. [`Default`] is the user's clipboard and
/// [`shared_foreground`]; tests use a private named pasteboard.
#[derive(Default)]
pub struct HostConfig {
    pub pasteboard: PasteboardSource,
    /// `None` = `POLL_INTERVAL_MS`.
    pub poll_interval: Option<Duration>,
    /// `None` = [`shared_foreground`].
    pub foreground: Option<SharedForeground>,
}

/// Starts the macOS host on the general pasteboard. Missing Accessibility
/// is not an error: the tap is simply not installed and [`Host::status`]
/// says why.
pub fn start_host(sink: EventSink, opts: HostOptions) -> Result<Box<dyn Host>, HostError> {
    start_host_with(sink, opts, HostConfig::default())
}

/// [`start_host`] with an explicit [`HostConfig`].
pub fn start_host_with(
    sink: EventSink,
    opts: HostOptions,
    config: HostConfig,
) -> Result<Box<dyn Host>, HostError> {
    let sink: SharedSink = Arc::new(Mutex::new(sink));
    let gate = Arc::new(PasteGate::new());
    let foreground = config.foreground.unwrap_or_else(shared_foreground);

    let clip_sink = Arc::clone(&sink);
    let monitor = ClipboardMonitor::start_with(
        MonitorOptions {
            pasteboard: config.pasteboard,
            poll_interval: config.poll_interval,
            foreground: Some(Arc::clone(&foreground)),
            tap_gate: Some(Arc::clone(&gate)),
        },
        Box::new(move |e| emit(&clip_sink, HostEvent::Clip(e))),
    )
    .map_err(|_| HostError::Stopped)?;
    let clip = monitor.handle();

    let (tap_tx, tap_rx) = mpsc::sync_channel(TAP_EVENT_QUEUE_LEN);
    let quit = Arc::new(AtomicBool::new(false));
    let forwarder = {
        let ctx = Forwarder {
            sink,
            events: tap_rx,
            foreground,
            gate: Arc::clone(&gate),
            quit: Arc::clone(&quit),
            last: None,
            clip: clip.clone(),
            status_key: None,
            status_at: None,
        };
        std::thread::Builder::new()
            .name("pw-host".into())
            .spawn(move || ctx.run())
            .map_err(|_| HostError::Stopped)?
    };

    let host = MacHost {
        gate,
        tap: Mutex::new(TapSlot {
            wanted: opts.intercept,
            tap: None,
        }),
        tap_tx,
        version_changed: opts.version_changed,
        access: Mutex::new(None),
        quit,
        forwarder: Some(forwarder),
        clip,
        _monitor: monitor,
    };
    if opts.intercept {
        // No Accessibility yet: keep running; `status()` reports it and
        // `check_hook()` → Lost makes `pw-work` retry via `reinstall_hook`.
        let _ = host.install_tap(&mut lock(&host.tap));
    }
    Ok(Box::new(host))
}

type SharedSink = Arc<Mutex<EventSink>>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn emit(sink: &SharedSink, ev: HostEvent) {
    (lock(sink))(ev);
}

// ---------------------------------------------------------------------------
// Pure mapping (unit-tested)
// ---------------------------------------------------------------------------

/// `watch` from `NSPasteboard.accessBehavior` (§4.9.1 "剪貼簿隱私提示").
/// `Default` and unknown values count as active: the spec only names `ask`
/// and `alwaysDeny`.
pub fn watch_capability(access: Option<PasteboardAccess>) -> Capability {
    match access {
        Some(PasteboardAccess::AlwaysDeny) => {
            Capability::Unavailable(Reason::PasteboardAccessDenied)
        }
        Some(PasteboardAccess::Ask) => Capability::Degraded(Reason::PasteboardAccessAsk),
        _ => Capability::Active,
    }
}

/// Everything [`status_from`] looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusInputs {
    pub access: Option<PasteboardAccess>,
    /// Interception is turned on in settings.
    pub intercept_wanted: bool,
    pub trusted: bool,
    pub version_changed: bool,
    /// The tap is installed and `CGEventTapIsEnabled`.
    pub tap_enabled: bool,
    pub secure_input: bool,
}

/// §4.8.1 / §4.9.4 for macOS. Writing and the foreground need no permission.
pub fn status_from(i: StatusInputs) -> ProtectionStatus {
    let intercept = if i.intercept_wanted {
        intercept_state(i.trusted, i.version_changed, i.tap_enabled, i.secure_input).capability()
    } else {
        Capability::Unavailable(Reason::DisabledInSettings)
    };
    ProtectionStatus {
        watch: watch_capability(i.access),
        write: Capability::Active,
        foreground: Capability::Active,
        intercept,
    }
}

/// [`Host::check_hook`]: the OS is asked instead of probing (§4.9.1).
/// A wanted tap that is missing (no Accessibility at start, or revoked) is
/// `Lost`, so `pw-work` calls `reinstall_hook`, which succeeds once the
/// permission is granted.
pub fn hook_check(wanted: bool, installed: bool, tap_enabled: bool, trusted: bool) -> HookCheck {
    if !wanted {
        HookCheck::NotApplicable
    } else if installed && tap_enabled && trusted {
        HookCheck::Healthy
    } else {
        HookCheck::Lost
    }
}

/// A foreground app as the worker sees it: the pid is the window and its
/// root; the bundle id is both `class` and `process` (§4.9.1, like
/// `rules/policy/macos.json`). Unbundled executables fall back to the name.
pub fn foreground_info(app: &ForegroundApp) -> ForegroundInfo {
    let id = app.bundle_id.clone().or_else(|| app.name.clone());
    let pid = WindowId::from(app.pid.max(0));
    ForegroundInfo {
        window: pid,
        root: pid,
        class: id.clone(),
        title: None,
        process: id,
        elevated: false,
    }
}

/// A [`TapEvent`] as a [`HostEvent`]; `target` is the app in front.
pub fn tap_event_to_host(ev: TapEvent, target: WindowId) -> Option<HostEvent> {
    match ev {
        TapEvent::PasteSwallowed { reason, .. } => {
            let reason = match reason {
                paste_tap::SwallowReason::Pending => SwallowReason::Pending,
                paste_tap::SwallowReason::Intercept => SwallowReason::Intercept,
                // Never sent by the tap; nothing for the worker to do.
                paste_tap::SwallowReason::Repeat | paste_tap::SwallowReason::KeyUp => {
                    return None;
                }
            };
            Some(HostEvent::PasteSwallowed { target, reason })
        }
        TapEvent::Reenabled { .. } => Some(HostEvent::HookDisabled),
    }
}

fn clip_err(e: ClipError) -> HostError {
    match e {
        ClipError::Busy => HostError::Timeout,
        ClipError::WriteFailed => HostError::Clipboard,
    }
}

// ---------------------------------------------------------------------------
// pw-host thread
// ---------------------------------------------------------------------------

struct Forwarder {
    sink: SharedSink,
    events: Receiver<TapEvent>,
    foreground: SharedForeground,
    gate: Arc<PasteGate>,
    quit: Arc<AtomicBool>,
    /// `(pid, bundle id)` of the last reported foreground.
    last: Option<(i32, Option<String>)>,
    clip: ClipboardHandle,
    /// The last [`StatusKey`] seen, and when it was read.
    status_key: Option<StatusKey>,
    status_at: Option<Instant>,
}

/// What can change [`Host::status`] without the worker doing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusKey {
    pub trusted: bool,
    pub secure_input: bool,
    pub access: Option<PasteboardAccess>,
}

/// Whether a status change is worth a [`HostEvent::StatusChanged`]: never
/// for the first reading (the worker reads the status at start), and an
/// unknown pasteboard access (monitor busy) keeps the previous one.
pub fn status_key_changed(prev: Option<StatusKey>, mut next: StatusKey) -> (StatusKey, bool) {
    match prev {
        None => (next, false),
        Some(p) => {
            if next.access.is_none() {
                next.access = p.access;
            }
            (next, p != next)
        }
    }
}

impl Forwarder {
    fn current(&self) -> Option<ForegroundApp> {
        lock(&self.foreground).current().cloned()
    }

    fn run(mut self) {
        let tick = Duration::from_millis(FOREGROUND_POLL_MS);
        while !self.quit.load(Ordering::Acquire) {
            match self.events.recv_timeout(tick) {
                Ok(ev) => {
                    let target = self
                        .current()
                        .map(|a| WindowId::from(a.pid.max(0)))
                        .filter(|&p| p > 0)
                        .unwrap_or_else(|| self.gate.fg_root());
                    if let Some(ev) = tap_event_to_host(ev, target) {
                        emit(&self.sink, ev);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if let Some(app) = self.current() {
                let key = (app.pid, app.bundle_id.clone());
                if self.last.as_ref() != Some(&key) {
                    self.last = Some(key);
                    emit(&self.sink, HostEvent::Foreground(foreground_info(&app)));
                }
            }
            self.poll_status();
        }
    }

    fn poll_status(&mut self) {
        let due = self
            .status_at
            .is_none_or(|t| t.elapsed() >= Duration::from_millis(STATUS_POLL_MS));
        if !due {
            return;
        }
        self.status_at = Some(Instant::now());
        let next = StatusKey {
            trusted: accessibility_trusted(),
            secure_input: secure_input_enabled(),
            access: self.clip.access(),
        };
        let (key, changed) = status_key_changed(self.status_key, next);
        self.status_key = Some(key);
        if changed {
            emit(&self.sink, HostEvent::StatusChanged);
        }
    }
}

// ---------------------------------------------------------------------------
// The host
// ---------------------------------------------------------------------------

struct TapSlot {
    /// Interception is turned on in settings.
    wanted: bool,
    tap: Option<PasteTap>,
}

struct MacHost {
    gate: Arc<PasteGate>,
    tap: Mutex<TapSlot>,
    tap_tx: SyncSender<TapEvent>,
    version_changed: bool,
    /// Last known `accessBehavior` (kept when the monitor is busy).
    access: Mutex<Option<PasteboardAccess>>,
    quit: Arc<AtomicBool>,
    forwarder: Option<JoinHandle<()>>,
    clip: ClipboardHandle,
    /// Dropped last: stops `pw-clip`.
    _monitor: ClipboardMonitor,
}

impl MacHost {
    fn install_tap(&self, slot: &mut TapSlot) -> Result<(), HostError> {
        slot.tap = None;
        let tap = PasteTap::start(Arc::clone(&self.gate), self.tap_tx.clone())
            .map_err(|_| HostError::Hook)?;
        slot.tap = Some(tap);
        Ok(())
    }

    fn access(&self) -> Option<PasteboardAccess> {
        let mut cached = lock(&self.access);
        if let Some(a) = self.clip.access() {
            *cached = Some(a);
        }
        *cached
    }
}

/// Asks `pid` to come to the front and waits until it is.
fn activate(pid: i32) -> Result<(), HostError> {
    let requested = autoreleasepool(|_| {
        let Some(app) = NSRunningApplication::runningApplicationWithProcessIdentifier(pid) else {
            return false;
        };
        // Since macOS 14 `IgnoringOtherApps` has no effect; activation is
        // granted because our confirmation window is the active app.
        app.activateWithOptions(NSApplicationActivationOptions::empty())
    });
    if !requested {
        return Err(HostError::Unsupported);
    }
    let deadline = Instant::now() + Duration::from_millis(PASTE_ACTIVATE_TIMEOUT_MS);
    loop {
        if frontmost_app().is_some_and(|a| a.pid == pid) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HostError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(PASTE_ACTIVATE_POLL_MS));
    }
}

impl Host for MacHost {
    fn gate(&self) -> &Arc<PasteGate> {
        &self.gate
    }

    fn status(&self) -> ProtectionStatus {
        let access = self.access();
        let (wanted, tap_enabled) = {
            let slot = lock(&self.tap);
            (
                slot.wanted,
                slot.tap.as_ref().is_some_and(PasteTap::is_enabled),
            )
        };
        status_from(StatusInputs {
            access,
            intercept_wanted: wanted,
            trusted: accessibility_trusted(),
            version_changed: self.version_changed,
            tap_enabled,
            secure_input: secure_input_enabled(),
        })
    }

    fn write_text(&self, text: &str) -> Result<u32, HostError> {
        self.clip.write_text(text).map_err(clip_err)
    }

    fn clear(&self) -> Result<u32, HostError> {
        self.clip.clear().map_err(clip_err)
    }

    fn read_full(&self) -> Option<Zeroizing<String>> {
        self.clip.read_full()
    }

    fn snapshot(&self) -> Result<HostSnapshot, HostError> {
        let snap = self.clip.snapshot().map_err(clip_err)?;
        Ok(HostSnapshot(Box::new(snap)))
    }

    fn restore(&self, snap: HostSnapshot) -> Result<u32, HostError> {
        let snap = snap
            .0
            .downcast::<Snapshot>()
            .map_err(|_| HostError::Clipboard)?;
        self.clip.restore(*snap).map_err(clip_err)
    }

    /// Activates the app with pid `target`, waits until it is in front and
    /// posts a tagged Cmd+V. Never pastes when the activation does not
    /// happen (`Timeout`) or `target` is unknown (`Unsupported`). Posting
    /// needs Accessibility (`Hook` without it).
    fn paste_into(&self, target: WindowId) -> Result<(), HostError> {
        let pid = i32::try_from(target)
            .ok()
            .filter(|&p| p > 0)
            .ok_or(HostError::Unsupported)?;
        if !accessibility_trusted() {
            return Err(HostError::Hook);
        }
        activate(pid)?;
        std::thread::sleep(Duration::from_millis(PASTE_SETTLE_MS));
        if post_paste(Modifiers::default()) {
            Ok(())
        } else {
            Err(HostError::Hook)
        }
    }

    fn idle_ms(&self) -> Option<u64> {
        Some(input::idle_ms())
    }

    fn set_intercept(&self, enabled: bool) -> Result<(), HostError> {
        let mut slot = lock(&self.tap);
        slot.wanted = enabled;
        if !enabled {
            slot.tap = None;
            return Ok(());
        }
        if slot.tap.is_some() {
            return Ok(());
        }
        self.install_tap(&mut slot)
    }

    fn check_hook(&self) -> HookCheck {
        let slot = lock(&self.tap);
        hook_check(
            slot.wanted,
            slot.tap.is_some(),
            slot.tap.as_ref().is_some_and(PasteTap::is_enabled),
            accessibility_trusted(),
        )
    }

    fn reinstall_hook(&self) -> Result<(), HostError> {
        let mut slot = lock(&self.tap);
        if !slot.wanted {
            return Ok(());
        }
        self.install_tap(&mut slot)
    }

    #[cfg(debug_assertions)]
    fn debug_drop_hook(&self) {
        lock(&self.tap).tap = None;
    }

    #[cfg(debug_assertions)]
    fn debug_restore_hook(&self) {
        let mut slot = lock(&self.tap);
        if slot.wanted && slot.tap.is_none() {
            let _ = self.install_tap(&mut slot);
        }
    }
}

impl Drop for MacHost {
    fn drop(&mut self) {
        lock(&self.tap).tap = None;
        self.quit.store(true, Ordering::Release);
        if let Some(t) = self.forwarder.take() {
            let _ = t.join();
        }
        // `_monitor` is dropped after this and stops `pw-clip`.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> StatusInputs {
        StatusInputs {
            access: Some(PasteboardAccess::AlwaysAllow),
            intercept_wanted: true,
            trusted: true,
            version_changed: false,
            tap_enabled: true,
            secure_input: false,
        }
    }

    #[test]
    fn status_changes_are_reported_once() {
        let k = StatusKey {
            trusted: true,
            secure_input: false,
            access: Some(PasteboardAccess::AlwaysAllow),
        };
        assert_eq!(status_key_changed(None, k), (k, false), "first reading");
        assert_eq!(status_key_changed(Some(k), k), (k, false));
        let secure = StatusKey {
            secure_input: true,
            ..k
        };
        assert_eq!(status_key_changed(Some(k), secure), (secure, true));
        let busy = StatusKey { access: None, ..k };
        assert_eq!(status_key_changed(Some(k), busy), (k, false), "busy");
        let denied = StatusKey {
            access: Some(PasteboardAccess::AlwaysDeny),
            ..k
        };
        assert_eq!(status_key_changed(Some(k), denied), (denied, true));
        let revoked = StatusKey {
            trusted: false,
            ..k
        };
        assert!(status_key_changed(Some(k), revoked).1);
    }

    #[test]
    fn all_good_is_active() {
        assert_eq!(status_from(inputs()), ProtectionStatus::default());
    }

    #[test]
    fn pasteboard_access() {
        let watch = |a| {
            status_from(StatusInputs {
                access: a,
                ..inputs()
            })
            .watch
        };
        assert_eq!(
            watch(Some(PasteboardAccess::AlwaysDeny)),
            Capability::Unavailable(Reason::PasteboardAccessDenied)
        );
        assert_eq!(
            watch(Some(PasteboardAccess::Ask)),
            Capability::Degraded(Reason::PasteboardAccessAsk)
        );
        assert_eq!(watch(Some(PasteboardAccess::Default)), Capability::Active);
        assert_eq!(watch(Some(PasteboardAccess::Other(42))), Capability::Active);
        assert_eq!(watch(None), Capability::Active);
    }

    #[test]
    fn intercept_reasons() {
        let intercept = |i: StatusInputs| status_from(i).intercept;
        assert_eq!(
            intercept(StatusInputs {
                intercept_wanted: false,
                trusted: false,
                ..inputs()
            }),
            Capability::Unavailable(Reason::DisabledInSettings)
        );
        assert_eq!(
            intercept(StatusInputs {
                trusted: false,
                tap_enabled: false,
                ..inputs()
            }),
            Capability::Unavailable(Reason::NoAccessibility)
        );
        assert_eq!(
            intercept(StatusInputs {
                trusted: false,
                version_changed: true,
                ..inputs()
            }),
            Capability::Unavailable(Reason::NoAccessibilityAfterUpdate)
        );
        assert_eq!(
            intercept(StatusInputs {
                tap_enabled: false,
                ..inputs()
            }),
            Capability::Degraded(Reason::HookLost)
        );
        assert_eq!(
            intercept(StatusInputs {
                secure_input: true,
                ..inputs()
            }),
            Capability::Degraded(Reason::SecureInput)
        );
        // Other areas never depend on the tap.
        let s = status_from(StatusInputs {
            trusted: false,
            ..inputs()
        });
        assert!(s.write.is_active() && s.foreground.is_active() && s.watch.is_active());
    }

    #[test]
    fn hook_checks() {
        assert_eq!(
            hook_check(false, false, false, false),
            HookCheck::NotApplicable
        );
        assert_eq!(hook_check(true, true, true, true), HookCheck::Healthy);
        assert_eq!(hook_check(true, true, false, true), HookCheck::Lost);
        assert_eq!(hook_check(true, true, true, false), HookCheck::Lost);
        assert_eq!(hook_check(true, false, false, false), HookCheck::Lost);
    }

    #[test]
    fn foreground_uses_bundle_id() {
        let app = ForegroundApp::new(Some("org.example.term".into()), Some("Term".into()), 321);
        let f = foreground_info(&app);
        assert_eq!((f.window, f.root), (321, 321));
        assert_eq!(f.class.as_deref(), Some("org.example.term"));
        assert_eq!(f.process.as_deref(), Some("org.example.term"));
        assert_eq!(f.title, None);
        assert!(!f.elevated);

        let unbundled = ForegroundApp::new(None, Some("tool".into()), -1);
        let f = foreground_info(&unbundled);
        assert_eq!(f.window, 0, "no pid is unknown");
        assert_eq!(f.class.as_deref(), Some("tool"));
    }

    #[test]
    fn tap_events_map() {
        let ev = tap_event_to_host(
            TapEvent::PasteSwallowed {
                seq: 3,
                reason: paste_tap::SwallowReason::Intercept,
            },
            77,
        );
        assert!(matches!(
            ev,
            Some(HostEvent::PasteSwallowed {
                target: 77,
                reason: SwallowReason::Intercept
            })
        ));
        let ev = tap_event_to_host(
            TapEvent::PasteSwallowed {
                seq: 3,
                reason: paste_tap::SwallowReason::Pending,
            },
            1,
        );
        assert!(matches!(
            ev,
            Some(HostEvent::PasteSwallowed {
                reason: SwallowReason::Pending,
                ..
            })
        ));
        for r in [
            paste_tap::SwallowReason::Repeat,
            paste_tap::SwallowReason::KeyUp,
        ] {
            assert!(tap_event_to_host(TapEvent::PasteSwallowed { seq: 0, reason: r }, 1).is_none());
        }
        assert!(matches!(
            tap_event_to_host(TapEvent::Reenabled { by_timeout: true }, 1),
            Some(HostEvent::HookDisabled)
        ));
    }

    #[test]
    fn clip_errors_map() {
        assert_eq!(clip_err(ClipError::Busy), HostError::Timeout);
        assert_eq!(clip_err(ClipError::WriteFailed), HostError::Clipboard);
    }
}
