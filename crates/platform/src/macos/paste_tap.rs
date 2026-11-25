//! The `pw-hook` thread on macOS (phase-4.md §4.2, §4.9.1, S4 finding 4): an
//! active `CGEventTap` on its own `CFRunLoop` that swallows paste shortcuts
//! while the clipboard is unanalyzed or must be intercepted.
//!
//! The callback does no allocation, takes no locks and does no IO: it reads
//! the event's fields and the atomics in [`TapGate`] (written by `pw-work`
//! and `pw-clip`), and reports swallowed pastes through a pre-allocated
//! bounded channel (`try_send`, never blocks). The decision itself is the
//! pure [`decide`].

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{NonNull, null_mut};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use objc2_core_foundation::{CFMachPort, CFRunLoop, kCFRunLoopCommonModes, kCFRunLoopDefaultMode};
use objc2_core_graphics::{
    CGEvent, CGEventField, CGEventFlags, CGEventSource, CGEventSourceStateID, CGEventTapLocation,
    CGEventTapOptions, CGEventTapPlacement, CGEventTapProxy, CGEventType,
};

use super::permissions::accessibility_trusted;

/// Marks events we post ourselves (`kCGEventSourceUserData`); same value as
/// the Windows `dwExtraInfo` tag (phase-4.md §4.3).
pub const SELF_INPUT_TAG: i64 = 0x5057_0001;
/// `pw-work` checks [`PasteTap::is_enabled`] and accessibility this often.
pub const TAP_CHECK_INTERVAL_MS: u64 = 30_000;
/// The tap thread wakes this often to refresh [`PasteTap::is_enabled`] and
/// to notice shutdown.
pub const TAP_LOOP_TICK_MS: u64 = 250;
/// Capacity of the [`TapEvent`] channel, allocated before the tap starts.
pub const TAP_EVENT_QUEUE_LEN: usize = 64;
/// `kVK_ANSI_V`: the V key on an ANSI layout.
pub const KEYCODE_V: u16 = 9;
/// No key is being swallowed.
const NO_KEY: u32 = u32::MAX;

/// What `pw-work` decided for the analyzed clipboard (mirrors `PasteGate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    /// Not analyzed yet (or the analysis timed out).
    Unknown = 0,
    Allow = 1,
    /// Secret or registered secret: ask the user first.
    Intercept = 2,
}

impl Decision {
    fn from_u8(v: u8) -> Decision {
        match v {
            1 => Decision::Allow,
            2 => Decision::Intercept,
            _ => Decision::Unknown,
        }
    }
}

/// Shared atomics read by the tap callback (local mirror of §4.2 `PasteGate`).
///
/// `analyzed_seq` and `decision` are packed into one atomic so the callback
/// never sees a new sequence with an old decision.
#[derive(Debug)]
pub struct TapGate {
    /// `(analyzed_seq << 8) | decision`.
    verdict: AtomicU64,
    /// Latest `changeCount` seen by `pw-clip` (see [`super::monitor`]).
    clipboard_seq: AtomicU32,
    /// The frontmost app is on the paste allowlist (computed by `pw-work`).
    fg_allowed: AtomicBool,
    /// Keycode whose key-down we swallowed, until its key-up.
    swallowed_key: AtomicU32,
}

impl Default for TapGate {
    fn default() -> Self {
        TapGate {
            verdict: AtomicU64::new(Decision::Unknown as u64),
            clipboard_seq: AtomicU32::new(0),
            fg_allowed: AtomicBool::new(false),
            swallowed_key: AtomicU32::new(NO_KEY),
        }
    }
}

impl TapGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// `pw-work`: the clipboard at `seq` was analyzed with `decision`.
    pub fn publish(&self, seq: u32, decision: Decision) {
        let packed = (u64::from(seq) << 8) | decision as u64;
        self.verdict.store(packed, Ordering::Release);
    }

    /// `(analyzed_seq, decision)`.
    pub fn verdict(&self) -> (u32, Decision) {
        let v = self.verdict.load(Ordering::Acquire);
        ((v >> 8) as u32, Decision::from_u8(v as u8))
    }

    /// `pw-clip`: the pasteboard's current sequence number.
    pub fn set_clipboard_seq(&self, seq: u32) {
        self.clipboard_seq.store(seq, Ordering::Release);
    }

    pub fn clipboard_seq(&self) -> u32 {
        self.clipboard_seq.load(Ordering::Acquire)
    }

    /// `pw-work`, on every foreground change.
    pub fn set_fg_allowed(&self, allowed: bool) {
        self.fg_allowed.store(allowed, Ordering::Release);
    }
}

/// The parts of an event [`decide`] looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventFields {
    pub kind: EventKind,
    pub keycode: u16,
    /// The character the key produces in the current layout, when it is a
    /// single BMP char (`CGEventKeyboardGetUnicodeString`).
    pub ch: Option<char>,
    pub mods: Modifiers,
    pub autorepeat: bool,
    /// `kCGEventSourceUserData`.
    pub user_data: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    KeyDown,
    KeyUp,
    FlagsChanged,
    TapDisabledByTimeout,
    TapDisabledByUserInput,
    Other,
}

impl EventKind {
    pub fn from_cg(t: CGEventType) -> EventKind {
        match t {
            CGEventType::KeyDown => EventKind::KeyDown,
            CGEventType::KeyUp => EventKind::KeyUp,
            CGEventType::FlagsChanged => EventKind::FlagsChanged,
            CGEventType::TapDisabledByTimeout => EventKind::TapDisabledByTimeout,
            CGEventType::TapDisabledByUserInput => EventKind::TapDisabledByUserInput,
            _ => EventKind::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub command: bool,
    pub shift: bool,
    pub option: bool,
    pub control: bool,
}

impl Modifiers {
    pub fn from_cg(f: CGEventFlags) -> Modifiers {
        Modifiers {
            command: f.contains(CGEventFlags::MaskCommand),
            shift: f.contains(CGEventFlags::MaskShift),
            option: f.contains(CGEventFlags::MaskAlternate),
            control: f.contains(CGEventFlags::MaskControl),
        }
    }
}

/// Cmd+V, Cmd+Shift+V, Cmd+Option+Shift+V (phase-4.md §4.9.1 `PASTE_COMBOS`).
///
/// The key is the character in the current layout when that is an ASCII
/// letter (Dvorak: the key labelled V), else the physical V key (Cyrillic,
/// Zhuyin…: macOS falls back to the ANSI position for shortcuts).
pub fn is_paste_combo(keycode: u16, ch: Option<char>, m: Modifiers) -> bool {
    let is_v = match ch {
        Some(c) if c.is_ascii_alphabetic() => c.eq_ignore_ascii_case(&'v'),
        _ => keycode == KEYCODE_V,
    };
    let mods_ok = m.command && !m.control && (!m.option || m.shift);
    is_v && mods_ok
}

/// Why a key event was swallowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwallowReason {
    /// The clipboard changed since the last analysis (or none finished yet):
    /// `pw-work` should analyze and re-post the paste if allowed.
    Pending,
    /// The analyzed clipboard must be confirmed first.
    Intercept,
    /// Auto-repeat of a swallowed key.
    Repeat,
    /// Key-up of a swallowed key-down.
    KeyUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Swallow(SwallowReason),
    /// The system disabled the tap: re-enable it and pass the event on.
    ReEnable,
}

/// The tap callback's whole decision. Only atomics are touched.
pub fn decide(e: &EventFields, gate: &TapGate) -> Verdict {
    match e.kind {
        EventKind::TapDisabledByTimeout | EventKind::TapDisabledByUserInput => {
            return Verdict::ReEnable;
        }
        EventKind::FlagsChanged | EventKind::Other => return Verdict::Pass,
        EventKind::KeyDown | EventKind::KeyUp => {}
    }
    if e.user_data == SELF_INPUT_TAG {
        return Verdict::Pass;
    }
    let key = u32::from(e.keycode);
    let swallowed = gate.swallowed_key.load(Ordering::Acquire);
    if e.kind == EventKind::KeyUp {
        if swallowed == key {
            gate.swallowed_key.store(NO_KEY, Ordering::Release);
            return Verdict::Swallow(SwallowReason::KeyUp);
        }
        return Verdict::Pass;
    }
    if e.autorepeat && swallowed == key {
        return Verdict::Swallow(SwallowReason::Repeat);
    }
    if !is_paste_combo(e.keycode, e.ch, e.mods) || gate.fg_allowed.load(Ordering::Acquire) {
        return Verdict::Pass;
    }
    let (analyzed, decision) = gate.verdict();
    let reason = if analyzed != gate.clipboard_seq() {
        SwallowReason::Pending
    } else {
        match decision {
            Decision::Allow => return Verdict::Pass,
            Decision::Intercept => SwallowReason::Intercept,
            Decision::Unknown => SwallowReason::Pending,
        }
    };
    gate.swallowed_key.store(key, Ordering::Release);
    Verdict::Swallow(reason)
}

/// Sent from the callback to `pw-work` (dropped when the queue is full).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapEvent {
    /// A paste key-down was swallowed while the clipboard was at `seq`.
    PasteSwallowed { seq: u32, reason: SwallowReason },
    /// The system disabled the tap and we re-enabled it.
    Reenabled { by_timeout: bool },
}

/// Why the tap could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapStartError {
    /// "Accessibility" is not granted (`intercept = Unavailable(NoAccessibility)`).
    NoAccessibility,
    /// `CGEventTapCreate` returned NULL.
    CreateFailed,
    /// The run loop source could not be created or there is no run loop.
    RunLoop,
    ThreadGone,
}

struct TapContext {
    gate: Arc<TapGate>,
    events: SyncSender<TapEvent>,
    port: AtomicPtr<CFMachPort>,
    enabled: AtomicBool,
    reenabled: AtomicU32,
    quit: AtomicBool,
}

fn fields(kind: EventKind, event: &CGEvent) -> EventFields {
    let ev = Some(event);
    let keycode = CGEvent::integer_value_field(ev, CGEventField::KeyboardEventKeycode);
    let mut buf = [0u16; 2];
    let mut len = 0;
    if matches!(kind, EventKind::KeyDown | EventKind::KeyUp) {
        // SAFETY: `buf` holds 2 units and `len` is a valid out pointer.
        unsafe {
            CGEvent::keyboard_get_unicode_string(ev, 2, &mut len, buf.as_mut_ptr());
        }
    }
    let ch = (len == 1)
        .then(|| char::from_u32(u32::from(buf[0])))
        .flatten();
    EventFields {
        kind,
        keycode: u16::try_from(keycode).unwrap_or(u16::MAX),
        ch,
        mods: Modifiers::from_cg(CGEvent::flags(ev)),
        autorepeat: CGEvent::integer_value_field(ev, CGEventField::KeyboardEventAutorepeat) != 0,
        user_data: CGEvent::integer_value_field(ev, CGEventField::EventSourceUserData),
    }
}

fn handle(ctx: &TapContext, kind: EventKind, event: &CGEvent) -> bool {
    let f = fields(kind, event);
    match decide(&f, &ctx.gate) {
        Verdict::Pass => true,
        Verdict::ReEnable => {
            let port = ctx.port.load(Ordering::Acquire);
            // SAFETY: the tap thread keeps the port retained until after the
            // run loop stops calling us.
            if let Some(port) = unsafe { port.as_ref() } {
                CGEvent::tap_enable(port, true);
            }
            ctx.reenabled.fetch_add(1, Ordering::Relaxed);
            let _ = ctx.events.try_send(TapEvent::Reenabled {
                by_timeout: kind == EventKind::TapDisabledByTimeout,
            });
            true
        }
        Verdict::Swallow(reason) => {
            if matches!(reason, SwallowReason::Pending | SwallowReason::Intercept) {
                let _ = ctx.events.try_send(TapEvent::PasteSwallowed {
                    seq: ctx.gate.clipboard_seq(),
                    reason,
                });
            }
            false
        }
    }
}

unsafe extern "C-unwind" fn tap_callback(
    _proxy: CGEventTapProxy,
    ty: CGEventType,
    event: NonNull<CGEvent>,
    user_info: *mut c_void,
) -> *mut CGEvent {
    // SAFETY: `user_info` is the `TapContext` the tap thread keeps alive in
    // an `Arc` for as long as the tap exists; `event` is valid for the call.
    let (ctx, ev) = unsafe { (&*(user_info as *const TapContext), event.as_ref()) };
    let kind = EventKind::from_cg(ty);
    // Never unwind into CoreGraphics; a panic (there should be none) passes
    // the event on.
    let pass = catch_unwind(AssertUnwindSafe(|| handle(ctx, kind, ev))).unwrap_or(true);
    if pass { event.as_ptr() } else { null_mut() }
}

/// Owns the `pw-hook` thread; dropping it removes the tap and joins.
pub struct PasteTap {
    ctx: Arc<TapContext>,
    thread: Option<JoinHandle<()>>,
}

impl PasteTap {
    /// Installs the tap. `events` receives [`TapEvent`]s; use a
    /// `sync_channel(TAP_EVENT_QUEUE_LEN)` so the callback never allocates.
    pub fn start(
        gate: Arc<TapGate>,
        events: SyncSender<TapEvent>,
    ) -> Result<PasteTap, TapStartError> {
        if !accessibility_trusted() {
            return Err(TapStartError::NoAccessibility);
        }
        let ctx = Arc::new(TapContext {
            gate,
            events,
            port: AtomicPtr::new(null_mut()),
            enabled: AtomicBool::new(false),
            reenabled: AtomicU32::new(0),
            quit: AtomicBool::new(false),
        });
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread_ctx = Arc::clone(&ctx);
        let thread = std::thread::Builder::new()
            .name("pw-hook".into())
            .spawn(move || thread_main(thread_ctx, ready_tx))
            .map_err(|_| TapStartError::ThreadGone)?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(PasteTap {
                ctx,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(TapStartError::ThreadGone)
            }
        }
    }

    /// `CGEventTapIsEnabled`, refreshed every [`TAP_LOOP_TICK_MS`]. `false`
    /// after a re-enable means `Degraded(HookLost)`.
    pub fn is_enabled(&self) -> bool {
        self.ctx.enabled.load(Ordering::Acquire)
    }

    /// How often the system disabled the tap and we turned it back on.
    pub fn reenable_count(&self) -> u32 {
        self.ctx.reenabled.load(Ordering::Relaxed)
    }
}

impl Drop for PasteTap {
    fn drop(&mut self) {
        self.ctx.quit.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

const KEY_EVENTS_MASK: u64 = (1 << CGEventType::KeyDown.0)
    | (1 << CGEventType::KeyUp.0)
    | (1 << CGEventType::FlagsChanged.0);

fn thread_main(ctx: Arc<TapContext>, ready: SyncSender<Result<(), TapStartError>>) {
    let user_info = Arc::as_ptr(&ctx) as *mut c_void;
    // SAFETY: `tap_callback` matches `CGEventTapCallBack`; `user_info` points
    // at `ctx`, which this thread keeps alive until the port is invalidated.
    let port = unsafe {
        CGEvent::tap_create(
            CGEventTapLocation::HIDEventTap,
            CGEventTapPlacement::HeadInsertEventTap,
            CGEventTapOptions::Default,
            KEY_EVENTS_MASK,
            Some(tap_callback),
            user_info,
        )
    };
    let Some(port) = port else {
        let _ = ready.send(Err(TapStartError::CreateFailed));
        return;
    };
    let (Some(source), Some(run_loop)) = (
        CFMachPort::new_run_loop_source(None, Some(&port), 0),
        CFRunLoop::current(),
    ) else {
        port.invalidate();
        let _ = ready.send(Err(TapStartError::RunLoop));
        return;
    };
    ctx.port.store(
        objc2_core_foundation::CFRetained::as_ptr(&port).as_ptr(),
        Ordering::Release,
    );
    // SAFETY: reading CoreFoundation constants.
    let (common, default) = unsafe { (kCFRunLoopCommonModes, kCFRunLoopDefaultMode) };
    run_loop.add_source(Some(&source), common);
    CGEvent::tap_enable(&port, true);
    ctx.enabled
        .store(CGEvent::tap_is_enabled(&port), Ordering::Release);
    let _ = ready.send(Ok(()));

    let tick = TAP_LOOP_TICK_MS as f64 / 1_000.0;
    while !ctx.quit.load(Ordering::Acquire) {
        CFRunLoop::run_in_mode(default, tick, false);
        ctx.enabled
            .store(CGEvent::tap_is_enabled(&port), Ordering::Release);
    }
    CGEvent::tap_enable(&port, false);
    run_loop.remove_source(Some(&source), common);
    port.invalidate();
    ctx.port.store(null_mut(), Ordering::Release);
    ctx.enabled.store(false, Ordering::Release);
}

/// Serializes re-posted pastes so two never interleave.
static POST_LOCK: Mutex<()> = Mutex::new(());

/// Re-posts Cmd+V (key-down and key-up) tagged with [`SELF_INPUT_TAG`], so
/// the tap lets it through. Called by `pw-work` after an analysis allowed a
/// swallowed paste, or after "paste original / masked". Needs accessibility.
pub fn post_paste(mods: Modifiers) -> bool {
    let _guard = POST_LOCK.lock();
    let Some(source) = CGEventSource::new(CGEventSourceStateID::HIDSystemState) else {
        return false;
    };
    CGEventSource::set_user_data(Some(&source), SELF_INPUT_TAG);
    let mut flags = CGEventFlags::MaskCommand;
    if mods.shift {
        flags |= CGEventFlags::MaskShift;
    }
    if mods.option {
        flags |= CGEventFlags::MaskAlternate;
    }
    for down in [true, false] {
        let Some(ev) = CGEvent::new_keyboard_event(Some(&source), KEYCODE_V, down) else {
            return false;
        };
        CGEvent::set_flags(Some(&ev), flags);
        CGEvent::post(CGEventTapLocation::HIDEventTap, Some(&ev));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: Modifiers = Modifiers {
        command: true,
        shift: false,
        option: false,
        control: false,
    };

    fn key(kind: EventKind, keycode: u16, ch: Option<char>, mods: Modifiers) -> EventFields {
        EventFields {
            kind,
            keycode,
            ch,
            mods,
            autorepeat: false,
            user_data: 0,
        }
    }

    fn cmd_v(kind: EventKind) -> EventFields {
        key(kind, KEYCODE_V, Some('v'), CMD)
    }

    fn analyzed(seq: u32, d: Decision) -> TapGate {
        let g = TapGate::new();
        g.set_clipboard_seq(seq);
        g.publish(seq, d);
        g
    }

    #[test]
    fn paste_combos() {
        let shift = Modifiers { shift: true, ..CMD };
        let opt_shift = Modifiers {
            option: true,
            shift: true,
            ..CMD
        };
        let opt = Modifiers {
            option: true,
            ..CMD
        };
        let ctrl = Modifiers {
            control: true,
            ..CMD
        };
        assert!(is_paste_combo(KEYCODE_V, Some('v'), CMD));
        assert!(is_paste_combo(KEYCODE_V, Some('V'), shift));
        assert!(is_paste_combo(KEYCODE_V, Some('v'), opt_shift));
        assert!(!is_paste_combo(KEYCODE_V, Some('v'), opt), "Finder move");
        assert!(!is_paste_combo(KEYCODE_V, Some('v'), ctrl));
        assert!(!is_paste_combo(KEYCODE_V, Some('v'), Modifiers::default()));
        assert!(!is_paste_combo(8, Some('c'), CMD), "copy");
        // Dvorak: the physical V position types K; another key types V.
        assert!(!is_paste_combo(KEYCODE_V, Some('k'), CMD));
        assert!(is_paste_combo(47, Some('v'), CMD));
        // Non-Latin layout or no char: the physical position decides.
        assert!(is_paste_combo(KEYCODE_V, Some('м'), CMD));
        assert!(is_paste_combo(KEYCODE_V, None, CMD));
        assert!(!is_paste_combo(47, Some('м'), CMD));
    }

    #[test]
    fn allow_passes_intercept_swallows_with_key_up() {
        let g = analyzed(7, Decision::Allow);
        assert_eq!(decide(&cmd_v(EventKind::KeyDown), &g), Verdict::Pass);
        assert_eq!(decide(&cmd_v(EventKind::KeyUp), &g), Verdict::Pass);

        let g = analyzed(7, Decision::Intercept);
        assert_eq!(
            decide(&cmd_v(EventKind::KeyDown), &g),
            Verdict::Swallow(SwallowReason::Intercept)
        );
        let mut repeat = cmd_v(EventKind::KeyDown);
        repeat.autorepeat = true;
        assert_eq!(decide(&repeat, &g), Verdict::Swallow(SwallowReason::Repeat));
        // Cmd released first: the V key-up has no modifiers but is still ours.
        let up = key(EventKind::KeyUp, KEYCODE_V, Some('v'), Modifiers::default());
        assert_eq!(decide(&up, &g), Verdict::Swallow(SwallowReason::KeyUp));
        assert_eq!(decide(&up, &g), Verdict::Pass, "only one key-up");
    }

    #[test]
    fn stale_or_unknown_is_pending() {
        let g = analyzed(7, Decision::Allow);
        g.set_clipboard_seq(8);
        assert_eq!(
            decide(&cmd_v(EventKind::KeyDown), &g),
            Verdict::Swallow(SwallowReason::Pending)
        );
        let g = TapGate::new();
        assert_eq!(
            decide(&cmd_v(EventKind::KeyDown), &g),
            Verdict::Swallow(SwallowReason::Pending),
            "nothing analyzed yet"
        );
    }

    #[test]
    fn self_input_allowlist_and_other_keys_pass() {
        let g = analyzed(1, Decision::Intercept);
        let mut tagged = cmd_v(EventKind::KeyDown);
        tagged.user_data = SELF_INPUT_TAG;
        assert_eq!(decide(&tagged, &g), Verdict::Pass);
        tagged.kind = EventKind::KeyUp;
        assert_eq!(decide(&tagged, &g), Verdict::Pass);

        assert_eq!(
            decide(&key(EventKind::KeyDown, 0, Some('a'), CMD), &g),
            Verdict::Pass
        );
        assert_eq!(
            decide(&key(EventKind::FlagsChanged, 55, None, CMD), &g),
            Verdict::Pass
        );

        g.set_fg_allowed(true);
        assert_eq!(decide(&cmd_v(EventKind::KeyDown), &g), Verdict::Pass);
    }

    #[test]
    fn disabled_tap_is_reenabled() {
        let g = TapGate::new();
        for kind in [
            EventKind::TapDisabledByTimeout,
            EventKind::TapDisabledByUserInput,
        ] {
            assert_eq!(decide(&key(kind, 0, None, CMD), &g), Verdict::ReEnable);
        }
        assert_eq!(
            EventKind::from_cg(CGEventType::TapDisabledByUserInput),
            EventKind::TapDisabledByUserInput
        );
        assert_eq!(EventKind::from_cg(CGEventType(1)), EventKind::Other);
    }

    #[test]
    fn verdict_packing_round_trips() {
        let g = TapGate::new();
        assert_eq!(g.verdict(), (0, Decision::Unknown));
        g.publish(u32::MAX, Decision::Intercept);
        assert_eq!(g.verdict(), (u32::MAX, Decision::Intercept));
        g.publish(3, Decision::Allow);
        assert_eq!(g.verdict(), (3, Decision::Allow));
        assert_eq!(Decision::from_u8(9), Decision::Unknown);
    }

    #[test]
    fn modifiers_from_flags() {
        let m = Modifiers::from_cg(CGEventFlags::MaskCommand | CGEventFlags::MaskShift);
        assert!(m.command && m.shift && !m.option && !m.control);
    }
}
