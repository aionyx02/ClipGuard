//! The `pw-hook` thread (docs/plan/phase-4.md §4.2, §4.3, §4.4): a
//! `WH_KEYBOARD_LL` hook that swallows paste shortcuts while the clipboard is
//! unanalyzed or must be confirmed, answers the tagged `VK_F24` health probe
//! and swallows Enter for the window with an open confirmation.
//!
//! The callback does no allocation, takes no locks and does no IO: it reads
//! the key event, a few cheap Win32 getters (`GetClipboardSequenceNumber`,
//! `GetForegroundWindow`, `GetAsyncKeyState`) and the atomics in
//! [`PasteGate`], and reports through a pre-allocated bounded channel
//! (`try_send`, never blocks). Windows stops waiting for a callback after
//! about [`HOOK_FAIL_OPEN_MS`] and delivers the key anyway (S3), so the whole
//! decision is the pure [`decide`] and must stay far below
//! [`CALLBACK_BUDGET_US`].

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::{
    GetCurrentThread, GetCurrentThreadId, SetThreadPriority, THREAD_PRIORITY_HIGHEST,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, VK_CONTROL, VK_F24, VK_INSERT, VK_LWIN, VK_MENU, VK_RETURN, VK_RWIN,
    VK_SHIFT, VK_V,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GA_ROOTOWNER, GetAncestor, GetForegroundWindow, GetMessageW,
    HC_ACTION, HHOOK, KBDLLHOOKSTRUCT, MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW,
    SetWindowsHookExW, UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_APP, WM_KEYDOWN, WM_KEYUP,
    WM_SYSKEYDOWN, WM_SYSKEYUP,
};

use crate::gate::{Decision, NO_KEY, PasteGate};
use crate::host::{SwallowReason, WindowId};

pub use crate::probe::{HOOK_PROBE_DEADLINE_MS, HOOK_PROBE_FAIL_THRESHOLD, HOOK_PROBE_INTERVAL_MS};

/// Marks our own `SendInput` events in `dwExtraInfo`. `LLKHF_INJECTED`
/// cannot be used: remote desktop and on-screen keyboards inject every key
/// (S3 finding 3). Same value as macOS.
pub const SELF_INPUT_TAG: usize = 0x5057_0001;
/// The health-check key: sent tagged, swallowed by the callback (S3).
pub const PROBE_VK: u16 = VK_F24.0;
/// Windows ignores a callback that runs longer than this (S3, measured with
/// no `LowLevelHooksTimeout`). Documentation and test threshold only.
pub const HOOK_FAIL_OPEN_MS: u64 = 615;
/// Longest acceptable callback run time (measured worst case 14.8 µs).
pub const CALLBACK_BUDGET_US: u64 = 100;
/// How long `pw-work` waits for the analysis of a swallowed paste before
/// giving up without re-sending it (fail closed, §4.3).
pub const PENDING_ANALYSIS_TIMEOUT_MS: u64 = 2_000;
/// Capacity of the [`HookMsg`] channel, allocated before the hook starts.
pub const HOOK_EVENT_QUEUE_LEN: usize = 64;
/// Longest wait for the hook thread to (re)install the hook.
pub const HOOK_COMMAND_TIMEOUT_MS: u64 = 1_000;

/// Ctrl+V, Ctrl+Shift+V, Shift+Insert (§4.3 `PASTE_COMBOS`), as
/// `(virtual key, ctrl, shift)`. Alt or Win held never matches (AltGr is
/// Ctrl+Alt; Ctrl+Insert is copy).
pub const PASTE_COMBOS: [(u16, bool, bool); 3] = [
    (VK_V.0, true, false),
    (VK_V.0, true, true),
    (VK_INSERT.0, false, true),
];

const VK_ENTER: u16 = VK_RETURN.0;

/// Modifier keys held at the time of the event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
    pub win: bool,
}

/// Whether `vk` with `m` is one of [`PASTE_COMBOS`].
pub fn is_paste_combo(vk: u16, m: Modifiers) -> bool {
    !m.alt
        && !m.win
        && PASTE_COMBOS
            .iter()
            .any(|&(k, ctrl, shift)| k == vk && m.ctrl == ctrl && m.shift == shift)
}

/// Keys whose modifiers [`decide`] needs (the only ones worth a
/// `GetAsyncKeyState` call).
fn is_combo_key(vk: u16) -> bool {
    PASTE_COMBOS.iter().any(|&(k, _, _)| k == vk)
}

/// The parts of a `KBDLLHOOKSTRUCT` [`decide`] looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub vk: u16,
    /// `WM_KEYDOWN` / `WM_SYSKEYDOWN` (auto-repeat arrives as more downs).
    pub down: bool,
    pub extra_info: usize,
}

/// State the callback reads lazily, only when the decision needs it.
pub trait HookEnv {
    /// `GetClipboardSequenceNumber`.
    fn clipboard_seq(&self) -> u32;
    /// `GetForegroundWindow` and its `GA_ROOTOWNER`.
    fn foreground(&self) -> (WindowId, WindowId);
    /// `GetAsyncKeyState` of Ctrl / Shift / Alt / Win.
    fn modifiers(&self) -> Modifiers;
}

/// Why a key was swallowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Swallow {
    /// A paste key-down (report to `pw-work`).
    Paste {
        target: WindowId,
        reason: SwallowReason,
    },
    /// Enter for the window with an open confirmation (report).
    Enter { target: WindowId },
    /// Our tagged probe key-down (report `ProbeAnswered`).
    Probe,
    /// Key-up or auto-repeat of a key we swallowed, or the probe's key-up.
    Quiet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Swallow(Swallow),
}

/// The callback's whole decision (§4.4). Touches only `gate`'s atomics and
/// the lazy getters of `env`.
pub fn decide(e: &KeyEvent, gate: &PasteGate, env: &impl HookEnv) -> Verdict {
    if e.extra_info == SELF_INPUT_TAG {
        if e.vk == PROBE_VK {
            return Verdict::Swallow(if e.down {
                Swallow::Probe
            } else {
                Swallow::Quiet
            });
        }
        return Verdict::Pass;
    }
    let vk = u32::from(e.vk);
    let swallowed = gate.swallowed_key.load(Ordering::Acquire);
    if !e.down {
        if swallowed == vk {
            gate.swallowed_key.store(NO_KEY, Ordering::Release);
            return Verdict::Swallow(Swallow::Quiet);
        }
        return Verdict::Pass;
    }
    if swallowed == vk {
        // Auto-repeat while held: the key-up has not arrived yet.
        return Verdict::Swallow(Swallow::Quiet);
    }
    if e.vk == VK_ENTER {
        let pending = gate.pending_target();
        if pending == 0 {
            return Verdict::Pass;
        }
        let (window, root) = env.foreground();
        if window != pending && root != pending {
            return Verdict::Pass;
        }
        gate.swallowed_key.store(vk, Ordering::Release);
        return Verdict::Swallow(Swallow::Enter { target: pending });
    }
    if !is_combo_key(e.vk) || !is_paste_combo(e.vk, env.modifiers()) {
        return Verdict::Pass;
    }
    let (window, root) = env.foreground();
    if gate.fg_allowed() && root != 0 && root == gate.fg_root() {
        return Verdict::Pass;
    }
    let (analyzed, decision) = gate.verdict();
    let reason = if analyzed != env.clipboard_seq() {
        SwallowReason::Pending
    } else {
        match decision {
            Decision::Allow => return Verdict::Pass,
            Decision::Intercept => SwallowReason::Intercept,
            Decision::Unknown => SwallowReason::Pending,
        }
    };
    gate.swallowed_key.store(vk, Ordering::Release);
    Verdict::Swallow(Swallow::Paste {
        target: window,
        reason,
    })
}

/// Sent from the callback (dropped when the queue is full).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookMsg {
    PasteSwallowed {
        target: WindowId,
        reason: SwallowReason,
    },
    EnterSwallowed {
        target: WindowId,
    },
    ProbeAnswered,
}

/// Why the hook could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStartError {
    /// `SetWindowsHookExW` failed (HRESULT).
    Install(i32),
    ThreadGone,
}

struct HookContext {
    gate: Arc<PasteGate>,
    events: SyncSender<HookMsg>,
    installed: AtomicBool,
    /// Run time of the slowest callback so far, in nanoseconds.
    max_callback_ns: AtomicU64,
    last_callback_ns: AtomicU64,
}

thread_local! {
    /// The hook thread's context; the callback runs on that thread.
    static CONTEXT: Cell<*const HookContext> = const { Cell::new(std::ptr::null()) };
}

/// The real Win32 getters.
struct Win32Env;

fn hwnd_id(h: HWND) -> WindowId {
    h.0 as WindowId
}

impl HookEnv for Win32Env {
    fn clipboard_seq(&self) -> u32 {
        // SAFETY: plain Win32 getter.
        unsafe { GetClipboardSequenceNumber() }
    }

    fn foreground(&self) -> (WindowId, WindowId) {
        // SAFETY: plain Win32 getters; a null window yields a null root.
        unsafe {
            let fg = GetForegroundWindow();
            if fg.is_invalid() {
                return (0, 0);
            }
            (hwnd_id(fg), hwnd_id(GetAncestor(fg, GA_ROOTOWNER)))
        }
    }

    fn modifiers(&self) -> Modifiers {
        // SAFETY: plain Win32 getter; the high bit means "down".
        let down = |vk: u16| unsafe { GetAsyncKeyState(i32::from(vk)) } < 0;
        Modifiers {
            ctrl: down(VK_CONTROL.0),
            shift: down(VK_SHIFT.0),
            alt: down(VK_MENU.0),
            win: down(VK_LWIN.0) || down(VK_RWIN.0),
        }
    }
}

fn on_key(wp: WPARAM, lp: LPARAM) -> bool {
    let ctx = CONTEXT.with(Cell::get);
    // SAFETY: set by the hook thread while it holds an `Arc` to the context,
    // cleared after the hook is removed; the callback runs on that thread.
    let Some(ctx) = (unsafe { ctx.as_ref() }) else {
        return false;
    };
    let started = Instant::now();
    // SAFETY: for HC_ACTION, `lp` points at a KBDLLHOOKSTRUCT for this call.
    let k = unsafe { &*(lp.0 as *const KBDLLHOOKSTRUCT) };
    let msg = wp.0 as u32;
    let down = matches!(msg, WM_KEYDOWN | WM_SYSKEYDOWN);
    if !down && !matches!(msg, WM_KEYUP | WM_SYSKEYUP) {
        return false;
    }
    let event = KeyEvent {
        vk: u16::try_from(k.vkCode).unwrap_or(u16::MAX),
        down,
        extra_info: k.dwExtraInfo,
    };
    let verdict = decide(&event, &ctx.gate, &Win32Env);
    let report = match verdict {
        Verdict::Swallow(Swallow::Paste { target, reason }) => {
            Some(HookMsg::PasteSwallowed { target, reason })
        }
        Verdict::Swallow(Swallow::Enter { target }) => Some(HookMsg::EnterSwallowed { target }),
        Verdict::Swallow(Swallow::Probe) => Some(HookMsg::ProbeAnswered),
        Verdict::Swallow(Swallow::Quiet) | Verdict::Pass => None,
    };
    if let Some(m) = report {
        let _ = ctx.events.try_send(m);
    }
    let ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    ctx.last_callback_ns.store(ns, Ordering::Relaxed);
    ctx.max_callback_ns.fetch_max(ns, Ordering::Relaxed);
    matches!(verdict, Verdict::Swallow(_))
}

unsafe extern "system" fn ll_keyboard_proc(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 {
        // Never unwind into user32; a panic (there should be none) passes
        // the key on rather than breaking the keyboard.
        if catch_unwind(AssertUnwindSafe(|| on_key(wp, lp))).unwrap_or(false) {
            return LRESULT(1);
        }
    }
    // SAFETY: forwarding the unchanged arguments, as the hook contract requires.
    unsafe { CallNextHookEx(None, code, wp, lp) }
}

/// Wakes the loop to drain the command queue.
const WM_PW_COMMAND: u32 = WM_APP + 1;
/// Asks the loop to unhook and exit.
const WM_PW_QUIT: u32 = WM_APP + 2;

enum Command {
    /// Unhook (if installed) and install again.
    Reinstall(SyncSender<Result<(), HookStartError>>),
    /// Unhook and stay unhooked (debug builds; settings).
    Remove(SyncSender<Result<(), HookStartError>>),
}

/// Owns the `pw-hook` thread; dropping it removes the hook and joins.
pub struct PasteHook {
    ctx: Arc<HookContext>,
    thread_id: u32,
    commands: Sender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl PasteHook {
    /// Installs the hook. `events` should come from
    /// `sync_channel(HOOK_EVENT_QUEUE_LEN)` so the callback never allocates.
    pub fn start(
        gate: Arc<PasteGate>,
        events: SyncSender<HookMsg>,
    ) -> Result<PasteHook, HookStartError> {
        let ctx = Arc::new(HookContext {
            gate,
            events,
            installed: AtomicBool::new(false),
            max_callback_ns: AtomicU64::new(0),
            last_callback_ns: AtomicU64::new(0),
        });
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let thread_ctx = Arc::clone(&ctx);
        let thread = std::thread::Builder::new()
            .name("pw-hook".into())
            .spawn(move || thread_main(thread_ctx, cmd_rx, ready_tx))
            .map_err(|_| HookStartError::ThreadGone)?;
        match ready_rx.recv() {
            Ok(Ok(thread_id)) => Ok(PasteHook {
                ctx,
                thread_id,
                commands: cmd_tx,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(HookStartError::ThreadGone)
            }
        }
    }

    fn call(
        &self,
        make: impl FnOnce(SyncSender<Result<(), HookStartError>>) -> Command,
    ) -> Result<(), HookStartError> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.commands
            .send(make(tx))
            .map_err(|_| HookStartError::ThreadGone)?;
        // SAFETY: posting to our own thread's queue (created before `ready`).
        unsafe { PostThreadMessageW(self.thread_id, WM_PW_COMMAND, WPARAM(0), LPARAM(0)) }
            .map_err(|_| HookStartError::ThreadGone)?;
        rx.recv_timeout(Duration::from_millis(HOOK_COMMAND_TIMEOUT_MS))
            .unwrap_or(Err(HookStartError::ThreadGone))
    }

    /// Removes and installs the hook again (after a failed probe; also
    /// restores a [`Self::remove`]).
    pub fn reinstall(&self) -> Result<(), HookStartError> {
        self.call(Command::Reinstall)
    }

    /// Removes the hook but keeps the thread (debug `debug_drop_hook`).
    pub fn remove(&self) -> Result<(), HookStartError> {
        self.call(Command::Remove)
    }

    pub fn is_installed(&self) -> bool {
        self.ctx.installed.load(Ordering::Acquire)
    }

    /// Slowest callback so far, in microseconds (rounded up).
    pub fn max_callback_us(&self) -> u64 {
        self.ctx
            .max_callback_ns
            .load(Ordering::Relaxed)
            .div_ceil(1_000)
    }

    /// The last callback's run time, in nanoseconds.
    pub fn last_callback_ns(&self) -> u64 {
        self.ctx.last_callback_ns.load(Ordering::Relaxed)
    }
}

impl Drop for PasteHook {
    fn drop(&mut self) {
        // SAFETY: posting to our own thread's queue.
        let _ = unsafe { PostThreadMessageW(self.thread_id, WM_PW_QUIT, WPARAM(0), LPARAM(0)) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn install(ctx: &HookContext) -> Result<HHOOK, HookStartError> {
    // SAFETY: our module handle and a callback with the HOOKPROC signature;
    // low-level hooks run on this thread, which pumps messages below.
    let hook = unsafe {
        let module = GetModuleHandleW(None).map_err(|e| HookStartError::Install(e.code().0))?;
        SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(ll_keyboard_proc),
            Some(HINSTANCE(module.0)),
            0,
        )
    }
    .map_err(|e| HookStartError::Install(e.code().0))?;
    // A key-down swallowed before a reinstall may never see its key-up.
    ctx.gate.swallowed_key.store(NO_KEY, Ordering::Release);
    ctx.installed.store(true, Ordering::Release);
    Ok(hook)
}

fn uninstall(ctx: &HookContext, hook: &mut Option<HHOOK>) {
    if let Some(h) = hook.take() {
        // SAFETY: a hook installed by this thread.
        let _ = unsafe { UnhookWindowsHookEx(h) };
    }
    ctx.installed.store(false, Ordering::Release);
}

fn thread_main(
    ctx: Arc<HookContext>,
    commands: Receiver<Command>,
    ready: SyncSender<Result<u32, HookStartError>>,
) {
    let mut msg = MSG::default();
    // SAFETY: creates this thread's message queue so PostThreadMessageW
    // works as soon as `ready` is sent; raises our priority (§4.2).
    let thread_id = unsafe {
        let _ = PeekMessageW(&mut msg, None, 0, 0, PM_NOREMOVE);
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        GetCurrentThreadId()
    };
    CONTEXT.with(|c| c.set(Arc::as_ptr(&ctx)));
    let mut hook = match install(&ctx) {
        Ok(h) => Some(h),
        Err(e) => {
            CONTEXT.with(|c| c.set(std::ptr::null()));
            let _ = ready.send(Err(e));
            return;
        }
    };
    let _ = ready.send(Ok(thread_id));

    // SAFETY: standard message loop; low-level hook callbacks are delivered
    // while this thread waits in GetMessageW.
    while unsafe { GetMessageW(&mut msg, None, 0, 0) }.0 > 0 {
        match msg.message {
            WM_PW_COMMAND => {
                while let Ok(cmd) = commands.try_recv() {
                    match cmd {
                        Command::Reinstall(reply) => {
                            uninstall(&ctx, &mut hook);
                            let r = install(&ctx).map(|h| hook = Some(h));
                            let _ = reply.send(r);
                        }
                        Command::Remove(reply) => {
                            uninstall(&ctx, &mut hook);
                            let _ = reply.send(Ok(()));
                        }
                    }
                }
            }
            WM_PW_QUIT => break,
            // SAFETY: no windows on this thread; dispatch is a formality.
            _ => unsafe {
                DispatchMessageW(&msg);
            },
        }
    }
    uninstall(&ctx, &mut hook);
    CONTEXT.with(|c| c.set(std::ptr::null()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        seq: u32,
        fg: (WindowId, WindowId),
        mods: Modifiers,
    }

    impl HookEnv for Fake {
        fn clipboard_seq(&self) -> u32 {
            self.seq
        }
        fn foreground(&self) -> (WindowId, WindowId) {
            self.fg
        }
        fn modifiers(&self) -> Modifiers {
            self.mods
        }
    }

    const CTRL: Modifiers = Modifiers {
        ctrl: true,
        shift: false,
        alt: false,
        win: false,
    };
    const SHIFT: Modifiers = Modifiers {
        ctrl: false,
        shift: true,
        alt: false,
        win: false,
    };

    fn key(vk: u16, down: bool) -> KeyEvent {
        KeyEvent {
            vk,
            down,
            extra_info: 0,
        }
    }

    fn env(seq: u32, mods: Modifiers) -> Fake {
        Fake {
            seq,
            fg: (100, 10),
            mods,
        }
    }

    fn analyzed(seq: u32, d: Decision) -> PasteGate {
        let g = PasteGate::new();
        g.publish(seq, d);
        g
    }

    fn paste(reason: SwallowReason) -> Verdict {
        Verdict::Swallow(Swallow::Paste {
            target: 100,
            reason,
        })
    }

    #[test]
    fn paste_combos() {
        let ctrl_shift = Modifiers {
            shift: true,
            ..CTRL
        };
        assert!(is_paste_combo(VK_V.0, CTRL));
        assert!(is_paste_combo(VK_V.0, ctrl_shift));
        assert!(is_paste_combo(VK_INSERT.0, SHIFT));
        assert!(!is_paste_combo(VK_INSERT.0, CTRL), "Ctrl+Insert is copy");
        assert!(
            !is_paste_combo(VK_V.0, Modifiers { alt: true, ..CTRL }),
            "AltGr"
        );
        assert!(!is_paste_combo(VK_V.0, Modifiers { win: true, ..CTRL }));
        assert!(
            !is_paste_combo(
                VK_V.0,
                Modifiers {
                    win: true,
                    ..Modifiers::default()
                }
            ),
            "Win+V"
        );
        assert!(!is_paste_combo(VK_V.0, Modifiers::default()));
        assert!(!is_paste_combo(VK_V.0, SHIFT));
        assert!(!is_paste_combo(u16::from(b'C'), CTRL));
    }

    #[test]
    fn allow_passes_intercept_swallows_with_key_up() {
        let g = analyzed(7, Decision::Allow);
        assert_eq!(decide(&key(VK_V.0, true), &g, &env(7, CTRL)), Verdict::Pass);
        assert_eq!(
            decide(&key(VK_V.0, false), &g, &env(7, CTRL)),
            Verdict::Pass
        );

        let g = analyzed(7, Decision::Intercept);
        assert_eq!(
            decide(&key(VK_V.0, true), &g, &env(7, CTRL)),
            paste(SwallowReason::Intercept)
        );
        // Auto-repeat while held.
        assert_eq!(
            decide(&key(VK_V.0, true), &g, &env(7, CTRL)),
            Verdict::Swallow(Swallow::Quiet)
        );
        // Ctrl released first: the V key-up is still ours.
        let none = env(7, Modifiers::default());
        assert_eq!(decide(&key(VK_CONTROL.0, false), &g, &none), Verdict::Pass);
        assert_eq!(
            decide(&key(VK_V.0, false), &g, &none),
            Verdict::Swallow(Swallow::Quiet)
        );
        assert_eq!(
            decide(&key(VK_V.0, false), &g, &none),
            Verdict::Pass,
            "only one key-up"
        );
    }

    #[test]
    fn shift_insert_is_intercepted() {
        let g = analyzed(7, Decision::Intercept);
        assert_eq!(
            decide(&key(VK_INSERT.0, true), &g, &env(7, SHIFT)),
            paste(SwallowReason::Intercept)
        );
        assert_eq!(
            decide(&key(VK_INSERT.0, false), &g, &env(7, SHIFT)),
            Verdict::Swallow(Swallow::Quiet)
        );
    }

    #[test]
    fn stale_or_unknown_is_pending() {
        let g = analyzed(7, Decision::Allow);
        assert_eq!(
            decide(&key(VK_V.0, true), &g, &env(8, CTRL)),
            paste(SwallowReason::Pending)
        );
        let g = PasteGate::new();
        assert_eq!(
            decide(&key(VK_V.0, true), &g, &env(0, CTRL)),
            paste(SwallowReason::Pending),
            "nothing analyzed yet"
        );
    }

    #[test]
    fn tagged_input_passes_and_probe_is_swallowed() {
        let g = analyzed(1, Decision::Intercept);
        let mut tagged = key(VK_V.0, true);
        tagged.extra_info = SELF_INPUT_TAG;
        assert_eq!(decide(&tagged, &g, &env(1, CTRL)), Verdict::Pass);
        tagged.down = false;
        assert_eq!(decide(&tagged, &g, &env(1, CTRL)), Verdict::Pass);

        let mut probe = key(PROBE_VK, true);
        probe.extra_info = SELF_INPUT_TAG;
        assert_eq!(
            decide(&probe, &g, &env(1, CTRL)),
            Verdict::Swallow(Swallow::Probe)
        );
        probe.down = false;
        assert_eq!(
            decide(&probe, &g, &env(1, CTRL)),
            Verdict::Swallow(Swallow::Quiet)
        );
        // An untagged F24 (someone's macro key) is not ours.
        assert_eq!(
            decide(&key(PROBE_VK, true), &g, &env(1, CTRL)),
            Verdict::Pass
        );
        // Injected-looking but untagged pastes are still checked (S3 finding 3).
        let mut other_tag = key(VK_V.0, true);
        other_tag.extra_info = SELF_INPUT_TAG + 1;
        assert_eq!(
            decide(&other_tag, &g, &env(1, CTRL)),
            paste(SwallowReason::Intercept)
        );
    }

    #[test]
    fn allowlisted_foreground_passes_only_while_it_is_in_front() {
        let g = analyzed(1, Decision::Intercept);
        g.set_fg_allowed(true);
        g.set_fg_root(10);
        assert_eq!(decide(&key(VK_V.0, true), &g, &env(1, CTRL)), Verdict::Pass);
        // The foreground already moved on: fg_allowed is stale.
        let moved = Fake {
            seq: 1,
            fg: (200, 20),
            mods: CTRL,
        };
        assert_eq!(
            decide(&key(VK_V.0, true), &g, &moved),
            Verdict::Swallow(Swallow::Paste {
                target: 200,
                reason: SwallowReason::Intercept
            })
        );
        // Unknown foreground never matches.
        let g = analyzed(1, Decision::Intercept);
        g.set_fg_allowed(true);
        let unknown = Fake {
            seq: 1,
            fg: (0, 0),
            mods: CTRL,
        };
        assert!(matches!(
            decide(&key(VK_V.0, true), &g, &unknown),
            Verdict::Swallow(Swallow::Paste { .. })
        ));
    }

    #[test]
    fn enter_is_swallowed_only_for_the_pending_target() {
        let g = analyzed(1, Decision::Allow);
        assert_eq!(
            decide(&key(VK_ENTER, true), &g, &env(1, Modifiers::default())),
            Verdict::Pass
        );
        g.set_pending_target(100);
        let e = env(1, Modifiers::default());
        assert_eq!(
            decide(&key(VK_ENTER, true), &g, &e),
            Verdict::Swallow(Swallow::Enter { target: 100 })
        );
        assert_eq!(
            decide(&key(VK_ENTER, true), &g, &e),
            Verdict::Swallow(Swallow::Quiet)
        );
        assert_eq!(
            decide(&key(VK_ENTER, false), &g, &e),
            Verdict::Swallow(Swallow::Quiet)
        );
        // Matching by root owner (the confirmation was for the top window).
        g.set_pending_target(10);
        assert_eq!(
            decide(&key(VK_ENTER, true), &g, &e),
            Verdict::Swallow(Swallow::Enter { target: 10 })
        );
        decide(&key(VK_ENTER, false), &g, &e);
        // Another window in front: Enter passes.
        g.set_pending_target(300);
        assert_eq!(decide(&key(VK_ENTER, true), &g, &e), Verdict::Pass);
    }

    #[test]
    fn other_keys_pass() {
        let g = analyzed(1, Decision::Intercept);
        for vk in [u16::from(b'A'), VK_CONTROL.0, VK_SHIFT.0, VK_ENTER] {
            assert_eq!(decide(&key(vk, true), &g, &env(1, CTRL)), Verdict::Pass);
            assert_eq!(decide(&key(vk, false), &g, &env(1, CTRL)), Verdict::Pass);
        }
    }
}
