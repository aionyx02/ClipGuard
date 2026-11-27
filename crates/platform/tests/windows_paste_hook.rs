//! Integration tests for the `WH_KEYBOARD_LL` paste hook, the tagged probe
//! and the Windows host (docs/plan/phase-4.md §4.4, §4.6, §4.8.4). Ignored by
//! default: they install a global keyboard hook, inject keys and change the
//! clipboard. Run them on a Windows desktop session (not over SSH, not on a
//! headless runner), from a normal (non-elevated) terminal, **release build**
//! (the callback budget is measured), one test at a time:
//!
//! ```sh
//! cargo test --release -p paste-warden-platform --test windows_paste_hook -- --ignored --test-threads=1
//! ```
//!
//! Keep the terminal in front and do not type while they run. The injected
//! keys are a tagged `VK_F24` (swallowed), untagged Ctrl+V / Shift+Insert
//! (expected to be swallowed; if the hook fails they paste the fake text
//! `pw-test` into the terminal prompt, without a newline) and Enter (expected
//! to be swallowed; if not, the terminal gets an empty line). The clipboard's
//! text formats are saved first and put back at the end.
//!
//! One hook per process at a time: low-level hooks chain, and the newest
//! hook swallows the probe before an older one sees it.
#![cfg(windows)]
// Injecting untagged keys needs `SendInput` directly.
#![allow(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use paste_warden_platform::clipboard::ClipEvent;
use paste_warden_platform::gate::{Decision, PasteGate};
use paste_warden_platform::host::SwallowReason;
use paste_warden_platform::windows::clipboard::{Snapshot, sequence};
use paste_warden_platform::windows::paste_hook::{
    CALLBACK_BUDGET_US, HOOK_EVENT_QUEUE_LEN, HOOK_FAIL_OPEN_MS, HOOK_PROBE_DEADLINE_MS,
};
use paste_warden_platform::windows::{ClipboardMonitor, HookMsg, PasteHook, foreground, send};
use windows::Win32::System::Console::SetConsoleCtrlHandler;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, KEYBD_EVENT_FLAGS, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, MAPVK_VK_TO_VSC, MapVirtualKeyW, SendInput, VIRTUAL_KEY, VK_CONTROL,
    VK_INSERT, VK_RETURN, VK_SHIFT, VK_V,
};
use windows::core::BOOL;

const DEADLINE: Duration = Duration::from_millis(HOOK_PROBE_DEADLINE_MS);
const PROBES: usize = 200;
/// Pastes timed after the first (cold) one; the budget applies to these.
const WARM_PASTES: usize = 5;
/// The Ctrl+V test takes about 7 s; past this it is stuck.
const WATCHDOG: Duration = Duration::from_secs(20);

/// Saves the clipboard text and puts a harmless fake text on it.
struct ClipboardGuard {
    monitor: ClipboardMonitor,
    saved: Option<Snapshot>,
}

impl ClipboardGuard {
    fn new() -> ClipboardGuard {
        let monitor = ClipboardMonitor::start(Box::new(|_: ClipEvent| {})).expect("monitor starts");
        let saved = monitor.handle().snapshot().ok();
        monitor
            .handle()
            .write_text("pw-test")
            .expect("fake text written");
        ClipboardGuard { monitor, saved }
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        if let Some(s) = self.saved.take() {
            let _ = self.monitor.handle().restore(s);
        }
    }
}

/// Untagged key events, as a user's keyboard would produce them. Returns
/// how many events `SendInput` accepted; never panics (used from `Drop`).
fn send_keys(keys: &[(VIRTUAL_KEY, bool)]) -> usize {
    let inputs: Vec<INPUT> = keys
        .iter()
        .map(|&(vk, up)| INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    // A real keyboard always sends a scan code; with 0,
                    // Tabby (Electron) turned an injected Ctrl key-up into
                    // a console Ctrl+C for the whole group.
                    // SAFETY: plain Win32 lookup.
                    wScan: u16::try_from(unsafe {
                        MapVirtualKeyW(u32::from(vk.0), MAPVK_VK_TO_VSC)
                    })
                    .unwrap_or(0),
                    // The dedicated Insert key is an extended key; without the
                    // flag it is the numpad one, which NumLock can turn into
                    // a digit with a synthetic Shift-up.
                    dwFlags: KEYBD_EVENT_FLAGS(
                        if up { KEYEVENTF_KEYUP.0 } else { 0 }
                            | if vk == VK_INSERT {
                                KEYEVENTF_EXTENDEDKEY.0
                            } else {
                                0
                            },
                    ),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        })
        .collect();
    // SAFETY: a fully initialized slice of keyboard inputs.
    let sent = unsafe { SendInput(&inputs, size_of::<INPUT>() as i32) };
    sent as usize
}

fn press(keys: &[(VIRTUAL_KEY, bool)]) {
    assert_eq!(send_keys(keys), keys.len(), "SendInput blocked");
}

/// Releases every key the tests press, also when a test panics halfway: a
/// Ctrl left down by one test turns the next test's Shift+Insert into
/// Ctrl+Shift+Insert, which is not a paste.
struct ReleaseKeys;

impl Drop for ReleaseKeys {
    fn drop(&mut self) {
        // Must not panic: a second panic while a failed test unwinds aborts
        // the process and the first failure's message is lost.
        let keys = [
            (VK_V, true),
            (VK_INSERT, true),
            (VK_CONTROL, true),
            (VK_SHIFT, true),
        ];
        if send_keys(&keys) != keys.len() {
            eprintln!("warning: could not release the injected keys");
        }
    }
}

/// Prints console control events (Ctrl+C = 0, Ctrl+Break = 1, close = 2)
/// and lets the default handler run: a run on Windows ended silently, the
/// way a Ctrl+C to the whole console group does.
unsafe extern "system" fn report_ctrl(event: u32) -> BOOL {
    eprintln!("console control event {event} received");
    BOOL(0)
}

fn watch_console_events() {
    // SAFETY: registers a plain function; it only prints.
    if let Err(e) = unsafe { SetConsoleCtrlHandler(Some(report_ctrl), true) } {
        eprintln!("SetConsoleCtrlHandler failed: {e}");
    }
}

fn start_hook() -> (Arc<PasteGate>, PasteHook, Receiver<HookMsg>) {
    let gate = Arc::new(PasteGate::new());
    let (tx, rx) = mpsc::sync_channel(HOOK_EVENT_QUEUE_LEN);
    let hook = PasteHook::start(Arc::clone(&gate), tx).expect("hook installs");
    (gate, hook, rx)
}

fn drain(rx: &Receiver<HookMsg>) {
    while rx.try_recv().is_ok() {}
}

#[test]
#[ignore = "installs a global keyboard hook and injects keys"]
fn tagged_probe_is_answered_within_budget() {
    let (_gate, hook, rx) = start_hook();
    let mut worst = Duration::ZERO;
    for _ in 0..PROBES {
        let t = Instant::now();
        assert!(send::send_probe());
        assert_eq!(rx.recv_timeout(DEADLINE), Ok(HookMsg::ProbeAnswered));
        worst = worst.max(t.elapsed());
    }
    assert!(rx.try_recv().is_err(), "the probe's key-up is not reported");
    let max_us = hook.max_callback_us();
    eprintln!(
        "callback max {max_us} µs; SendInput→answer max {} µs",
        worst.as_micros()
    );
    assert!(
        max_us <= CALLBACK_BUDGET_US,
        "callback {max_us} µs > budget {CALLBACK_BUDGET_US} µs"
    );
    assert!(worst < Duration::from_millis(HOOK_FAIL_OPEN_MS));
}

#[test]
#[ignore = "installs a global keyboard hook, injects keys, changes the clipboard"]
fn intercept_swallows_ctrl_v_with_its_key_up() {
    let started = Instant::now();
    let step = |what: &str| eprintln!("[{:>6} ms] {what}", started.elapsed().as_millis());
    // A run on Windows ended with no output at all; if a step blocks, say
    // which one instead of hanging (the panic hook is not reached then).
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let until = Instant::now() + WATCHDOG;
            while Instant::now() < until {
                if done.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            eprintln!("watchdog: no progress for {WATCHDOG:?}; see the last step above");
            let _ = send_keys(&[(VK_V, true), (VK_CONTROL, true)]);
            std::process::exit(3);
        })
    };
    watch_console_events();
    step("clipboard guard");
    let _clip = ClipboardGuard::new();
    let _keys = ReleaseKeys;
    step("start hook");
    let (gate, hook, rx) = start_hook();
    gate.publish(sequence(), Decision::Intercept);
    // The paste path (clipboard sequence, foreground, modifiers, waking the
    // worker) is the slowest one. The first paste is cold (page faults, the
    // receiver's first wake-up) and is only reported; the budget applies to
    // the warm ones. Both are far below HOOK_FAIL_OPEN_MS.
    let mut times = Vec::with_capacity(WARM_PASTES + 1);
    for i in 0..=WARM_PASTES {
        step(&format!("paste {i}: Ctrl+V down"));
        press(&[(VK_CONTROL, false), (VK_V, false)]);
        step(&format!("paste {i}: wait for the hook"));
        match rx.recv_timeout(DEADLINE) {
            Ok(HookMsg::PasteSwallowed { reason, .. }) => {
                assert_eq!(reason, SwallowReason::Intercept)
            }
            other => panic!("paste {i}: expected a swallowed paste, got {other:?}"),
        }
        times.push(hook.last_callback_ns());
        step(&format!("paste {i}: callback {} ns; key-ups", times[i]));
        // Ctrl released first, then V: the V key-up is swallowed silently.
        press(&[(VK_CONTROL, true), (VK_V, true)]);
        step(&format!("paste {i}: key-ups sent"));
        let extra = rx.recv_timeout(Duration::from_millis(200));
        assert!(extra.is_err(), "paste {i}: key-up reported {extra:?}");
        step(&format!("paste {i}: done"));
    }
    let warm = times[1..].iter().copied().max().unwrap_or(0);
    step(&format!("cold {} ns, warm max {warm} ns", times[0]));
    done.store(true, Ordering::Release);
    let _ = watchdog.join();
    assert!(times[0] < HOOK_FAIL_OPEN_MS * 1_000_000);
    assert!(
        warm <= CALLBACK_BUDGET_US * 1_000,
        "warm paste callback {warm} ns > budget {CALLBACK_BUDGET_US} µs"
    );
}

#[test]
#[ignore = "installs a global keyboard hook, injects keys, changes the clipboard"]
fn unanalyzed_clipboard_is_pending_and_shift_insert_counts() {
    let _clip = ClipboardGuard::new();
    let _keys = ReleaseKeys;
    let (gate, _hook, rx) = start_hook();
    gate.publish(sequence().wrapping_sub(1), Decision::Allow);
    press(&[
        (VK_SHIFT, false),
        (VK_INSERT, false),
        (VK_INSERT, true),
        (VK_SHIFT, true),
    ]);
    match rx.recv_timeout(DEADLINE) {
        Ok(HookMsg::PasteSwallowed { reason, .. }) => assert_eq!(reason, SwallowReason::Pending),
        other => panic!("expected a pending paste, got {other:?}"),
    }
}

#[test]
#[ignore = "installs a global keyboard hook and injects keys"]
fn enter_is_swallowed_for_the_pending_target() {
    let (gate, _hook, rx) = start_hook();
    let fg = foreground::current().expect("a foreground window");
    gate.set_pending_target(fg.window);
    press(&[(VK_RETURN, false), (VK_RETURN, true)]);
    assert_eq!(
        rx.recv_timeout(DEADLINE),
        Ok(HookMsg::EnterSwallowed { target: fg.window })
    );
    gate.set_pending_target(0);
}

#[test]
#[ignore = "installs a global keyboard hook and injects keys"]
fn removed_hook_misses_the_probe_until_reinstalled() {
    let (_gate, hook, rx) = start_hook();
    hook.remove().unwrap();
    assert!(!hook.is_installed());
    assert!(send::send_probe());
    assert!(rx.recv_timeout(DEADLINE).is_err(), "nobody answers");
    hook.reinstall().unwrap();
    assert!(hook.is_installed());
    drain(&rx);
    assert!(send::send_probe());
    assert_eq!(rx.recv_timeout(DEADLINE), Ok(HookMsg::ProbeAnswered));
}

#[test]
#[ignore = "needs an interactive desktop"]
fn foreground_is_described_without_elevation() {
    let fg = foreground::current().expect("a foreground window");
    assert_ne!(fg.window, 0);
    assert_ne!(fg.root, 0);
    assert!(fg.class.is_some());
    assert!(fg.process.is_some(), "{fg:?}");
    assert!(
        fg.title.as_ref().is_none_or(
            |t| t.chars().count() <= paste_warden_platform::host::WINDOW_TITLE_MAX_CHARS
        )
    );
    assert!(
        !fg.elevated,
        "run from a non-elevated terminal: {fg:?} looks elevated"
    );
    assert!(foreground::own_integrity_level().is_some());
}

/// Seconds the manual test waits for physical Ctrl+V presses.
const MANUAL_WAIT: Duration = Duration::from_secs(30);
/// Physical pastes the manual test asks for.
const MANUAL_PASTES: usize = 3;

/// Manual check with the real keyboard (not injected keys): does a swallowed
/// Ctrl+V leak anything to the window in front? Run it from one terminal,
/// then within 30 s click into another terminal that runs `sleep 60` and
/// press Ctrl+V three times. Expected: three "swallowed" lines here, nothing
/// pasted there, and `sleep 60` still running.
///
/// ```sh
/// cargo test --release -p paste-warden-platform --test windows_paste_hook manual_physical_ctrl_v -- --ignored --nocapture
/// ```
#[test]
#[ignore = "manual: waits for the tester to press Ctrl+V on the real keyboard"]
fn manual_physical_ctrl_v() {
    watch_console_events();
    let _clip = ClipboardGuard::new();
    let (gate, _hook, rx) = start_hook();
    gate.publish(sequence(), Decision::Intercept);
    eprintln!(
        "within {MANUAL_WAIT:?}: click into the other terminal and press Ctrl+V {MANUAL_PASTES} times"
    );
    let until = Instant::now() + MANUAL_WAIT;
    let mut seen = 0;
    while seen < MANUAL_PASTES {
        let left = until.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(HookMsg::PasteSwallowed { reason, .. }) => {
                seen += 1;
                eprintln!("swallowed {seen}/{MANUAL_PASTES} ({reason:?})");
            }
            Ok(other) => eprintln!("other hook message: {other:?}"),
            Err(_) => break,
        }
    }
    assert_eq!(seen, MANUAL_PASTES, "not every Ctrl+V reached the hook");
    eprintln!("now check the other terminal: nothing pasted, `sleep 60` still running");
}
