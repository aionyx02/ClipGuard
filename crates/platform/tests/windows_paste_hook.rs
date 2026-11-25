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
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, KEYBD_EVENT_FLAGS, KEYBDINPUT, KEYEVENTF_KEYUP, SendInput,
    VIRTUAL_KEY, VK_CONTROL, VK_INSERT, VK_RETURN, VK_SHIFT, VK_V,
};

const DEADLINE: Duration = Duration::from_millis(HOOK_PROBE_DEADLINE_MS);
const PROBES: usize = 200;

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

/// Untagged key events, as a user's keyboard would produce them.
fn press(keys: &[(VIRTUAL_KEY, bool)]) {
    let inputs: Vec<INPUT> = keys
        .iter()
        .map(|&(vk, up)| INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: if up {
                        KEYEVENTF_KEYUP
                    } else {
                        KEYBD_EVENT_FLAGS(0)
                    },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        })
        .collect();
    // SAFETY: a fully initialized slice of keyboard inputs.
    let sent = unsafe { SendInput(&inputs, size_of::<INPUT>() as i32) };
    assert_eq!(sent as usize, inputs.len(), "SendInput blocked");
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
    let _clip = ClipboardGuard::new();
    let (gate, hook, rx) = start_hook();
    gate.publish(sequence(), Decision::Intercept);
    press(&[(VK_CONTROL, false), (VK_V, false)]);
    match rx.recv_timeout(DEADLINE) {
        Ok(HookMsg::PasteSwallowed { reason, .. }) => {
            assert_eq!(reason, SwallowReason::Intercept)
        }
        other => panic!("expected a swallowed paste, got {other:?}"),
    }
    // The paste path (clipboard sequence, foreground, modifiers) is the
    // slowest one.
    let ns = hook.last_callback_ns();
    eprintln!("paste callback {ns} ns");
    assert!(ns <= CALLBACK_BUDGET_US * 1_000);
    // Ctrl released first, then V: the V key-up is swallowed silently.
    press(&[(VK_CONTROL, true), (VK_V, true)]);
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
}

#[test]
#[ignore = "installs a global keyboard hook, injects keys, changes the clipboard"]
fn unanalyzed_clipboard_is_pending_and_shift_insert_counts() {
    let _clip = ClipboardGuard::new();
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
