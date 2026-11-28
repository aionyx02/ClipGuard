//! Our own key input (docs/plan/phase-4.md §4.4): the tagged paste that
//! replays a swallowed or confirmed paste into its window, and the tagged
//! `VK_F24` health probe. Every event carries [`SELF_INPUT_TAG`] in
//! `dwExtraInfo`, which the hook lets through (or, for the probe, swallows).
//!
//! `SendInput` into a window of higher integrity is silently dropped (UIPI);
//! the probe scheduler pauses in that case (§4.4), and a paste into such a
//! window never reaches our hook in the first place.

use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, KEYBD_EVENT_FLAGS, KEYBDINPUT, KEYEVENTF_KEYUP, SendInput,
    VIRTUAL_KEY, VK_CONTROL, VK_V,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GA_ROOTOWNER, GetAncestor, GetForegroundWindow, IsWindow, SetForegroundWindow,
};

use super::paste_hook::{PROBE_VK, SELF_INPUT_TAG};
use crate::host::{HostError, WindowId};

/// Longest wait for the target window to become the foreground before the
/// paste is sent.
pub const PASTE_FOCUS_TIMEOUT_MS: u64 = 500;
/// Poll interval while waiting for the focus.
const PASTE_FOCUS_POLL_MS: u64 = 10;

/// Serializes our input so two replays never interleave.
static SEND_LOCK: Mutex<()> = Mutex::new(());

fn key(vk: VIRTUAL_KEY, up: bool) -> INPUT {
    INPUT {
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
                dwExtraInfo: SELF_INPUT_TAG,
            },
        },
    }
}

fn send(inputs: &[INPUT]) -> bool {
    let _guard = SEND_LOCK.lock();
    // SAFETY: `inputs` is a fully initialized slice of keyboard INPUTs.
    let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };
    usize::try_from(sent).is_ok_and(|n| n == inputs.len())
}

/// Sends the tagged probe key (down + up). `false` when `SendInput`
/// reports a block (it does not report UIPI drops).
pub fn send_probe() -> bool {
    let vk = VIRTUAL_KEY(PROBE_VK);
    send(&[key(vk, false), key(vk, true)])
}

fn hwnd(id: WindowId) -> HWND {
    HWND(id as *mut _)
}

fn in_front(target: HWND) -> bool {
    // SAFETY: plain Win32 getters.
    unsafe {
        let fg = GetForegroundWindow();
        fg == target || GetAncestor(fg, GA_ROOTOWNER) == target
    }
}

/// Brings `target` to the front and sends a tagged Ctrl+V. 0 pastes into
/// whatever is in front.
pub fn paste_into(target: WindowId) -> Result<(), HostError> {
    if target != 0 {
        let h = hwnd(target);
        // SAFETY: IsWindow accepts any value; SetForegroundWindow on a valid
        // window. Windows allows it because our confirmation window was the
        // foreground (the user just clicked it).
        unsafe {
            if !IsWindow(Some(h)).as_bool() {
                return Err(HostError::Stopped);
            }
            let _ = SetForegroundWindow(h);
        }
        let deadline = Instant::now() + Duration::from_millis(PASTE_FOCUS_TIMEOUT_MS);
        while !in_front(h) {
            if Instant::now() >= deadline {
                return Err(HostError::Timeout);
            }
            sleep(Duration::from_millis(PASTE_FOCUS_POLL_MS));
        }
    }
    let sent = send(&[
        key(VK_CONTROL, false),
        key(VK_V, false),
        key(VK_V, true),
        key(VK_CONTROL, true),
    ]);
    if sent { Ok(()) } else { Err(HostError::Hook) }
}
