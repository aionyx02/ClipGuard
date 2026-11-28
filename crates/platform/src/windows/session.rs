//! Probe pause conditions that come from the session (docs/plan/phase-4.md
//! §4.3, §4.4): the lock screen and the secure desktop (UAC prompt). In
//! both, `SendInput` is silently dropped, so a missing probe answer says
//! nothing about the hook.
//!
//! Lock / unlock arrive as `WM_WTSSESSION_CHANGE` at the `pw-clip` window,
//! registered with [`register`]; the secure desktop is polled with
//! [`secure_desktop_active`] when a probe is due.

use windows::Win32::Foundation::{HANDLE, HWND, WPARAM};
use windows::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, GetUserObjectInformationW,
    OpenInputDesktop, UOI_NAME,
};
use windows::Win32::UI::WindowsAndMessaging::{WTS_SESSION_LOCK, WTS_SESSION_UNLOCK};

/// Name of the user's normal input desktop; anything else (`Winlogon`, the
/// UAC secure desktop) means our input cannot reach the hook.
pub const INPUT_DESKTOP_DEFAULT: &str = "Default";
/// Desktop names are short; longer ones are cut (and never equal "Default").
const DESKTOP_NAME_MAX_UNITS: usize = 64;

/// Asks Windows to send `WM_WTSSESSION_CHANGE` for this session to `hwnd`.
pub fn register(hwnd: HWND) -> bool {
    // SAFETY: our own window, unregistered with [`unregister`].
    unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) }.is_ok()
}

pub fn unregister(hwnd: HWND) {
    // SAFETY: as above.
    let _ = unsafe { WTSUnRegisterSessionNotification(hwnd) };
}

/// The lock state a `WM_WTSSESSION_CHANGE` reports, if it is about locking.
pub fn lock_change(wp: WPARAM) -> Option<bool> {
    match u32::try_from(wp.0).ok()? {
        WTS_SESSION_LOCK => Some(true),
        WTS_SESSION_UNLOCK => Some(false),
        _ => None,
    }
}

/// Whether the input desktop is a secure desktop (UAC prompt, lock screen).
/// Opening the input desktop fails while one is shown (access denied), and
/// that counts as active too.
pub fn secure_desktop_active() -> bool {
    // SAFETY: read-only desktop handle, closed below.
    let desk =
        match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) } {
            Ok(d) => d,
            Err(_) => return true,
        };
    let mut buf = [0u16; DESKTOP_NAME_MAX_UNITS];
    let mut needed = 0u32;
    // SAFETY: `buf` is writable for `size_of_val(&buf)` bytes.
    let ok = unsafe {
        GetUserObjectInformationW(
            HANDLE(desk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr().cast()),
            size_of_val(&buf) as u32,
            Some(&mut needed),
        )
    }
    .is_ok();
    // SAFETY: `desk` came from OpenInputDesktop.
    let _ = unsafe { CloseDesktop(desk) };
    if !ok {
        return true;
    }
    let end = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    !is_default_desktop(&buf[..end])
}

fn is_default_desktop(name: &[u16]) -> bool {
    String::from_utf16_lossy(name).eq_ignore_ascii_case(INPUT_DESKTOP_DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_messages() {
        assert_eq!(lock_change(WPARAM(WTS_SESSION_LOCK as usize)), Some(true));
        assert_eq!(
            lock_change(WPARAM(WTS_SESSION_UNLOCK as usize)),
            Some(false)
        );
        assert_eq!(lock_change(WPARAM(1)), None, "console connect");
    }

    #[test]
    fn desktop_names() {
        let w = |s: &str| s.encode_utf16().collect::<Vec<_>>();
        assert!(is_default_desktop(&w("Default")));
        assert!(!is_default_desktop(&w("Winlogon")));
        assert!(!is_default_desktop(&w("")));
    }
}
