//! Time since the last user input, for the wallet-swap timing
//! (docs/plan/phase-4.md §4.3 "錢包掉包用的輸入時間"). Only
//! `GetLastInputInfo`: no hook, no key logging. The timing constants live in
//! `core::wallet::swap`; `pw-work` passes the result into core.

use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

// `GetTickCount` lives behind the `Win32_System_SystemInformation` feature,
// which the workspace does not enable; kernel32 is always linked.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetTickCount() -> u32;
}

/// Milliseconds between `last_input` and `now`, both `GetTickCount` values
/// (which wrap every ~49.7 days).
pub fn elapsed_ticks(now: u32, last_input: u32) -> u64 {
    u64::from(now.wrapping_sub(last_input))
}

/// Milliseconds since the last keyboard or mouse input in this session, or 0
/// when Windows cannot tell (treated as "the user is active").
pub fn idle_ms() -> u64 {
    let mut info = LASTINPUTINFO {
        cbSize: size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is initialized with its size, as the API requires.
    if !unsafe { GetLastInputInfo(&mut info) }.as_bool() {
        return 0;
    }
    // SAFETY: plain getter, declared with its documented signature.
    elapsed_ticks(unsafe { GetTickCount() }, info.dwTime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_wraparound() {
        assert_eq!(elapsed_ticks(1_500, 1_000), 500);
        assert_eq!(elapsed_ticks(10, u32::MAX - 9), 20);
        assert_eq!(elapsed_ticks(5, 5), 0);
    }

    #[test]
    fn idle_query_runs() {
        // Any value is fine on a runner; this only exercises the calls.
        let _ = idle_ms();
    }
}
