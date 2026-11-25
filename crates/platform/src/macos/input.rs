//! Time since the last user input, for the wallet-swap timing in core
//! (phase-4.md §4.3 `input.rs`, §4.9.1). The macOS counterpart of Windows'
//! `GetLastInputInfo`: no hook, no permission, no keys recorded.

use objc2_core_graphics::{CGEventSource, CGEventSourceStateID, CGEventType};

/// `kCGAnyInputEventType` (`~0`).
const ANY_INPUT_EVENT_TYPE: CGEventType = CGEventType(u32::MAX);

/// Converts the CoreGraphics idle time (seconds, `f64`) to whole
/// milliseconds; NaN, negative and huge values never panic.
pub fn idle_secs_to_ms(secs: f64) -> u64 {
    if secs.is_nan() || secs <= 0.0 {
        0
    } else {
        // `as` saturates at u64::MAX for out-of-range floats.
        (secs * 1_000.0) as u64
    }
}

/// Milliseconds since the last keyboard / mouse / trackpad event in this
/// login session (`CGEventSourceSecondsSinceLastEventType(CombinedSessionState,
/// AnyInputEventType)`).
pub fn idle_ms() -> u64 {
    idle_secs_to_ms(CGEventSource::seconds_since_last_event_type(
        CGEventSourceStateID::CombinedSessionState,
        ANY_INPUT_EVENT_TYPE,
    ))
}

/// The last input as a time on the caller's clock: `now_ms - idle_ms()`.
/// `pw-work` passes the result into core (time is never read in core).
pub fn last_input_ms(now_ms: u64) -> u64 {
    now_ms.saturating_sub(idle_ms())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_never_panics() {
        assert_eq!(idle_secs_to_ms(0.0), 0);
        assert_eq!(idle_secs_to_ms(-3.0), 0);
        assert_eq!(idle_secs_to_ms(f64::NAN), 0);
        assert_eq!(idle_secs_to_ms(1.2345), 1_234);
        assert_eq!(idle_secs_to_ms(f64::INFINITY), u64::MAX);
    }

    #[test]
    fn idle_time_is_available_without_permission() {
        // Works in CI too: no permission is needed. Only sanity-checked.
        let now = idle_ms().saturating_add(1_000);
        assert!(last_input_ms(now) <= now);
        assert_eq!(last_input_ms(0), 0);
    }
}
