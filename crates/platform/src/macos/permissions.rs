//! Permission and Secure Input checks (phase-4.md §4.9.1, §4.9.4).

use objc2_application_services::AXIsProcessTrusted;

use crate::status::{Capability, Reason};

/// Opens System Settings → Privacy & Security → Accessibility.
pub const ACCESSIBILITY_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";

#[link(name = "Carbon", kind = "framework")]
unsafe extern "C" {
    /// HIToolbox `Boolean IsSecureEventInputEnabled(void)`; not bound by the
    /// objc2 crates.
    fn IsSecureEventInputEnabled() -> u8;
}

/// "Accessibility" is granted, so an active event tap can swallow keys.
pub fn accessibility_trusted() -> bool {
    // SAFETY: no arguments, no preconditions; only reads TCC state.
    unsafe { AXIsProcessTrusted() }
}

/// Some app turned on Secure Event Input (a password field, Terminal's
/// "Secure Keyboard Entry"): no event tap receives keys meanwhile.
pub fn secure_input_enabled() -> bool {
    // SAFETY: declared above with the HIToolbox signature (no arguments,
    // returns a C `Boolean`, i.e. u8); no preconditions.
    unsafe { IsSecureEventInputEnabled() != 0 }
}

/// What the paste interception can do right now, as far as the OS says.
/// [`InterceptState::capability`] turns it into the `intercept` field of
/// `ProtectionStatus` (§4.8.1); each non-`Active` value maps to one §4.9.4
/// `Reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptState {
    Active,
    /// `Degraded(HookLost)`: the tap is installed but disabled.
    HookLost,
    /// `Degraded(SecureInput)`.
    SecureInput,
    /// `Unavailable(NoAccessibility)`.
    NoAccessibility,
    /// `Unavailable(NoAccessibilityAfterUpdate)`: the ad-hoc signature changed.
    NoAccessibilityAfterUpdate,
}

impl InterceptState {
    /// The `ProtectionStatus.intercept` value for this state.
    pub fn capability(self) -> Capability {
        match self {
            InterceptState::Active => Capability::Active,
            InterceptState::HookLost => Capability::Degraded(Reason::HookLost),
            InterceptState::SecureInput => Capability::Degraded(Reason::SecureInput),
            InterceptState::NoAccessibility => Capability::Unavailable(Reason::NoAccessibility),
            InterceptState::NoAccessibilityAfterUpdate => {
                Capability::Unavailable(Reason::NoAccessibilityAfterUpdate)
            }
        }
    }
}

/// Combines the checks `pw-work` makes every `TAP_CHECK_INTERVAL_MS`.
/// `version_changed`: this build differs from the one that last ran.
pub fn intercept_state(
    trusted: bool,
    version_changed: bool,
    tap_enabled: bool,
    secure_input: bool,
) -> InterceptState {
    if !trusted {
        if version_changed {
            InterceptState::NoAccessibilityAfterUpdate
        } else {
            InterceptState::NoAccessibility
        }
    } else if !tap_enabled {
        InterceptState::HookLost
    } else if secure_input {
        InterceptState::SecureInput
    } else {
        InterceptState::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_priority() {
        use InterceptState::*;
        assert_eq!(intercept_state(true, false, true, false), Active);
        assert_eq!(intercept_state(true, true, true, false), Active);
        assert_eq!(intercept_state(false, false, true, true), NoAccessibility);
        assert_eq!(
            intercept_state(false, true, false, false),
            NoAccessibilityAfterUpdate
        );
        assert_eq!(intercept_state(true, false, false, true), HookLost);
        assert_eq!(intercept_state(true, false, true, true), SecureInput);
    }

    #[test]
    fn maps_to_status_reasons() {
        use InterceptState::*;
        assert_eq!(Active.capability(), Capability::Active);
        assert_eq!(
            HookLost.capability(),
            Capability::Degraded(Reason::HookLost)
        );
        assert_eq!(
            SecureInput.capability(),
            Capability::Degraded(Reason::SecureInput)
        );
        assert_eq!(
            NoAccessibility.capability(),
            Capability::Unavailable(Reason::NoAccessibility)
        );
        assert_eq!(
            NoAccessibilityAfterUpdate.capability(),
            Capability::Unavailable(Reason::NoAccessibilityAfterUpdate)
        );
    }

    #[test]
    fn checks_do_not_panic() {
        // Values depend on the machine; only check they can be called.
        let _ = accessibility_trusted();
        let _ = secure_input_enabled();
        assert!(ACCESSIBILITY_SETTINGS_URL.starts_with("x-apple.systempreferences:"));
    }
}
