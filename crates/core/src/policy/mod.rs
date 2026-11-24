//! State machines and decisions used by the apps (pure logic; time is passed in).
//!
//! - [`guard`]: clipboard verdict → quarantine → restore (legacy `ClipboardGuardState`)
//! - [`entry`]: execution-entry warnings (legacy `ExecutionEntryGuard`, `EntryWarningGate`)
//! - [`throttle`]: notification throttling (legacy `NotificationThrottle`)
//! - [`paste`]: paste interception, masking, settings (legacy `PasteGuard`,
//!   `PasteGuardSettingsStore` sanitizing)
//! - [`registered`]: registered-secret HMAC matching and input validation (legacy
//!   `RegisteredSecretStore`, `SecretRegistration`)
//! - [`windows`]: Windows window classes / process names (`rules/policy/windows.json`)

pub mod entry;
pub mod guard;
pub mod paste;
pub mod registered;
pub mod throttle;
pub mod windows;

/// Case-insensitive comparison (approximates .NET `OrdinalIgnoreCase`: per-char
/// case folding, no normalization).
pub(crate) fn eq_ignore_case(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}
