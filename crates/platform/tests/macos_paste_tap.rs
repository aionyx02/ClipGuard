//! The real CGEventTap (phase-4.md §4.9.1). Needs "Accessibility" for the
//! test runner (inherited from the terminal), so it is ignored by default:
//!
//! ```sh
//! cargo test -p paste-warden-platform --test macos_paste_tap -- --ignored
//! ```
//!
//! The gate is set to Allow for the current clipboard, so the user's own
//! Cmd+V keeps working while the test runs. No key is posted.
#![cfg(target_os = "macos")]

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use paste_warden_platform::macos::foreground::frontmost_app;
use paste_warden_platform::macos::paste_tap::{
    Decision, PasteTap, TAP_EVENT_QUEUE_LEN, TAP_LOOP_TICK_MS, TapGate, TapStartError,
};
use paste_warden_platform::macos::permissions::accessibility_trusted;

#[test]
#[ignore = "installs a system-wide event tap; needs Accessibility"]
fn tap_starts_reports_health_and_stops() {
    let gate = Arc::new(TapGate::new());
    gate.set_clipboard_seq(1);
    gate.publish(1, Decision::Allow);
    let (tx, _rx) = mpsc::sync_channel(TAP_EVENT_QUEUE_LEN);
    match PasteTap::start(Arc::clone(&gate), tx) {
        Ok(tap) => {
            eprintln!("tap installed (Accessibility granted)");
            assert!(accessibility_trusted());
            std::thread::sleep(Duration::from_millis(TAP_LOOP_TICK_MS * 2));
            assert!(tap.is_enabled(), "CGEventTapIsEnabled");
            assert_eq!(tap.reenable_count(), 0);
            drop(tap);
        }
        Err(e) => {
            eprintln!("tap not installed: no Accessibility");
            assert!(!accessibility_trusted());
            assert_eq!(e, TapStartError::NoAccessibility);
        }
    }
}

#[test]
fn start_without_permission_is_a_typed_error() {
    // Only meaningful where Accessibility is not granted (CI); elsewhere the
    // ignored test above covers the tap.
    if accessibility_trusted() {
        return;
    }
    let (tx, _rx) = mpsc::sync_channel(TAP_EVENT_QUEUE_LEN);
    assert_eq!(
        PasteTap::start(Arc::new(TapGate::new()), tx).err(),
        Some(TapStartError::NoAccessibility)
    );
}

#[test]
fn frontmost_app_does_not_panic() {
    // May be None on a headless runner.
    if let Some(app) = frontmost_app() {
        assert!(app.pid != 0);
    }
}
