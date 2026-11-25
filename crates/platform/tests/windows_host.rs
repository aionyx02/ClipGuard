//! Integration test for the Windows [`Host`] (docs/plan/phase-4.md §4.2,
//! §4.8.4 item 6). Ignored by default: it installs a global keyboard hook,
//! injects the tagged `VK_F24` probe and reads the clipboard (it does not
//! change it). Run it on a Windows desktop session from a normal
//! (non-elevated) terminal, in a **debug** build (the `debug_drop_hook` part
//! only exists with `debug_assertions`), and not while another PasteWarden
//! instance or hook test is running:
//!
//! ```sh
//! cargo test -p paste-warden-platform --test windows_host -- --ignored --test-threads=1
//! ```
//!
//! [`Host`]: paste_warden_platform::host::Host
#![cfg(windows)]

use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use paste_warden_platform::host::{HookCheck, HostEvent, HostOptions};
use paste_warden_platform::status::{Capability, Reason};
use paste_warden_platform::windows::start_host;

/// Waits for the first host event matching `pred`.
fn wait_for(rx: &Receiver<HostEvent>, pred: impl Fn(&HostEvent) -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(3);
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(e) if pred(&e) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    false
}

#[test]
#[ignore = "installs a global keyboard hook and injects keys"]
fn host_reports_start_probe_and_settings() {
    let (tx, rx) = mpsc::channel();
    let host = start_host(
        Box::new(move |e| {
            let _ = tx.send(e);
        }),
        HostOptions {
            intercept: true,
            version_changed: false,
        },
    )
    .expect("host starts");
    assert!(
        wait_for(&rx, |e| matches!(e, HostEvent::Clip(_))),
        "initial check"
    );
    let status = host.status();
    assert_eq!(status.watch, Capability::Active);
    assert_eq!(status.foreground, Capability::Active);
    assert_eq!(status.intercept, Capability::Active);
    assert!(!host.secure_desktop_active());
    assert!(host.idle_ms().is_some_and(|ms| ms < 60_000));

    assert_eq!(host.check_hook(), HookCheck::ProbeSent);
    assert!(wait_for(&rx, |e| matches!(e, HostEvent::ProbeAnswered)));

    // §4.8.4 item 6: a dropped hook stays dropped through reinstall_hook.
    #[cfg(debug_assertions)]
    {
        host.debug_drop_hook();
        assert_eq!(
            host.status().intercept,
            Capability::Active,
            "worker not told"
        );
        assert_eq!(host.check_hook(), HookCheck::ProbeSent);
        assert!(!wait_for(&rx, |e| matches!(e, HostEvent::ProbeAnswered)));
        host.reinstall_hook().unwrap();
        assert_eq!(host.check_hook(), HookCheck::ProbeSent);
        assert!(!wait_for(&rx, |e| matches!(e, HostEvent::ProbeAnswered)));
        host.debug_restore_hook();
        assert_eq!(host.check_hook(), HookCheck::ProbeSent);
        assert!(wait_for(&rx, |e| matches!(e, HostEvent::ProbeAnswered)));
    }

    host.set_intercept(false).unwrap();
    assert_eq!(
        host.status().intercept,
        Capability::Unavailable(Reason::DisabledInSettings)
    );
    assert_eq!(host.check_hook(), HookCheck::NotApplicable);
    host.set_intercept(true).unwrap();
    assert_eq!(host.check_hook(), HookCheck::ProbeSent);
    assert!(wait_for(&rx, |e| matches!(e, HostEvent::ProbeAnswered)));
}
