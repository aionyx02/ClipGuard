//! The macOS `Host` against a real `NSPasteboard` (phase-4.md §4.9.1,
//! §4.9.5). Each test uses its own private named pasteboard and foreground
//! history, so the user's clipboard is never read or changed. Ignored by
//! default because the interception test installs a system-wide tap:
//!
//! ```sh
//! cargo test -p paste-warden-platform -- --ignored macos_host
//! ```
//!
//! Only harmless text is used; no test prints pasteboard content. No key is
//! ever posted (`paste_into` is only called with invalid targets).
#![cfg(target_os = "macos")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use paste_warden_platform::clipboard::{ClipEvent, EmptyReason};
use paste_warden_platform::gate::Decision;
use paste_warden_platform::host::{HookCheck, Host, HostError, HostEvent, HostOptions};
use paste_warden_platform::macos::PasteboardSource;
use paste_warden_platform::macos::clipboard::release_named_pasteboard;
use paste_warden_platform::macos::foreground::{ForegroundApp, ForegroundHistory};
use paste_warden_platform::macos::host::{HostConfig, start_host_with};
use paste_warden_platform::macos::permissions::{accessibility_trusted, secure_input_enabled};
use paste_warden_platform::status::{Capability, Reason};

const WAIT: Duration = Duration::from_secs(3);

fn unique_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        "org.pastewarden.test.host.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

struct Fixture {
    name: String,
    host: Option<Box<dyn Host>>,
    events: Receiver<HostEvent>,
    history: paste_warden_platform::macos::foreground::SharedForeground,
}

impl Fixture {
    fn new(opts: HostOptions) -> Fixture {
        let name = unique_name();
        let history = ForegroundHistory::shared();
        let (tx, rx) = mpsc::channel();
        let host = start_host_with(
            Box::new(move |e| {
                let _ = tx.send(e);
            }),
            opts,
            HostConfig {
                pasteboard: PasteboardSource::Named(name.clone()),
                poll_interval: Some(Duration::from_millis(20)),
                foreground: Some(history.clone()),
            },
        )
        .expect("host starts");
        Fixture {
            name,
            host: Some(host),
            events: rx,
            history,
        }
    }

    fn host(&self) -> &dyn Host {
        self.host.as_deref().unwrap()
    }

    /// The next event matching `want`, skipping others.
    fn wait_for(&self, mut want: impl FnMut(&HostEvent) -> bool) -> HostEvent {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let e = self.events.recv_timeout(left).expect("host event");
            if want(&e) {
                return e;
            }
        }
    }

    fn next_clip(&self) -> ClipEvent {
        match self.wait_for(|e| matches!(e, HostEvent::Clip(_))) {
            HostEvent::Clip(c) => c,
            _ => unreachable!(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.host.take();
        release_named_pasteboard(&self.name);
    }
}

const NO_INTERCEPT: HostOptions = HostOptions {
    intercept: false,
    version_changed: false,
};

#[test]
#[ignore = "real pasteboard; run with --ignored macos_host"]
fn macos_host_clipboard_round_trip() {
    let f = Fixture::new(NO_INTERCEPT);
    // RUN_INITIAL_CHECK: a fresh private pasteboard is empty.
    assert!(matches!(
        f.next_clip(),
        ClipEvent::Empty {
            reason: EmptyReason::NoText,
            ..
        }
    ));

    let seq = f.host().write_text("pw-test host write").unwrap();
    match f.next_clip() {
        ClipEvent::Text(t) => {
            assert_eq!(t.sequence, seq);
            assert!(t.self_write);
            assert_eq!(t.text.as_str(), "pw-test host write");
        }
        other => panic!("expected text, got {other:?}"),
    }
    assert_eq!(
        f.host().read_full().as_deref().map(String::as_str),
        Some("pw-test host write")
    );
    assert_eq!(f.host().gate().clipboard_seq(), seq, "pw-clip publishes");

    let snap = f.host().snapshot().unwrap();
    assert!(!format!("{snap:?}").contains("pw-test"));
    f.host().write_text("pw-test masked").unwrap();
    f.host().restore(snap).unwrap();
    assert_eq!(
        f.host().read_full().as_deref().map(String::as_str),
        Some("pw-test host write")
    );

    f.host().clear().unwrap();
    assert_eq!(f.host().read_full(), None);
}

#[test]
#[ignore = "real pasteboard; run with --ignored macos_host"]
fn macos_host_status_and_hook_without_intercept() {
    let f = Fixture::new(NO_INTERCEPT);
    let s = f.host().status();
    assert_eq!(
        s.intercept,
        Capability::Unavailable(Reason::DisabledInSettings)
    );
    assert!(s.write.is_active() && s.foreground.is_active());
    // A private pasteboard has no privacy prompt.
    assert!(s.watch.is_active(), "{:?}", s.watch);
    assert_eq!(f.host().check_hook(), HookCheck::NotApplicable);
    assert_eq!(f.host().paste_into(0), Err(HostError::Unsupported));
    assert_eq!(f.host().paste_into(-4), Err(HostError::Unsupported));
    let _ = f.host().idle_ms();
}

#[test]
#[ignore = "real pasteboard; run with --ignored macos_host"]
fn macos_host_reports_foreground_changes() {
    let f = Fixture::new(NO_INTERCEPT);
    f.history.lock().unwrap().push(
        ForegroundApp::new(Some("org.example.term".into()), Some("Term".into()), 4242),
        Instant::now(),
    );
    let e = f.wait_for(|e| matches!(e, HostEvent::Foreground(info) if info.window == 4242));
    let HostEvent::Foreground(info) = e else {
        unreachable!()
    };
    assert_eq!(info.root, 4242);
    assert_eq!(info.class.as_deref(), Some("org.example.term"));
    assert_eq!(info.process.as_deref(), Some("org.example.term"));
    assert_eq!(info.title, None);
}

#[test]
#[ignore = "installs a system-wide event tap when Accessibility is granted"]
fn macos_host_intercept_follows_permission() {
    let f = Fixture::new(NO_INTERCEPT);
    // Let the user's own Cmd+V through while the tap is installed.
    let gate = f.host().gate();
    gate.set_fg_allowed(true);
    gate.publish(gate.clipboard_seq(), Decision::Allow);

    let installed = f.host().set_intercept(true);
    if accessibility_trusted() {
        eprintln!("Accessibility granted: tap installed");
        installed.expect("tap installs");
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(f.host().check_hook(), HookCheck::Healthy);
        let expected = if secure_input_enabled() {
            Capability::Degraded(Reason::SecureInput)
        } else {
            Capability::Active
        };
        assert_eq!(f.host().status().intercept, expected);

        #[cfg(debug_assertions)]
        {
            f.host().debug_drop_hook();
            assert_eq!(f.host().check_hook(), HookCheck::Lost);
            f.host().debug_restore_hook();
            std::thread::sleep(Duration::from_millis(600));
            assert_eq!(f.host().check_hook(), HookCheck::Healthy);
        }
        f.host().reinstall_hook().expect("reinstall");
    } else {
        eprintln!("no Accessibility: tap not installed (skipping the tap checks)");
        assert_eq!(installed, Err(HostError::Hook));
        assert_eq!(f.host().check_hook(), HookCheck::Lost);
        assert_eq!(
            f.host().status().intercept,
            Capability::Unavailable(Reason::NoAccessibility)
        );
    }
    f.host().set_intercept(false).unwrap();
    assert_eq!(f.host().check_hook(), HookCheck::NotApplicable);
}
