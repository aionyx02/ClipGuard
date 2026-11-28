//! Integration tests against a real `NSPasteboard` (phase-4.md §4.9.5). Each
//! test uses its own private named pasteboard, so the user's clipboard is
//! never read or changed and the tests run in CI. Only harmless text is
//! used, and no test prints pasteboard content.
#![cfg(target_os = "macos")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use objc2::rc::autoreleasepool;
use objc2_app_kit::NSPasteboard;
use objc2_foundation::{NSData, NSString};
use paste_warden_platform::clipboard::{ClipEvent, ClipText, EmptyReason, MAX_ANALYZED_CHARS};
use paste_warden_platform::macos::clipboard::{
    CONCEALED_TYPES, SOURCE_URL_TYPE, TEXT_TYPE, release_named_pasteboard,
};
use paste_warden_platform::macos::foreground::{ForegroundApp, ForegroundHistory};
use paste_warden_platform::macos::paste_tap::TapGate;
use paste_warden_platform::macos::{
    ClipboardHandle, ClipboardMonitor, MonitorOptions, PasteboardSource,
};

const WAIT: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(300);
const POLL: Duration = Duration::from_millis(20);

fn unique_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        "org.pastewarden.test.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

struct Fixture {
    name: String,
    monitor: Option<ClipboardMonitor>,
    events: Receiver<ClipEvent>,
}

impl Fixture {
    fn with(edit: impl FnOnce(&mut MonitorOptions)) -> Fixture {
        let name = unique_name();
        let (tx, rx) = mpsc::channel();
        let mut opts = MonitorOptions {
            pasteboard: PasteboardSource::Named(name.clone()),
            poll_interval: Some(POLL),
            ..Default::default()
        };
        edit(&mut opts);
        let monitor = ClipboardMonitor::start_with(
            opts,
            Box::new(move |e| {
                let _ = tx.send(e);
            }),
        )
        .expect("monitor starts");
        let f = Fixture {
            name,
            monitor: Some(monitor),
            events: rx,
        };
        // RUN_INITIAL_CHECK: a fresh private pasteboard is empty.
        assert!(matches!(
            f.next(),
            ClipEvent::Empty {
                reason: EmptyReason::NoText,
                ..
            }
        ));
        f
    }

    fn new() -> Fixture {
        Self::with(|_| {})
    }

    fn handle(&self) -> ClipboardHandle {
        self.monitor.as_ref().unwrap().handle()
    }

    fn next(&self) -> ClipEvent {
        self.events.recv_timeout(WAIT).expect("clipboard event")
    }

    fn quiet(&self) -> bool {
        self.events.recv_timeout(QUIET).is_err()
    }

    /// Writes from "another app": a second handle on the same named
    /// pasteboard, with optional extra types.
    fn external_write(&self, text: &str, extra: &[(&str, &[u8])]) {
        autoreleasepool(|_| {
            let pb = NSPasteboard::pasteboardWithName(&NSString::from_str(&self.name));
            pb.clearContents();
            assert!(
                pb.setString_forType(&NSString::from_str(text), &NSString::from_str(TEXT_TYPE))
            );
            for (ty, bytes) in extra {
                assert!(
                    pb.setData_forType(Some(&NSData::with_bytes(bytes)), &NSString::from_str(ty))
                );
            }
        });
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.monitor.take();
        release_named_pasteboard(&self.name);
    }
}

fn expect_text(e: ClipEvent) -> ClipText {
    match e {
        ClipEvent::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    }
}

#[test]
fn own_writes_are_read_and_marked_as_self_writes() {
    let f = Fixture::new();
    let seq = f.handle().write_text("pw-test own write").unwrap();
    assert_eq!(f.handle().sequence(), Some(seq));
    let t = expect_text(f.next());
    assert_eq!(t.sequence, seq);
    assert_eq!(t.text.as_str(), "pw-test own write");
    assert!(t.self_write);
    assert!(!t.truncated);
}

#[test]
fn external_text_is_read_once() {
    let f = Fixture::new();
    f.external_write("pw-test external", &[]);
    let t = expect_text(f.next());
    assert_eq!(t.text.as_str(), "pw-test external");
    assert!(!t.self_write);
    assert_eq!(t.source_url, None);
    f.external_write("pw-test external", &[]);
    assert!(f.quiet(), "repeated content is dropped");
}

#[test]
fn clearing_reports_empty_and_resets_dedupe() {
    let f = Fixture::new();
    f.external_write("pw-test again", &[]);
    expect_text(f.next());
    f.handle().clear().unwrap();
    assert!(matches!(
        f.next(),
        ClipEvent::Empty {
            reason: EmptyReason::NoText,
            ..
        }
    ));
    f.external_write("pw-test again", &[]);
    let t = expect_text(f.next());
    assert_eq!(t.text.as_str(), "pw-test again", "re-copy after clear");
}

#[test]
fn password_manager_markers_skip_the_text() {
    let f = Fixture::new();
    for (i, marker) in CONCEALED_TYPES.iter().enumerate() {
        f.external_write(&format!("pw-test marked {i}"), &[(marker, b"")]);
        assert!(
            matches!(
                f.next(),
                ClipEvent::Empty {
                    reason: EmptyReason::Excluded,
                    ..
                }
            ),
            "{marker}"
        );
    }
}

#[test]
fn chromium_source_url_is_attached() {
    let f = Fixture::new();
    f.external_write(
        "pw-test from a page",
        &[(SOURCE_URL_TYPE, b"https://example.invalid/article")],
    );
    let t = expect_text(f.next());
    assert_eq!(
        t.source_url.as_deref(),
        Some("https://example.invalid/article")
    );
    f.external_write("pw-test bad url", &[(SOURCE_URL_TYPE, b"file:///tmp/x")]);
    assert_eq!(expect_text(f.next()).source_url, None);
}

#[test]
fn long_text_is_truncated_and_read_full_gets_all() {
    let f = Fixture::new();
    let long = "a".repeat(MAX_ANALYZED_CHARS + 10);
    f.external_write(&long, &[]);
    let t = expect_text(f.next());
    assert!(t.truncated);
    assert_eq!(t.text.chars().count(), MAX_ANALYZED_CHARS);
    let full = f.handle().read_full().unwrap();
    assert_eq!(full.len(), long.len());
}

#[test]
fn snapshot_restores_text() {
    let f = Fixture::new();
    f.external_write("pw-test original", &[]);
    expect_text(f.next());
    let snap = f.handle().snapshot().unwrap();
    f.handle().write_text("pw-test masked").unwrap();
    assert!(expect_text(f.next()).self_write);
    f.handle().restore(snap).unwrap();
    let t = expect_text(f.next());
    assert_eq!(t.text.as_str(), "pw-test original");
    assert!(t.self_write);
    assert_eq!(f.handle().read_full().unwrap().as_str(), "pw-test original");
}

#[test]
fn tap_gate_follows_the_sequence() {
    let gate = Arc::new(TapGate::new());
    let g = Arc::clone(&gate);
    let f = Fixture::with(|o| o.tap_gate = Some(g));
    let seq = f.handle().write_text("pw-test gate").unwrap();
    expect_text(f.next());
    assert_eq!(gate.clipboard_seq(), seq);
}

#[test]
fn owner_is_the_app_in_front_before_the_change() {
    let history = ForegroundHistory::shared();
    let h = Arc::clone(&history);
    let f = Fixture::with(|o| o.foreground = Some(h));
    history.lock().unwrap().push(
        ForegroundApp::new(Some("org.example.browser".into()), None, 1),
        Instant::now(),
    );
    // Let one poll pass so the browser is "before" the change.
    std::thread::sleep(POLL * 3);
    f.external_write("pw-test owner", &[]);
    let t = expect_text(f.next());
    assert_eq!(t.owner_process.as_deref(), Some("org.example.browser"));
}

#[test]
fn access_behavior_of_a_private_pasteboard() {
    use paste_warden_platform::macos::PasteboardAccess;
    let f = Fixture::new();
    // Non-general pasteboards always allow access (AppKit header).
    let a = f.handle().access().unwrap();
    assert!(
        matches!(a, PasteboardAccess::Default | PasteboardAccess::AlwaysAllow),
        "{a:?}"
    );
}
