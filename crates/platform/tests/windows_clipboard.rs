//! Integration tests against the real Windows clipboard (docs/plan/phase-4.md
//! §4.6). Ignored by default: they change the user's clipboard. Run locally:
//!
//! ```sh
//! cargo test -p paste-warden-platform --test windows_clipboard -- --ignored --test-threads=1
//! ```
//!
//! The text formats on the clipboard are saved first and put back at the end
//! (also on failure). Non-text content (an image, copied files) cannot be
//! saved and is lost. Only fake text is used.
#![cfg(windows)]

use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use paste_warden_platform::clipboard::{ClipEvent, EmptyReason};
use paste_warden_platform::windows::{ClipboardHandle, ClipboardMonitor};

const WAIT: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(700);

struct Fixture {
    monitor: Option<ClipboardMonitor>,
    events: Receiver<ClipEvent>,
    saved: Option<paste_warden_platform::windows::clipboard::Snapshot>,
}

impl Fixture {
    fn new() -> Fixture {
        let (tx, rx) = mpsc::channel();
        let monitor = ClipboardMonitor::start(Box::new(move |e| {
            let _ = tx.send(e);
        }))
        .expect("monitor starts");
        let saved = monitor.handle().snapshot().ok();
        let f = Fixture {
            monitor: Some(monitor),
            events: rx,
            saved,
        };
        // The initial check (RUN_INITIAL_CHECK) reports the current clipboard.
        assert!(f.events.recv_timeout(WAIT).is_ok(), "initial check event");
        f
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let (Some(m), Some(s)) = (self.monitor.as_ref(), self.saved.take()) {
            let _ = m.handle().restore(s);
        }
    }
}

/// Writes text from another process (with an optional extra format holding
/// four zero bytes), the way a browser or password manager would.
fn external_write(text: &str, marker: Option<&str>) {
    let marker = marker
        .map(|m| format!("$d.SetData('{m}', (New-Object IO.MemoryStream (,[byte[]](0,0,0,0))));"))
        .unwrap_or_default();
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms; \
         $d = New-Object Windows.Forms.DataObject; $d.SetText('{text}'); {marker} \
         [Windows.Forms.Clipboard]::SetDataObject($d, $true)"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-STA", "-Command", &script])
        .output()
        .expect("powershell runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn expect_text(e: ClipEvent) -> paste_warden_platform::clipboard::ClipText {
    match e {
        ClipEvent::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    }
}

#[test]
#[ignore = "changes the real clipboard"]
fn own_writes_are_read_and_marked_as_self_writes() {
    let f = Fixture::new();
    let seq = f.handle().write_text("pw-test own write").unwrap();
    let t = expect_text(f.next());
    assert_eq!(t.sequence, seq);
    assert_eq!(t.text.as_str(), "pw-test own write");
    assert!(
        t.self_write,
        "our CanIncludeInClipboardHistory=0 marker is not a password manager"
    );
    assert!(!t.truncated);
}

#[test]
#[ignore = "changes the real clipboard"]
fn external_text_is_read_once() {
    let f = Fixture::new();
    external_write("pw-test external", None);
    let t = expect_text(f.next());
    assert_eq!(t.text.as_str(), "pw-test external");
    assert!(!t.self_write);
    // Same text again from another write: de-duplicated by hash.
    external_write("pw-test external", None);
    assert!(f.quiet(), "repeated content is dropped");
}

#[test]
#[ignore = "changes the real clipboard"]
fn clearing_reports_empty_and_resets_dedupe() {
    let f = Fixture::new();
    external_write("pw-test again", None);
    expect_text(f.next());
    f.handle().clear().unwrap();
    assert!(matches!(
        f.next(),
        ClipEvent::Empty {
            reason: EmptyReason::NoText,
            ..
        }
    ));
    external_write("pw-test again", None);
    let t = expect_text(f.next());
    assert_eq!(
        t.text.as_str(),
        "pw-test again",
        "re-copy after clear is analyzed"
    );
}

#[test]
#[ignore = "changes the real clipboard"]
fn password_manager_markers_skip_the_text() {
    let f = Fixture::new();
    for marker in [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
    ] {
        external_write("pw-test marked", Some(marker));
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
#[ignore = "changes the real clipboard"]
fn snapshot_restores_text() {
    let f = Fixture::new();
    external_write("pw-test original", None);
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

/// A monitor that reads immediately can grab the clipboard between .NET's
/// `OleSetClipboard` and `OleFlushClipboard`, making the other app's copy
/// throw. Every external write must succeed.
#[test]
#[ignore = "changes the real clipboard"]
fn external_writers_are_not_disturbed() {
    let f = Fixture::new();
    let mut failed = 0;
    for i in 0..20 {
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; \
             [Windows.Forms.Clipboard]::SetText('pw-test burst {i}')"
        );
        let ok = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-STA", "-Command", &script])
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            failed += 1;
        }
    }
    while f.events.recv_timeout(QUIET).is_ok() {}
    assert_eq!(failed, 0, "external copies that failed");
}
