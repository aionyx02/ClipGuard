//! Integration tests against a real X server (phase-4.md §4.9.5): Xvfb with
//! an EWMH window manager (openbox). Ignored by default; they change the
//! CLIPBOARD selection, so run them one at a time on a throwaway display.
//! Starting Xvfb without BIG-REQUESTS makes large copies use INCR:
//!
//! ```sh
//! Xvfb :1 -extension BIG-REQUESTS & DISPLAY=:1 openbox &
//! DISPLAY=:1 cargo test -p paste-warden-platform --test linux_x11 \
//!     -- --ignored --test-threads=1
//! ```
//!
//! Only placeholder text is used, and nothing here prints clipboard content.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use paste_warden_core::policy::entry::{EntryPoint, classify_with};
use paste_warden_core::policy::linux::linux_rules;
use paste_warden_platform::clipboard::{ClipEvent, ClipText, EmptyReason, MAX_ANALYZED_CHARS};
use paste_warden_platform::linux::text::PASSWORD_MANAGER_HINT;
use paste_warden_platform::linux::{
    Backend, ClipboardHandle, ClipboardMonitor, Env, ForegroundHistory, ForegroundSource,
    ForegroundTracker, MonitorOptions,
};

const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(300);

/// X11 only, even if a Wayland session is around.
fn x11_env() -> Env {
    Env::from_vars(None, std::env::var("DISPLAY").ok(), None)
}

struct Fixture {
    monitor: ClipboardMonitor,
    events: Receiver<ClipEvent>,
}

impl Fixture {
    fn new() -> Fixture {
        let (tx, rx) = mpsc::channel();
        let monitor = ClipboardMonitor::start_with(
            MonitorOptions {
                env: Some(x11_env()),
                ..Default::default()
            },
            Box::new(move |e| {
                let _ = tx.send(e);
            }),
        )
        .expect("monitor starts (is DISPLAY set?)");
        assert_eq!(monitor.selection().backend, Backend::X11);
        let f = Fixture {
            monitor,
            events: rx,
        };
        f.next();
        f.quiet();
        f
    }

    fn next(&self) -> ClipEvent {
        self.events.recv_timeout(WAIT).expect("a clipboard event")
    }

    fn next_text(&self) -> ClipText {
        match self.next() {
            ClipEvent::Text(t) => t,
            ClipEvent::Empty { reason, .. } => panic!("expected text, got Empty({reason:?})"),
        }
    }

    fn next_empty(&self) -> EmptyReason {
        match self.next() {
            ClipEvent::Empty { reason, .. } => reason,
            ClipEvent::Text(t) => panic!("expected empty, got text ({t:?})"),
        }
    }

    fn quiet(&self) {
        while self.events.recv_timeout(QUIET).is_ok() {}
    }

    fn handle(&self) -> ClipboardHandle {
        self.monitor.handle()
    }
}

fn xclip_copy(target: Option<&str>, text: &str) {
    let mut args = vec!["-selection", "clipboard", "-i"];
    if let Some(t) = target {
        args.extend(["-t", t]);
    }
    let mut child = Command::new("xclip")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        // xclip stays in the background holding the selection; it must not
        // keep the test's output pipes open.
        .stderr(Stdio::null())
        .spawn()
        .expect("xclip installed");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

fn xclip_paste() -> Option<Vec<u8>> {
    let out = Command::new("xclip")
        .args(["-selection", "clipboard", "-o", "-t", "UTF8_STRING"])
        .stderr(Stdio::null())
        .output()
        .expect("xclip installed");
    out.status.success().then_some(out.stdout)
}

#[test]
#[ignore]
fn copy_is_seen_with_owner() {
    let f = Fixture::new();
    xclip_copy(None, "placeholder alpha");
    let t = f.next_text();
    assert!(t.text.as_str() == "placeholder alpha", "text mismatch");
    assert!(!t.truncated && !t.self_write);
    // S5: xclip forks after connecting, so the XRes pid may be gone; when it
    // is still there the name is xclip.
    assert!(t.owner_process.as_deref().is_none_or(|p| p == "xclip"));
}

#[test]
#[ignore]
fn password_hint_target_is_excluded() {
    let f = Fixture::new();
    xclip_copy(Some(PASSWORD_MANAGER_HINT), "secret");
    assert_eq!(f.next_empty(), EmptyReason::Excluded);
}

#[test]
#[ignore]
fn non_text_target_is_no_text() {
    let f = Fixture::new();
    xclip_copy(Some("image/png"), "not-a-png");
    assert_eq!(f.next_empty(), EmptyReason::NoText);
}

#[test]
#[ignore]
fn write_back_clear_and_self_write() {
    let f = Fixture::new();
    let h = f.handle();
    let seq = h.write_text("masked ****").expect("write");
    let t = f.next_text();
    assert_eq!(t.sequence, seq);
    assert!(t.self_write);
    assert!(
        xclip_paste().as_deref() == Some(b"masked ****".as_slice()),
        "xclip reads our write"
    );
    let targets = Command::new("xclip")
        .args(["-selection", "clipboard", "-o", "-t", "TARGETS"])
        .output()
        .unwrap();
    let targets = String::from_utf8_lossy(&targets.stdout);
    assert!(targets.contains("UTF8_STRING"));
    assert!(!targets.contains("text/html"), "text only");

    h.clear().expect("clear");
    assert_eq!(f.next_empty(), EmptyReason::NoText);
    assert!(xclip_paste().is_none(), "no owner after clear");

    h.write_text("masked again").unwrap();
    assert!(f.next_text().self_write);
    xclip_copy(None, "placeholder beta");
    assert!(!f.next_text().self_write, "someone else took over");
}

#[test]
#[ignore]
fn snapshot_restore_read_full() {
    let f = Fixture::new();
    let h = f.handle();
    xclip_copy(None, "placeholder original");
    f.next_text();
    let snap = h.snapshot().unwrap();
    assert!(h.read_full().unwrap().as_str() == "placeholder original");
    h.write_text("masked").unwrap();
    f.next_text();
    h.restore(snap).unwrap();
    let t = f.next_text();
    assert!(t.self_write && t.text.as_str() == "placeholder original");
    assert!(xclip_paste().as_deref() == Some(b"placeholder original".as_slice()));
}

#[test]
#[ignore]
fn incr_transfer_below_the_cap() {
    // 1 MiB: above the 256 KiB request limit without BIG-REQUESTS → INCR.
    let f = Fixture::new();
    let text = "*".repeat(1 << 20);
    xclip_copy(None, &text);
    let t = f.next_text();
    assert!(!t.truncated);
    assert_eq!(t.text.len(), text.len());
}

#[test]
#[ignore]
fn large_copy_is_truncated() {
    let f = Fixture::new();
    // A different char than the INCR test: an identical analyzed prefix
    // would (correctly) be dropped as a repeat by the Deduper.
    let text = "-".repeat(MAX_ANALYZED_CHARS * 4 + 1000);
    xclip_copy(None, &text);
    let t = f.next_text();
    assert!(t.truncated);
    assert_eq!(t.text.chars().count(), MAX_ANALYZED_CHARS);
}

#[test]
#[ignore]
fn rapid_copies_end_on_the_last_one() {
    // S5 pitfall 6: owners change before conversions return.
    let f = Fixture::new();
    for i in 0..30 {
        xclip_copy(None, &format!("placeholder {i}"));
    }
    let deadline = Instant::now() + WAIT;
    let mut last = None;
    while Instant::now() < deadline {
        match f.events.recv_timeout(QUIET) {
            Ok(ClipEvent::Text(t)) => last = Some(t),
            Ok(ClipEvent::Empty { .. }) => {}
            Err(_) => break,
        }
    }
    let last = last.expect("at least one text");
    assert!(
        last.text.as_str() == "placeholder 29",
        "final event is the final copy"
    );
}

#[test]
#[ignore]
fn active_window_is_tracked() {
    let history = ForegroundHistory::shared();
    let _tracker = ForegroundTracker::start(
        &x11_env(),
        ForegroundSource::X11ActiveWindow,
        Arc::clone(&history),
    )
    .expect("X11 tracker");
    let mut child = Command::new("xterm")
        .args(["-e", "sleep", "10"])
        .spawn()
        .expect("xterm installed");
    let deadline = Instant::now() + WAIT;
    let mut app = None;
    while Instant::now() < deadline {
        if let Some(a) = history.lock().unwrap().current().cloned()
            && a.class.as_deref() == Some("XTerm")
        {
            app = Some(a);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let app = app.expect("xterm became the active window");
    assert_eq!(app.instance.as_deref(), Some("xterm"));
    assert_eq!(app.pid, Some(child.id()));
    assert_eq!(app.process.as_deref(), Some("xterm"));
    assert_eq!(
        classify_with(&linux_rules().entry, app.class_str(), "", app.process_str()),
        EntryPoint::Terminal
    );
}
