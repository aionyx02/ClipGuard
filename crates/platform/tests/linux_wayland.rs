//! Integration tests against a real wlroots compositor (phase-4.md §4.9.5):
//! headless sway with `ext_data_control_manager_v1` and
//! `zwlr_data_control_manager_v1`. Ignored by default; they change the
//! session clipboard, so run them one at a time inside a throwaway session:
//!
//! ```sh
//! WLR_BACKENDS=headless sway &          # sway >= 1.11 for ext
//! WAYLAND_DISPLAY=wayland-1 cargo test -p paste-warden-platform \
//!     --test linux_wayland -- --ignored --test-threads=1
//! ```
//!
//! Only placeholder text is used, and nothing here prints clipboard content
//! (assertions compare without formatting the values).
#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use paste_warden_platform::clipboard::{ClipEvent, ClipText, EmptyReason, MAX_ANALYZED_CHARS};
use paste_warden_platform::linux::text::{DATA_CONTROL_READ_TIMEOUT_MS, PASSWORD_MANAGER_HINT};
use paste_warden_platform::linux::{
    Backend, ClipboardMonitor, ForegroundHistory, ForegroundSource, ForegroundTracker,
    MonitorOptions, env_from_process, probe,
};
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::{wl_registry, wl_seat};
use wayland_client::{Connection, Dispatch, QueueHandle};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1 as dev, ext_data_control_manager_v1 as mgr,
    ext_data_control_offer_v1 as offer, ext_data_control_source_v1 as src,
};

const WAIT: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(300);

struct Fixture {
    monitor: Option<ClipboardMonitor>,
    events: Receiver<ClipEvent>,
}

impl Fixture {
    fn new(backend: Backend) -> Fixture {
        let (tx, rx) = mpsc::channel();
        let monitor = ClipboardMonitor::start_with(
            MonitorOptions {
                backend: Some(backend),
                ..Default::default()
            },
            Box::new(move |e| {
                let _ = tx.send(e);
            }),
        )
        .expect("monitor starts (is WAYLAND_DISPLAY a data-control compositor?)");
        assert_eq!(monitor.selection().backend, backend);
        let f = Fixture {
            monitor: Some(monitor),
            events: rx,
        };
        // RUN_INITIAL_CHECK: whatever the clipboard holds now.
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

    fn handle(&self) -> paste_warden_platform::linux::ClipboardHandle {
        self.monitor.as_ref().unwrap().handle()
    }
}

fn wl_copy(args: &[&str], text: &str) {
    let mut child = Command::new("wl-copy")
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .expect("wl-copy installed");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

fn wl_paste() -> Option<Vec<u8>> {
    let out = Command::new("wl-paste")
        .args(["--no-newline", "--type", "text/plain;charset=utf-8"])
        .stderr(Stdio::null())
        .output()
        .expect("wl-paste installed");
    out.status.success().then_some(out.stdout)
}

fn kill_wl_copy() {
    let _ = Command::new("pkill").args(["-x", "wl-copy"]).status();
}

// ---- tests, run once per protocol --------------------------------------------

fn copy_is_seen(b: Backend) {
    let f = Fixture::new(b);
    let s0 = f.handle().sequence().unwrap();
    wl_copy(&[], "placeholder alpha");
    let t = f.next_text();
    assert!(t.text.as_str() == "placeholder alpha", "text mismatch");
    assert!(!t.truncated && !t.self_write);
    assert!(t.sequence > s0, "sequence increases");
    wl_copy(&[], "placeholder beta");
    let t2 = f.next_text();
    assert!(t2.text.as_str() == "placeholder beta", "text mismatch");
    assert!(t2.sequence > t.sequence);
    kill_wl_copy();
}

fn hint_only_offer_is_excluded(b: Backend) {
    let f = Fixture::new(b);
    wl_copy(&["--type", PASSWORD_MANAGER_HINT], "secret");
    assert_eq!(f.next_empty(), EmptyReason::Excluded);
    kill_wl_copy();
}

fn image_is_no_text(b: Backend) {
    let f = Fixture::new(b);
    wl_copy(&["--type", "image/png"], "not-a-png");
    assert_eq!(f.next_empty(), EmptyReason::NoText);
    kill_wl_copy();
}

fn write_back_clear_and_self_write(b: Backend) {
    let f = Fixture::new(b);
    let h = f.handle();
    let seq = h.write_text("masked ****").expect("write");
    let t = f.next_text();
    assert_eq!(t.sequence, seq, "write returns the sequence of its change");
    assert!(t.self_write, "own write is marked");
    assert!(t.text.as_str() == "masked ****", "text mismatch");
    assert!(
        wl_paste().as_deref() == Some(b"masked ****".as_slice()),
        "wl-paste reads our write"
    );

    let seq2 = h.clear().expect("clear");
    assert!(seq2 > seq);
    assert_eq!(f.next_empty(), EmptyReason::NoText);
    assert!(wl_paste().is_none(), "clipboard is empty");

    // Somebody else copies: our source is cancelled, theirs is analyzed.
    h.write_text("masked again").unwrap();
    assert!(f.next_text().self_write);
    wl_copy(&[], "placeholder gamma");
    let t = f.next_text();
    assert!(!t.self_write);
    kill_wl_copy();
}

fn snapshot_restore_read_full(b: Backend) {
    let f = Fixture::new(b);
    let h = f.handle();
    wl_copy(&[], "placeholder original");
    f.next_text();
    let snap = h.snapshot().expect("snapshot");
    let full = h.read_full().expect("read_full");
    assert!(
        full.as_str() == "placeholder original",
        "full text mismatch"
    );
    h.write_text("masked").unwrap();
    assert!(f.next_text().self_write);
    h.restore(snap).expect("restore");
    let t = f.next_text();
    assert!(t.self_write, "restore is our own write");
    assert!(t.text.as_str() == "placeholder original", "restored text");
    assert!(wl_paste().as_deref() == Some(b"placeholder original".as_slice()));
    kill_wl_copy();
}

fn large_copy_is_truncated(b: Backend) {
    let f = Fixture::new(b);
    // Not `*`: the streaming test's prefix would be a dedupe repeat.
    let big = "#".repeat(MAX_ANALYZED_CHARS + 10);
    wl_copy(&[], &big);
    let t = f.next_text();
    assert!(t.truncated);
    assert_eq!(t.text.chars().count(), MAX_ANALYZED_CHARS);
    let full = f.handle().read_full().expect("read_full");
    assert_eq!(full.len(), big.len());
    kill_wl_copy();
}

macro_rules! per_protocol {
    ($($name:ident),* $(,)?) => {
        mod ext {
            $( #[test] #[ignore] fn $name() { super::$name(super::Backend::WaylandExt) } )*
        }
        mod wlr {
            $( #[test] #[ignore] fn $name() { super::$name(super::Backend::WaylandWlr) } )*
        }
    };
}

per_protocol!(
    copy_is_seen,
    hint_only_offer_is_excluded,
    image_is_no_text,
    write_back_clear_and_self_write,
    snapshot_restore_read_full,
    large_copy_is_truncated,
);

#[test]
#[ignore]
fn probe_prefers_ext() {
    let s = probe(&env_from_process());
    assert_eq!(s.backend, Backend::WaylandExt);
    assert_eq!(s.foreground, ForegroundSource::WlrForeignToplevel);
}

// ---- a hostile / marked source (ext protocol) --------------------------------

#[derive(Clone, Copy)]
enum Behavior {
    /// Answers with this placeholder text.
    Text(&'static str),
    /// Writes `*` until the reader closes (a source that streams forever).
    Stream,
    /// Keeps the fd open and never writes.
    Silent,
}

struct TestSource {
    stop: Arc<AtomicBool>,
    sends: Arc<AtomicUsize>,
    join: Option<JoinHandle<()>>,
}

struct SrcState {
    behavior: Behavior,
    sends: Arc<AtomicUsize>,
    held: Vec<OwnedFd>,
    stop: Arc<AtomicBool>,
    writers: Vec<JoinHandle<()>>,
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for SrcState {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}
impl Dispatch<wl_seat::WlSeat, ()> for SrcState {
    fn event(
        _: &mut Self,
        _: &wl_seat::WlSeat,
        _: wl_seat::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}
impl Dispatch<mgr::ExtDataControlManagerV1, ()> for SrcState {
    fn event(
        _: &mut Self,
        _: &mgr::ExtDataControlManagerV1,
        _: mgr::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}
impl Dispatch<dev::ExtDataControlDeviceV1, ()> for SrcState {
    fn event(
        _: &mut Self,
        _: &dev::ExtDataControlDeviceV1,
        event: dev::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let dev::Event::Selection { id: Some(o) }
        | dev::Event::PrimarySelection { id: Some(o) } = event
        {
            o.destroy();
        }
    }
    wayland_client::event_created_child!(SrcState, dev::ExtDataControlDeviceV1, [
        dev::EVT_DATA_OFFER_OPCODE => (offer::ExtDataControlOfferV1, ()),
    ]);
}
impl Dispatch<offer::ExtDataControlOfferV1, ()> for SrcState {
    fn event(
        _: &mut Self,
        _: &offer::ExtDataControlOfferV1,
        _: offer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}
impl Dispatch<src::ExtDataControlSourceV1, ()> for SrcState {
    fn event(
        st: &mut Self,
        _: &src::ExtDataControlSourceV1,
        event: src::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let src::Event::Send { fd, .. } = event else {
            return;
        };
        st.sends.fetch_add(1, Ordering::SeqCst);
        match st.behavior {
            Behavior::Text(t) => {
                let mut f = std::fs::File::from(fd);
                let _ = f.write_all(t.as_bytes());
            }
            Behavior::Stream => {
                let stop = Arc::clone(&st.stop);
                st.writers.push(std::thread::spawn(move || {
                    let mut f = std::fs::File::from(fd);
                    let chunk = [b'*'; 65536];
                    while !stop.load(Ordering::SeqCst) && f.write_all(&chunk).is_ok() {}
                }));
            }
            Behavior::Silent => st.held.push(fd),
        }
    }
}

impl TestSource {
    fn start(mimes: &'static [&'static str], behavior: Behavior) -> TestSource {
        let stop = Arc::new(AtomicBool::new(false));
        let sends = Arc::new(AtomicUsize::new(0));
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (stop2, sends2) = (Arc::clone(&stop), Arc::clone(&sends));
        let join = std::thread::spawn(move || {
            let conn = Connection::connect_to_env().expect("wayland");
            let (globals, mut queue) = registry_queue_init::<SrcState>(&conn).unwrap();
            let qh = queue.handle();
            let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=1, ()).unwrap();
            let m: mgr::ExtDataControlManagerV1 = globals.bind(&qh, 1..=1, ()).unwrap();
            let d = m.get_data_device(&seat, &qh, ());
            let s = m.create_data_source(&qh, ());
            for mime in mimes {
                s.offer((*mime).to_owned());
            }
            d.set_selection(Some(&s));
            let mut st = SrcState {
                behavior,
                sends: sends2,
                held: Vec::new(),
                stop: Arc::clone(&stop2),
                writers: Vec::new(),
            };
            queue.roundtrip(&mut st).unwrap();
            ready_tx.send(()).unwrap();
            while !stop2.load(Ordering::SeqCst) {
                queue.dispatch_pending(&mut st).unwrap();
                conn.flush().unwrap();
                if let Some(guard) = queue.prepare_read() {
                    let fd = guard.connection_fd();
                    let mut p = [rustix::event::PollFd::new(
                        &fd,
                        rustix::event::PollFlags::IN,
                    )];
                    let ts = rustix::event::Timespec {
                        tv_sec: 0,
                        tv_nsec: 50_000_000,
                    };
                    let _ = rustix::event::poll(&mut p, Some(&ts));
                    if p[0].revents().contains(rustix::event::PollFlags::IN) {
                        let _ = guard.read();
                    }
                }
            }
            st.held.clear();
            for w in st.writers.drain(..) {
                let _ = w.join();
            }
            s.destroy();
            let _ = conn.flush();
        });
        ready_rx.recv_timeout(WAIT).expect("test source ready");
        TestSource {
            stop,
            sends,
            join: Some(join),
        }
    }

    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }
}

impl Drop for TestSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

const TEXT_AND_HINT: &[&str] = &[
    "text/plain",
    PASSWORD_MANAGER_HINT,
    "text/plain;charset=utf-8",
];
const TEXT_ONLY: &[&str] = &["text/plain;charset=utf-8"];

#[test]
#[ignore]
fn password_manager_hint_is_never_read() {
    // The KeePassXC Wayland offer (S5).
    let f = Fixture::new(Backend::WaylandExt);
    let src = TestSource::start(TEXT_AND_HINT, Behavior::Text("placeholder"));
    assert_eq!(f.next_empty(), EmptyReason::Excluded);
    f.quiet();
    assert_eq!(src.sends(), 0, "the monitor never asked for the text");
}

#[test]
#[ignore]
fn streaming_source_hits_the_cap() {
    let f = Fixture::new(Backend::WaylandExt);
    let start = Instant::now();
    let src = TestSource::start(TEXT_ONLY, Behavior::Stream);
    let t = f.next_text();
    assert!(t.truncated, "cut at the cap");
    assert_eq!(t.text.chars().count(), MAX_ANALYZED_CHARS);
    assert!(start.elapsed() < WAIT);
    assert_eq!(src.sends(), 1);
    // The monitor still works afterwards.
    drop(src);
    wl_copy(&[], "placeholder after stream");
    loop {
        // Dropping the source may clear the selection first.
        match f.next() {
            ClipEvent::Text(t) => {
                assert!(t.text.as_str() == "placeholder after stream");
                break;
            }
            ClipEvent::Empty { .. } => {}
        }
    }
    kill_wl_copy();
}

#[test]
#[ignore]
fn silent_source_times_out() {
    let f = Fixture::new(Backend::WaylandExt);
    let src = TestSource::start(TEXT_ONLY, Behavior::Silent);
    let start = Instant::now();
    assert_eq!(f.next_empty(), EmptyReason::Unreadable);
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(DATA_CONTROL_READ_TIMEOUT_MS / 2));
    assert!(took < WAIT);
    drop(src);
}

// ---- foreground ----------------------------------------------------------------------

#[test]
#[ignore]
fn foreign_toplevel_tracks_the_active_window() {
    let env = env_from_process();
    let history = ForegroundHistory::shared();
    let _tracker = ForegroundTracker::start(
        &env,
        ForegroundSource::WlrForeignToplevel,
        Arc::clone(&history) as Arc<Mutex<_>>,
    )
    .expect("zwlr_foreign_toplevel_manager_v1");
    let mut child = Command::new("foot")
        .args(["--app-id", "pw-test-terminal", "sleep", "10"])
        .stderr(Stdio::null())
        .spawn()
        .expect("foot installed");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = false;
    while Instant::now() < deadline {
        if history
            .lock()
            .unwrap()
            .current()
            .is_some_and(|a| a.class.as_deref() == Some("pw-test-terminal"))
        {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(seen, "the new terminal became the current foreground app");
    let rules = &paste_warden_core::policy::linux::linux_rules().entry;
    let a =
        paste_warden_platform::linux::ForegroundApp::new(Some("foot".into()), None, None, None, 1);
    assert_eq!(
        paste_warden_core::policy::entry::classify_with(rules, a.class_str(), "", a.process_str()),
        paste_warden_core::policy::entry::EntryPoint::Terminal
    );
}
