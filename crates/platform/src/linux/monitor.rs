//! The `pw-clip` thread on Linux (phase-4.md §4.2, §4.9.2): picks a backend
//! with [`super::backend::select`] and runs it. Same public shape as the
//! Windows and macOS monitors: [`ClipboardMonitor::start`] with a sink,
//! [`ClipboardMonitor::handle`] for writes.
//!
//! This is the only place in the Linux module that reads environment
//! variables.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::backend::{Backend, Env, Selection, select};
use super::foreground::SharedForeground;
use super::io::{WakeReceiver, Waker, waker};
use super::text::decode_utf8_prefix;
use super::{wayland, x11};
use crate::clipboard::{
    ClipEvent, ContentHash, Deduper, RUN_INITIAL_CHECK, SelfWriteCache, content_hash,
};

/// Longest wait for the monitor thread to run a command (phase-4.md §4.3).
/// Longer than the macOS value: a write waits for a compositor round trip
/// and for our own read-back.
pub const CLIPBOARD_COMMAND_TIMEOUT_MS: u64 = 2_000;

/// Receives every clipboard change (on the monitor thread; keep it short).
pub type ClipSink = Box<dyn FnMut(ClipEvent) + Send>;

/// A clipboard operation failed. Carries no clipboard content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipError {
    /// The monitor thread did not answer in time (or is gone).
    Busy,
    /// The compositor / X server refused, or the connection broke.
    WriteFailed,
}

/// Why the monitor could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// No usable backend; the selection says why (for the status UI).
    Unavailable(Selection),
    /// The display could not be reached or lacks a needed extension.
    Connect,
    ThreadGone,
}

/// How the monitor is set up. [`Default`] reads the environment and picks
/// the backend per phase-4.md §4.9.2.
#[derive(Default)]
pub struct MonitorOptions {
    /// `None` = read `WAYLAND_DISPLAY`, `DISPLAY`, `XDG_CURRENT_DESKTOP`,
    /// `XDG_RUNTIME_DIR` from the process environment.
    pub env: Option<Env>,
    /// Force a backend (tests: exercise wlr on a compositor that has ext).
    pub backend: Option<Backend>,
    /// When set, `ClipText::owner_process` falls back to the window that was
    /// in front when the change arrived (Wayland gives no owner).
    pub foreground: Option<SharedForeground>,
}

/// Text saved before a masked paste, to put back afterwards.
pub struct Snapshot {
    pub(crate) text: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("has_text", &self.text.is_some())
            .finish()
    }
}

pub(crate) enum Command {
    WriteText(Zeroizing<String>, SyncSender<Result<u32, ClipError>>),
    Clear(SyncSender<Result<u32, ClipError>>),
    ReadFull(SyncSender<Option<Zeroizing<String>>>),
    Snapshot(SyncSender<Snapshot>),
    Restore(Snapshot, SyncSender<Result<u32, ClipError>>),
    Sequence(SyncSender<u32>),
    Quit,
}

/// De-duplication, self-write marking and owner lookup shared by the
/// backends; it is the only thing that calls the sink.
pub(crate) struct Emitter {
    sink: ClipSink,
    dedupe: Deduper,
    self_writes: SelfWriteCache,
    start: Instant,
    foreground: Option<SharedForeground>,
}

impl Emitter {
    fn new(sink: ClipSink, foreground: Option<SharedForeground>) -> Emitter {
        Emitter {
            sink,
            dedupe: Deduper::new(),
            self_writes: SelfWriteCache::new(),
            start: Instant::now(),
            foreground,
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// The hash a write of `bytes` will show up with (the analyzed prefix).
    pub(crate) fn write_hash(bytes: &[u8]) -> ContentHash {
        content_hash(&decode_utf8_prefix(bytes).0)
    }

    /// Remembers our own write before it is read back. Only the hash is
    /// matched: the sequence number of the change is not known until the
    /// compositor / X server announces it, and guessing it could mark a
    /// foreign copy that lands in between as ours (and silence it).
    pub(crate) fn record_write(&mut self, hash: ContentHash) {
        let now = self.now_ms();
        self.self_writes.record(0, hash, now);
    }

    fn owner_at(&self, at: Instant) -> Option<String> {
        let fg = self.foreground.as_ref()?.lock().ok()?;
        let app = fg.at(at)?;
        let p = app.process_str();
        (!p.is_empty()).then(|| p.to_owned())
    }

    /// Sends one change to the sink unless it repeats the previous one.
    pub(crate) fn emit(&mut self, event: ClipEvent, at: Instant) {
        let now = self.now_ms();
        match event {
            ClipEvent::Text(mut t) => {
                let hash = content_hash(&t.text);
                if self.dedupe.is_repeat(t.sequence, &hash, now) {
                    return;
                }
                t.self_write = t.self_write || self.self_writes.contains(&hash, now);
                if t.owner_process.is_none() {
                    t.owner_process = self.owner_at(at);
                }
                (self.sink)(ClipEvent::Text(t));
            }
            ClipEvent::Empty { sequence, reason } => {
                if !self.dedupe.on_empty(sequence) {
                    (self.sink)(ClipEvent::Empty { sequence, reason });
                }
            }
        }
    }
}

/// What a backend thread gets.
pub(crate) struct Thread {
    pub emitter: Emitter,
    pub commands: Receiver<Command>,
    pub wake: WakeReceiver,
    /// Skip the first change (when [`RUN_INITIAL_CHECK`] is off).
    pub initial_check: bool,
}

/// Sends commands to the monitor thread. Cheap to clone, `Send`.
#[derive(Clone)]
pub struct ClipboardHandle {
    commands: Sender<Command>,
    waker: Arc<Waker>,
}

impl ClipboardHandle {
    fn call<T>(&self, make: impl FnOnce(SyncSender<T>) -> Command) -> Option<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.commands.send(make(tx)).ok()?;
        self.waker.wake();
        rx.recv_timeout(Duration::from_millis(CLIPBOARD_COMMAND_TIMEOUT_MS))
            .ok()
    }

    /// Replaces the clipboard with plain `text` (masked paste, restore).
    /// Returns the sequence number of the resulting change.
    pub fn write_text(&self, text: &str) -> Result<u32, ClipError> {
        let text = Zeroizing::new(text.to_owned());
        self.call(|r| Command::WriteText(text, r))
            .unwrap_or(Err(ClipError::Busy))
    }

    /// Clears the clipboard (quarantine).
    pub fn clear(&self) -> Result<u32, ClipError> {
        self.call(Command::Clear).unwrap_or(Err(ClipError::Busy))
    }

    /// The whole clipboard text (up to `FULL_READ_MAX_BYTES`), for
    /// quarantining a truncated read.
    pub fn read_full(&self) -> Option<Zeroizing<String>> {
        self.call(Command::ReadFull).flatten()
    }

    /// Saves the text before a masked paste.
    pub fn snapshot(&self) -> Result<Snapshot, ClipError> {
        self.call(Command::Snapshot).ok_or(ClipError::Busy)
    }

    /// Puts a snapshot back (an empty snapshot clears the clipboard).
    pub fn restore(&self, snap: Snapshot) -> Result<u32, ClipError> {
        self.call(|r| Command::Restore(snap, r))
            .unwrap_or(Err(ClipError::Busy))
    }

    /// The current sequence number (selection changes seen so far).
    pub fn sequence(&self) -> Option<u32> {
        self.call(Command::Sequence)
    }
}

/// Owns the monitor thread; dropping it stops it and joins.
pub struct ClipboardMonitor {
    handle: ClipboardHandle,
    selection: Selection,
    thread: Option<JoinHandle<()>>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The environment the backend selection depends on.
pub fn env_from_process() -> Env {
    let mut env = Env::from_vars(
        var("WAYLAND_DISPLAY"),
        var("DISPLAY"),
        var("XDG_CURRENT_DESKTOP"),
    );
    env.runtime_dir = var("XDG_RUNTIME_DIR").filter(|s| !s.is_empty());
    env
}

/// What [`ClipboardMonitor::start`] would pick right now, without starting
/// anything (connects to the compositor once to list its globals).
pub fn probe(env: &Env) -> Selection {
    select(env, wayland::probe_globals(env))
}

impl ClipboardMonitor {
    /// Starts `pw-clip` on the session's clipboard. `sink` receives every
    /// change, starting with the current clipboard when [`RUN_INITIAL_CHECK`]
    /// is set.
    pub fn start(sink: ClipSink) -> Result<ClipboardMonitor, StartError> {
        Self::start_with(MonitorOptions::default(), sink)
    }

    pub fn start_with(
        opts: MonitorOptions,
        sink: ClipSink,
    ) -> Result<ClipboardMonitor, StartError> {
        let env = opts.env.clone().unwrap_or_else(env_from_process);
        let mut selection = probe(&env);
        if let Some(b) = opts.backend {
            selection.backend = b;
        }
        let (waker, wake) = waker().map_err(|_| StartError::ThreadGone)?;
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<bool>(1);
        let thread = Thread {
            emitter: Emitter::new(sink, opts.foreground),
            commands: cmd_rx,
            wake,
            initial_check: RUN_INITIAL_CHECK,
        };
        let backend = selection.backend;
        let spawn = std::thread::Builder::new().name("pw-clip".into());
        let join = match backend {
            Backend::WaylandExt | Backend::WaylandWlr => {
                let proto = if backend == Backend::WaylandExt {
                    wayland::Proto::Ext
                } else {
                    wayland::Proto::Wlr
                };
                spawn.spawn(move || wayland::run(&env, proto, thread, ready_tx))
            }
            Backend::X11 | Backend::XWayland => {
                spawn.spawn(move || x11::run(&env, thread, ready_tx))
            }
            Backend::None => return Err(StartError::Unavailable(selection)),
        }
        .map_err(|_| StartError::ThreadGone)?;
        match ready_rx.recv() {
            Ok(true) => {}
            Ok(false) => {
                let _ = join.join();
                return Err(StartError::Connect);
            }
            Err(_) => return Err(StartError::ThreadGone),
        }
        Ok(ClipboardMonitor {
            handle: ClipboardHandle {
                commands: cmd_tx,
                waker: Arc::new(waker),
            },
            selection,
            thread: Some(join),
        })
    }

    pub fn handle(&self) -> ClipboardHandle {
        self.handle.clone()
    }

    /// The backend in use and the honest capability report (§4.8).
    pub fn selection(&self) -> Selection {
        self.selection
    }
}

impl Drop for ClipboardMonitor {
    fn drop(&mut self) {
        let _ = self.handle.commands.send(Command::Quit);
        self.handle.waker.wake();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
