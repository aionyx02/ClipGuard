//! The `pw-clip` thread on macOS (phase-4.md §4.2, §4.9.1): polls
//! `changeCount` every [`POLL_INTERVAL_MS`], each iteration wrapped in its own
//! `autoreleasepool` (S4: without it, ~30 MB leaks per day). It is the only
//! thread that touches the pasteboard; other threads send it commands through
//! [`ClipboardHandle`]. Same public shape as the Windows monitor.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use objc2::rc::autoreleasepool;
use zeroize::Zeroizing;

use super::clipboard::{
    ClipError, POLL_INTERVAL_MS, Pasteboard, PasteboardAccess, PasteboardSource, Snapshot,
};
use super::foreground::SharedForeground;
use super::paste_tap::TapGate;
use crate::clipboard::{ClipEvent, Deduper, RUN_INITIAL_CHECK, SelfWriteCache, content_hash};

/// Longest wait for the monitor thread to run a command (phase-4.md §4.3).
pub const CLIPBOARD_COMMAND_TIMEOUT_MS: u64 = 1_000;

/// Receives every clipboard change (on the monitor thread; keep it short).
pub type ClipSink = Box<dyn FnMut(ClipEvent) + Send>;

/// How the monitor is set up. [`Default`] watches the general pasteboard.
#[derive(Default)]
pub struct MonitorOptions {
    pub pasteboard: PasteboardSource,
    /// `None` = [`POLL_INTERVAL_MS`]. Tests use a shorter one.
    pub poll_interval: Option<Duration>,
    /// When set, `ClipText::owner_process` is the bundle id of the app that
    /// was in front at the previous poll, i.e. before the change (S4 finding 2).
    pub foreground: Option<SharedForeground>,
    /// When set, every poll publishes the current sequence for the tap.
    pub tap_gate: Option<Arc<TapGate>>,
}

enum Command {
    WriteText(Zeroizing<String>, SyncSender<Result<u32, ClipError>>),
    Clear(SyncSender<Result<u32, ClipError>>),
    ReadFull(SyncSender<Option<Zeroizing<String>>>),
    Snapshot(SyncSender<Snapshot>),
    Restore(Snapshot, SyncSender<Result<u32, ClipError>>),
    Sequence(SyncSender<u32>),
    Access(SyncSender<PasteboardAccess>),
    Quit,
}

struct State {
    pb: Pasteboard,
    dedupe: Deduper,
    self_writes: SelfWriteCache,
    sink: ClipSink,
    start: Instant,
    last_seq: Option<u32>,
    last_poll: Instant,
    foreground: Option<SharedForeground>,
    tap_gate: Option<Arc<TapGate>>,
}

impl State {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn owner_before(&self, t: Instant) -> Option<String> {
        let fg = self.foreground.as_ref()?.lock().ok()?;
        fg.at(t)?.bundle_id.clone()
    }

    fn poll(&mut self) {
        let previous_poll = std::mem::replace(&mut self.last_poll, Instant::now());
        let seq = self.pb.sequence();
        if let Some(g) = &self.tap_gate {
            g.set_clipboard_seq(seq);
        }
        if self.last_seq == Some(seq) {
            return;
        }
        self.last_seq = Some(seq);
        self.on_change(previous_poll);
    }

    fn on_change(&mut self, previous_poll: Instant) {
        let now = self.now_ms();
        let self_writes = &mut self.self_writes;
        let event = self.pb.read_change(|seq| self_writes.is_ours(seq, now));
        match event {
            ClipEvent::Text(mut t) => {
                let hash = content_hash(&t.text);
                if self.dedupe.is_repeat(t.sequence, &hash) {
                    return;
                }
                t.self_write = t.self_write || self.self_writes.contains(&hash, now);
                t.owner_process = self.owner_before(previous_poll);
                (self.sink)(ClipEvent::Text(t));
            }
            ClipEvent::Empty { sequence, reason } => {
                if !self.dedupe.on_empty(sequence) {
                    (self.sink)(ClipEvent::Empty { sequence, reason });
                }
            }
        }
    }

    fn record_write(&mut self, r: &Result<u32, ClipError>, hash: [u8; 32]) {
        if let Ok(seq) = r {
            let now = self.now_ms();
            self.self_writes.record(*seq, hash, now);
        }
    }

    /// Runs one command; `false` means quit.
    fn run(&mut self, cmd: Command) -> bool {
        match cmd {
            Command::WriteText(text, reply) => {
                let r = self.pb.write_text(&text);
                self.record_write(&r, content_hash(&text));
                let _ = reply.send(r);
            }
            Command::Clear(reply) => {
                let _ = reply.send(self.pb.clear());
            }
            Command::ReadFull(reply) => {
                let _ = reply.send(self.pb.read_full());
            }
            Command::Snapshot(reply) => {
                let _ = reply.send(self.pb.snapshot());
            }
            Command::Restore(snap, reply) => {
                let r = self.pb.restore(&snap);
                // The hash is unknown without re-reading; the sequence suffices.
                self.record_write(&r, [0; 32]);
                let _ = reply.send(r);
            }
            Command::Sequence(reply) => {
                let _ = reply.send(self.pb.sequence());
            }
            Command::Access(reply) => {
                let _ = reply.send(self.pb.access());
            }
            Command::Quit => return false,
        }
        true
    }
}

/// Sends commands to the monitor thread. Cheap to clone, `Send`.
#[derive(Clone)]
pub struct ClipboardHandle {
    commands: Sender<Command>,
}

impl ClipboardHandle {
    fn call<T>(&self, make: impl FnOnce(SyncSender<T>) -> Command) -> Option<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.commands.send(make(tx)).ok()?;
        rx.recv_timeout(Duration::from_millis(CLIPBOARD_COMMAND_TIMEOUT_MS))
            .ok()
    }

    /// Replaces the clipboard with plain `text` (masked paste, restore).
    /// Returns the new sequence number.
    pub fn write_text(&self, text: &str) -> Result<u32, ClipError> {
        let text = Zeroizing::new(text.to_owned());
        self.call(|r| Command::WriteText(text, r))
            .unwrap_or(Err(ClipError::Busy))
    }

    /// Clears the clipboard (quarantine).
    pub fn clear(&self) -> Result<u32, ClipError> {
        self.call(Command::Clear).unwrap_or(Err(ClipError::Busy))
    }

    /// The whole clipboard text, for quarantining a truncated read.
    pub fn read_full(&self) -> Option<Zeroizing<String>> {
        self.call(Command::ReadFull).flatten()
    }

    /// Saves the text types before a masked paste.
    pub fn snapshot(&self) -> Result<Snapshot, ClipError> {
        self.call(Command::Snapshot).ok_or(ClipError::Busy)
    }

    /// Puts a snapshot back.
    pub fn restore(&self, snap: Snapshot) -> Result<u32, ClipError> {
        self.call(|r| Command::Restore(snap, r))
            .unwrap_or(Err(ClipError::Busy))
    }

    /// The current `changeCount` as a sequence number.
    pub fn sequence(&self) -> Option<u32> {
        self.call(Command::Sequence)
    }

    /// `NSPasteboard.accessBehavior` of the watched pasteboard.
    pub fn access(&self) -> Option<PasteboardAccess> {
        self.call(Command::Access)
    }
}

/// Why the monitor could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    ThreadGone,
}

/// Owns the monitor thread; dropping it stops the polling and joins.
pub struct ClipboardMonitor {
    handle: ClipboardHandle,
    thread: Option<JoinHandle<()>>,
}

impl ClipboardMonitor {
    /// Starts `pw-clip` on the general pasteboard. `sink` receives every
    /// change, starting with the current clipboard when [`RUN_INITIAL_CHECK`]
    /// is set.
    pub fn start(sink: ClipSink) -> Result<ClipboardMonitor, StartError> {
        Self::start_with(MonitorOptions::default(), sink)
    }

    pub fn start_with(
        opts: MonitorOptions,
        sink: ClipSink,
    ) -> Result<ClipboardMonitor, StartError> {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
        let thread = std::thread::Builder::new()
            .name("pw-clip".into())
            .spawn(move || thread_main(opts, sink, cmd_rx, ready_tx))
            .map_err(|_| StartError::ThreadGone)?;
        ready_rx.recv().map_err(|_| StartError::ThreadGone)?;
        Ok(ClipboardMonitor {
            handle: ClipboardHandle { commands: cmd_tx },
            thread: Some(thread),
        })
    }

    pub fn handle(&self) -> ClipboardHandle {
        self.handle.clone()
    }
}

impl Drop for ClipboardMonitor {
    fn drop(&mut self) {
        let _ = self.handle.commands.send(Command::Quit);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn thread_main(
    opts: MonitorOptions,
    sink: ClipSink,
    commands: Receiver<Command>,
    ready: SyncSender<()>,
) {
    let interval = opts
        .poll_interval
        .unwrap_or(Duration::from_millis(POLL_INTERVAL_MS));
    let pb = autoreleasepool(|_| Pasteboard::open(&opts.pasteboard));
    let mut state = State {
        pb,
        dedupe: Deduper::new(),
        self_writes: SelfWriteCache::new(),
        sink,
        start: Instant::now(),
        last_seq: None,
        last_poll: Instant::now(),
        foreground: opts.foreground,
        tap_gate: opts.tap_gate,
    };
    if !RUN_INITIAL_CHECK {
        state.last_seq = Some(autoreleasepool(|_| state.pb.sequence()));
    }
    let _ = ready.send(());

    loop {
        // The whole iteration, reads and sink included, in one pool (S4).
        autoreleasepool(|_| state.poll());
        let deadline = Instant::now() + interval;
        loop {
            let wait = deadline.saturating_duration_since(Instant::now());
            match commands.recv_timeout(wait) {
                Ok(cmd) => {
                    if !autoreleasepool(|_| state.run(cmd)) {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}
