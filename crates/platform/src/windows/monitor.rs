//! The `pw-clip` thread (docs/plan/phase-4.md §4.2): a message-only window
//! with `AddClipboardFormatListener`. It is the only thread that opens the
//! clipboard; other threads send it commands through [`ClipboardHandle`].
//!
//! With [`MonitorOptions`] the same thread also runs the foreground
//! `SetWinEventHook` ([`super::foreground`]) and receives session lock
//! notifications ([`super::session`]), as §4.2 assigns them to `pw-clip`.

use std::cell::RefCell;
use std::sync::Once;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, RemoveClipboardFormatListener,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HWND_MESSAGE,
    KillTimer, MSG, PostMessageW, RegisterClassExW, SetTimer, WINDOW_EX_STYLE, WINDOW_STYLE,
    WM_APP, WM_CLIPBOARDUPDATE, WM_TIMER, WM_WTSSESSION_CHANGE, WNDCLASSEXW,
};
use windows::core::{PCWSTR, w};
use zeroize::Zeroizing;

use super::clipboard::{self as raw, ClipError, Formats, Snapshot};
use super::foreground::{ForegroundSink, ForegroundWatch};
use super::session;
use crate::clipboard::{ClipEvent, Deduper, RUN_INITIAL_CHECK, SelfWriteCache, content_hash};

/// Longest wait for the monitor thread to run a command.
pub const CLIPBOARD_COMMAND_TIMEOUT_MS: u64 = 1_000;
/// Delay between `WM_CLIPBOARDUPDATE` and reading. Reading at once grabs the
/// clipboard while the writer may still need it (.NET's `SetDataObject(…, true)`
/// reopens it for `OleFlushClipboard`, and that copy then fails); every new
/// notification inside the delay restarts it, which also merges bursts.
pub const CLIPBOARD_READ_DELAY_MS: u32 = 25;
/// Timer id of the delayed read.
const READ_TIMER_ID: usize = 1;

const CLASS_NAME: PCWSTR = w!("PasteWardenClipboardMonitor");
/// Wakes the loop to drain the command queue.
const WM_PW_COMMAND: u32 = WM_APP + 1;
/// Asks the loop to unregister and exit.
const WM_PW_QUIT: u32 = WM_APP + 2;

/// Receives every clipboard change (on the monitor thread; keep it short).
pub type ClipSink = Box<dyn FnMut(ClipEvent) + Send>;
/// Receives session lock (true) / unlock (false) on the monitor thread.
pub type SessionSink = Box<dyn FnMut(bool) + Send>;

/// What else `pw-clip` watches besides the clipboard.
#[derive(Default)]
pub struct MonitorOptions {
    /// Foreground changes (`SetWinEventHook(EVENT_SYSTEM_FOREGROUND)`); the
    /// current foreground is reported right after start.
    pub foreground: Option<ForegroundSink>,
    /// `WTS_SESSION_LOCK` / `WTS_SESSION_UNLOCK`.
    pub session: Option<SessionSink>,
}

enum Command {
    WriteText(Zeroizing<String>, SyncSender<Result<u32, ClipError>>),
    Clear(SyncSender<Result<u32, ClipError>>),
    ReadFull(SyncSender<Option<Zeroizing<String>>>),
    Snapshot(SyncSender<Result<Snapshot, ClipError>>),
    Restore(Snapshot, SyncSender<Result<u32, ClipError>>),
}

struct State {
    formats: Formats,
    dedupe: Deduper,
    self_writes: SelfWriteCache,
    sink: ClipSink,
    session: Option<SessionSink>,
    start: Instant,
}

impl State {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn on_update(&mut self, hwnd: HWND) {
        let now = self.now_ms();
        let self_writes = &mut self.self_writes;
        let event = raw::read_change(hwnd, &self.formats, |seq| self_writes.is_ours(seq, now));
        match event {
            ClipEvent::Text(mut t) => {
                let hash = content_hash(&t.text);
                if self.dedupe.is_repeat(t.sequence, &hash) {
                    return;
                }
                t.self_write = t.self_write || self.self_writes.contains(&hash, now);
                (self.sink)(ClipEvent::Text(t));
            }
            ClipEvent::Empty { sequence, reason } => {
                if !self.dedupe.on_empty(sequence) {
                    (self.sink)(ClipEvent::Empty { sequence, reason });
                }
            }
        }
    }

    fn run(&mut self, hwnd: HWND, cmd: Command) {
        match cmd {
            Command::WriteText(text, reply) => {
                let r = raw::write_text(hwnd, &self.formats, &text);
                if let Ok(seq) = r {
                    let now = self.now_ms();
                    self.self_writes.record(seq, content_hash(&text), now);
                }
                let _ = reply.send(r);
            }
            Command::Clear(reply) => {
                let _ = reply.send(raw::clear(hwnd));
            }
            Command::ReadFull(reply) => {
                let _ = reply.send(raw::read_full(hwnd));
            }
            Command::Snapshot(reply) => {
                let _ = reply.send(raw::snapshot(hwnd, &self.formats));
            }
            Command::Restore(snap, reply) => {
                let r = raw::restore(hwnd, &self.formats, &snap);
                if let Ok(seq) = r {
                    let now = self.now_ms();
                    // The hash is unknown without re-reading; the sequence suffices.
                    self.self_writes.record(seq, [0; 32], now);
                }
                let _ = reply.send(r);
            }
        }
    }
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_CLIPBOARDUPDATE {
        // SAFETY: our window; re-arming an existing timer restarts it.
        unsafe { SetTimer(Some(hwnd), READ_TIMER_ID, CLIPBOARD_READ_DELAY_MS, None) };
        return LRESULT(0);
    }
    if msg == WM_WTSSESSION_CHANGE {
        if let Some(locked) = session::lock_change(wp) {
            with_state(|s| {
                if let Some(sink) = s.session.as_mut() {
                    sink(locked);
                }
            });
        }
        return LRESULT(0);
    }
    if msg == WM_TIMER && wp.0 == READ_TIMER_ID {
        // SAFETY: our window and timer.
        let _ = unsafe { KillTimer(Some(hwnd), READ_TIMER_ID) };
        with_state(|s| s.on_update(hwnd));
        return LRESULT(0);
    }
    // SAFETY: default handling for every other message.
    unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
}

fn register_class(instance: HINSTANCE) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: instance,
            lpszClassName: CLASS_NAME,
            ..Default::default()
        };
        // SAFETY: `class` is fully initialized and outlives the call.
        unsafe { RegisterClassExW(&class) };
    });
}

/// Window handle that may cross threads (only used with PostMessageW).
#[derive(Clone, Copy)]
struct SendHwnd(isize);

impl SendHwnd {
    fn hwnd(self) -> HWND {
        HWND(self.0 as *mut _)
    }
}

/// Sends commands to the monitor thread. Cheap to clone.
#[derive(Clone)]
pub struct ClipboardHandle {
    hwnd: SendHwnd,
    commands: Sender<Command>,
}

impl ClipboardHandle {
    fn call<T>(&self, make: impl FnOnce(SyncSender<T>) -> Command) -> Option<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.commands.send(make(tx)).ok()?;
        // SAFETY: posting to our own window; a failure just times out below.
        unsafe { PostMessageW(Some(self.hwnd.hwnd()), WM_PW_COMMAND, WPARAM(0), LPARAM(0)) }
            .ok()?;
        rx.recv_timeout(Duration::from_millis(CLIPBOARD_COMMAND_TIMEOUT_MS))
            .ok()
    }

    /// Replaces the clipboard with `text` (masked paste, restore).
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

    /// Saves the text formats before a masked paste.
    pub fn snapshot(&self) -> Result<Snapshot, ClipError> {
        self.call(Command::Snapshot).unwrap_or(Err(ClipError::Busy))
    }

    /// Puts a snapshot back.
    pub fn restore(&self, snap: Snapshot) -> Result<u32, ClipError> {
        self.call(|r| Command::Restore(snap, r))
            .unwrap_or(Err(ClipError::Busy))
    }
}

/// Owns the monitor thread; dropping it unregisters the listener and joins.
pub struct ClipboardMonitor {
    handle: ClipboardHandle,
    thread: Option<JoinHandle<()>>,
    foreground_active: bool,
}

/// Why the monitor could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    Window(i32),
    Listener(i32),
    ThreadGone,
}

impl ClipboardMonitor {
    /// Starts `pw-clip`. `sink` receives every change, starting with the
    /// current clipboard when [`RUN_INITIAL_CHECK`] is set.
    pub fn start(sink: ClipSink) -> Result<ClipboardMonitor, StartError> {
        Self::start_with(sink, MonitorOptions::default())
    }

    /// [`Self::start`] plus the foreground and session watchers of `opts`.
    pub fn start_with(
        sink: ClipSink,
        opts: MonitorOptions,
    ) -> Result<ClipboardMonitor, StartError> {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
        let thread = std::thread::Builder::new()
            .name("pw-clip".into())
            .spawn(move || thread_main(sink, opts, cmd_rx, ready_tx))
            .map_err(|_| StartError::ThreadGone)?;
        let (hwnd, foreground_active) = ready_rx.recv().map_err(|_| StartError::ThreadGone)??;
        Ok(ClipboardMonitor {
            handle: ClipboardHandle {
                hwnd,
                commands: cmd_tx,
            },
            thread: Some(thread),
            foreground_active,
        })
    }

    pub fn handle(&self) -> ClipboardHandle {
        self.handle.clone()
    }

    /// The foreground hook of [`MonitorOptions::foreground`] is installed.
    pub fn foreground_active(&self) -> bool {
        self.foreground_active
    }
}

impl Drop for ClipboardMonitor {
    fn drop(&mut self) {
        // SAFETY: posting to our own window.
        let _ = unsafe {
            PostMessageW(
                Some(self.handle.hwnd.hwnd()),
                WM_PW_QUIT,
                WPARAM(0),
                LPARAM(0),
            )
        };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn thread_main(
    sink: ClipSink,
    opts: MonitorOptions,
    commands: Receiver<Command>,
    ready: SyncSender<Result<(SendHwnd, bool), StartError>>,
) {
    // SAFETY: Win32 window setup on this thread; every failure is reported
    // through `ready` and the thread exits.
    let hwnd = unsafe {
        let instance = match GetModuleHandleW(None) {
            Ok(m) => HINSTANCE(m.0),
            Err(e) => {
                let _ = ready.send(Err(StartError::Window(e.code().0)));
                return;
            }
        };
        register_class(instance);
        match CreateWindowExW(
            WINDOW_EX_STYLE(0),
            CLASS_NAME,
            w!("PasteWarden"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance),
            None,
        ) {
            Ok(h) => h,
            Err(e) => {
                let _ = ready.send(Err(StartError::Window(e.code().0)));
                return;
            }
        }
    };
    STATE.with(|s| {
        *s.borrow_mut() = Some(State {
            formats: Formats::register(),
            dedupe: Deduper::new(),
            self_writes: SelfWriteCache::new(),
            sink,
            session: opts.session,
            start: Instant::now(),
        });
    });
    // SAFETY: our window, created above on this thread.
    if let Err(e) = unsafe { AddClipboardFormatListener(hwnd) } {
        let _ = ready.send(Err(StartError::Listener(e.code().0)));
        // SAFETY: as above.
        let _ = unsafe { DestroyWindow(hwnd) };
        return;
    }
    let session_registered = with_state_ret(|s| s.session.is_some()) && session::register(hwnd);
    // Installed after the listener so both run on this thread's loop; a
    // failure only loses foreground events (status stays with the worker).
    let foreground = opts.foreground.and_then(ForegroundWatch::install);
    let _ = ready.send(Ok((SendHwnd(hwnd.0 as isize), foreground.is_some())));

    if RUN_INITIAL_CHECK {
        with_state(|s| s.on_update(hwnd));
    }

    let mut msg = MSG::default();
    // SAFETY: standard message loop for this thread's windows.
    while unsafe { GetMessageW(&mut msg, None, 0, 0) }.0 > 0 {
        match msg.message {
            WM_PW_COMMAND => {
                while let Ok(cmd) = commands.try_recv() {
                    with_state(|s| s.run(hwnd, cmd));
                }
            }
            WM_PW_QUIT => break,
            // SAFETY: dispatches to `wndproc`.
            _ => unsafe {
                DispatchMessageW(&msg);
            },
        }
    }
    drop(foreground);
    if session_registered {
        session::unregister(hwnd);
    }
    // SAFETY: our window; unregister before destroying it.
    unsafe {
        let _ = RemoveClipboardFormatListener(hwnd);
        let _ = DestroyWindow(hwnd);
    }
    // Drops the sink and zeroizes nothing else: no clipboard text is kept here.
    STATE.with(|s| s.borrow_mut().take());
}

fn with_state(f: impl FnOnce(&mut State)) {
    STATE.with(|s| {
        if let Ok(mut s) = s.try_borrow_mut()
            && let Some(state) = s.as_mut()
        {
            f(state);
        }
    });
}

fn with_state_ret(f: impl FnOnce(&State) -> bool) -> bool {
    STATE.with(|s| {
        s.try_borrow()
            .ok()
            .and_then(|s| s.as_ref().map(f))
            .unwrap_or(false)
    })
}
