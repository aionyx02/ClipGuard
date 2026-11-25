//! X11 backend (phase-4.md §4.9.2, S5): XFixes `SelectionNotify` on
//! CLIPBOARD, TARGETS first (password-manager hint), then `UTF8_STRING` with
//! INCR. Also used on XWayland when the compositor has no data-control.
//!
//! One thread and one connection read, write (we become the selection owner
//! and serve conversions while waiting for our own) and track the owner pid.
//! Replies for an owner that has since changed are dropped (S5 pitfall 6).
//!
//! Privacy (P3): property values are moved into [`Zeroizing`] buffers as
//! soon as x11rb hands them over; x11rb's own socket buffers are not ours to
//! wipe.

use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, TryRecvError};
use std::time::{Duration, Instant};

use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::Event;
use x11rb::protocol::res::{ClientIdMask, ClientIdSpec, ConnectionExt as _};
use x11rb::protocol::xfixes::{ConnectionExt as _, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, Property,
    SELECTION_NOTIFY_EVENT, SelectionNotifyEvent, SelectionRequestEvent, Window, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{COPY_DEPTH_FROM_PARENT, COPY_FROM_PARENT, CURRENT_TIME, NONE};
use zeroize::Zeroizing;

use super::backend::Env;
use super::io::wait_readable;
use super::monitor::{ClipError, Command, Emitter, Snapshot, Thread};
use super::text::{
    DATA_CONTROL_READ_MAX_BYTES, DATA_CONTROL_READ_TIMEOUT_MS, FULL_READ_MAX_BYTES,
    FULL_READ_TIMEOUT_MS, MAX_OFFERED_TYPES, OfferDecision, OfferTypes, PASSWORD_MANAGER_HINT,
    ReadEnd, ReadResult, TEXT_MIME_PREFERENCE, WRITE_MIME_TYPES, comm_name, decode_utf8_lossy,
    event_from_read,
};
use super::transfer::{Assembler, ConversionTracker, Generation, Step};
use crate::clipboard::{ClipEvent, EmptyReason};

/// Property on our window that conversions are delivered to.
pub const TRANSFER_PROPERTY: &str = "PASTE_WARDEN_SELECTION";
/// Property appended to (zero bytes) to learn the server time.
pub const TIME_PROPERTY: &str = "PASTE_WARDEN_TIME";
/// Bytes asked for per `GetProperty` (custom).
pub const PROPERTY_CHUNK_BYTES: usize = 256 * 1024;
/// Bytes of a TARGETS reply read at most.
pub const TARGETS_MAX_BYTES: usize = MAX_OFFERED_TYPES * 4;
/// Longest wait for the server time / our own ownership (custom).
pub const SERVER_TIME_TIMEOUT_MS: u64 = 500;
/// Bytes of `/proc/<pid>/comm` read at most.
pub const COMM_MAX_BYTES: u64 = 64;
/// Header room left in a `ChangeProperty` request.
const REQUEST_HEADER_BYTES: usize = 64;

type Shared = Arc<Zeroizing<Vec<u8>>>;

struct Atoms {
    clipboard: Atom,
    targets: Atom,
    timestamp: Atom,
    incr: Atom,
    transfer: Atom,
    time: Atom,
    hint: Atom,
    /// `TEXT_MIME_PREFERENCE[i]` interned.
    text: [Atom; TEXT_MIME_PREFERENCE.len()],
    /// `WRITE_MIME_TYPES[i]` interned.
    write: [Atom; WRITE_MIME_TYPES.len()],
}

fn intern(conn: &RustConnection, name: &str) -> Option<Atom> {
    Some(
        conn.intern_atom(false, name.as_bytes())
            .ok()?
            .reply()
            .ok()?
            .atom,
    )
}

impl Atoms {
    fn new(conn: &RustConnection) -> Option<Atoms> {
        let mut text = [0; TEXT_MIME_PREFERENCE.len()];
        for (a, n) in text.iter_mut().zip(TEXT_MIME_PREFERENCE) {
            *a = intern(conn, n)?;
        }
        let mut write = [0; WRITE_MIME_TYPES.len()];
        for (a, n) in write.iter_mut().zip(WRITE_MIME_TYPES) {
            *a = intern(conn, n)?;
        }
        Some(Atoms {
            clipboard: intern(conn, "CLIPBOARD")?,
            targets: intern(conn, "TARGETS")?,
            timestamp: intern(conn, "TIMESTAMP")?,
            incr: intern(conn, "INCR")?,
            transfer: intern(conn, TRANSFER_PROPERTY)?,
            time: intern(conn, TIME_PROPERTY)?,
            hint: intern(conn, PASSWORD_MANAGER_HINT)?,
            text,
            write,
        })
    }

    /// The type names the decision needs, from a TARGETS atom list.
    fn offer_types(&self, atoms: &[Atom]) -> OfferTypes {
        let mut t = OfferTypes::new();
        for &a in atoms.iter().take(MAX_OFFERED_TYPES) {
            if a == self.hint {
                t.add(PASSWORD_MANAGER_HINT);
            } else if let Some(i) = self.text.iter().position(|&x| x == a) {
                t.add(TEXT_MIME_PREFERENCE[i]);
            }
        }
        t
    }

    fn text_atom(&self, name: &str) -> Atom {
        let i = TEXT_MIME_PREFERENCE
            .iter()
            .position(|&n| n == name)
            .unwrap_or(0);
        self.text[i]
    }
}

/// Opens the display named by `env.x11_display`.
pub(crate) fn connect(env: &Env) -> Option<(RustConnection, usize)> {
    RustConnection::connect(Some(env.x11_display.as_deref()?)).ok()
}

/// pid of the client that created `window` (XRes `QueryClientIds`). S5: the
/// pid is the one at connection time and may be gone (`xclip` forks).
pub(crate) fn window_pid(conn: &RustConnection, window: Window) -> Option<u32> {
    let spec = ClientIdSpec {
        client: window,
        mask: ClientIdMask::LOCAL_CLIENT_PID,
    };
    let reply = conn.res_query_client_ids(&[spec]).ok()?.reply().ok()?;
    reply
        .ids
        .iter()
        .find(|id| id.spec.mask == ClientIdMask::LOCAL_CLIENT_PID)
        .and_then(|id| id.value.first().copied())
}

/// `/proc/<pid>/comm`, best effort.
pub(crate) fn process_name(pid: u32) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(format!("/proc/{pid}/comm")).ok()?;
    let mut buf = Vec::new();
    f.take(COMM_MAX_BYTES).read_to_end(&mut buf).ok()?;
    comm_name(&buf)
}

/// Result of one conversion.
enum Conv {
    Data(ReadResult),
    Refused,
    /// The owner changed while we waited; the new change is pending.
    Stale,
}

/// Result of reading one change.
enum Got {
    Text(ReadResult),
    Skip(EmptyReason),
    Stale,
}

struct X11 {
    conn: RustConnection,
    win: Window,
    atoms: Atoms,
    tracker: ConversionTracker,
    seq: u32,
    pending: Option<(Generation, Instant)>,
    /// Our selection: data and the time we took ownership.
    owned: Option<(Shared, u32)>,
    owner_cache: Option<(Window, Option<String>)>,
    max_property: usize,
    broken: bool,
}

impl X11 {
    fn open(env: &Env) -> Option<X11> {
        let (conn, screen) = connect(env)?;
        conn.xfixes_query_version(5, 0).ok()?.reply().ok()?;
        // XRes is optional: without it owner names stay unknown.
        let _ = conn.res_query_version(1, 2).map(|c| c.reply());
        let root = conn.setup().roots.get(screen)?.root;
        let win = conn.generate_id().ok()?;
        conn.create_window(
            COPY_DEPTH_FROM_PARENT,
            win,
            root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_ONLY,
            COPY_FROM_PARENT,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )
        .ok()?;
        let atoms = Atoms::new(&conn)?;
        conn.xfixes_select_selection_input(
            win,
            atoms.clipboard,
            SelectionEventMask::SET_SELECTION_OWNER
                | SelectionEventMask::SELECTION_WINDOW_DESTROY
                | SelectionEventMask::SELECTION_CLIENT_CLOSE,
        )
        .ok()?;
        conn.flush().ok()?;
        let max_property = conn
            .maximum_request_bytes()
            .saturating_sub(REQUEST_HEADER_BYTES);
        Some(X11 {
            conn,
            win,
            atoms,
            tracker: ConversionTracker::new(),
            seq: 0,
            pending: None,
            owned: None,
            owner_cache: None,
            max_property,
            broken: false,
        })
    }

    fn new_generation(&mut self, owner: Window, timestamp: u32) {
        self.seq = self.seq.wrapping_add(1);
        let g = Generation {
            owner,
            timestamp,
            sequence: self.seq,
        };
        self.tracker.on_owner_change(g);
        self.pending = Some((g, Instant::now()));
    }

    /// Seeds the current owner (initial check).
    fn seed(&mut self) -> bool {
        let Ok(Ok(r)) = self
            .conn
            .get_selection_owner(self.atoms.clipboard)
            .map(|c| c.reply())
        else {
            return false;
        };
        self.new_generation(r.owner, CURRENT_TIME);
        true
    }

    /// Handles an event that is not part of a transfer. Returns `true` when
    /// it announced a new owner.
    fn handle(&mut self, ev: Event) -> bool {
        match ev {
            Event::XfixesSelectionNotify(e) if e.selection == self.atoms.clipboard => {
                self.new_generation(e.owner, e.selection_timestamp);
                true
            }
            Event::SelectionRequest(e) => {
                self.serve(&e);
                false
            }
            Event::SelectionClear(e) if e.selection == self.atoms.clipboard => {
                self.owned = None;
                false
            }
            _ => false,
        }
    }

    /// The next event before `deadline` (`None` = timed out or broken).
    fn next_event(&mut self, deadline: Instant) -> Option<Event> {
        loop {
            match self.conn.poll_for_event() {
                Ok(Some(ev)) => return Some(ev),
                Ok(None) => {}
                Err(_) => {
                    self.broken = true;
                    return None;
                }
            }
            if self.conn.flush().is_err() {
                self.broken = true;
                return None;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let fd = self.conn.stream().as_fd();
            wait_readable(&[fd], Some(left));
        }
    }

    // ---- reading --------------------------------------------------------------

    fn property(
        &self,
        delete: bool,
        offset_units: u32,
        len: usize,
    ) -> Option<(Atom, u32, Zeroizing<Vec<u8>>)> {
        let units = u32::try_from(len.div_ceil(4)).unwrap_or(u32::MAX);
        let r = self
            .conn
            .get_property(
                delete,
                self.win,
                self.atoms.transfer,
                AtomEnum::ANY,
                offset_units,
                units,
            )
            .ok()?
            .reply()
            .ok()?;
        let type_ = r.type_;
        let after = r.bytes_after;
        Some((type_, after, Zeroizing::new(r.value)))
    }

    /// Reads the transfer property, following INCR.
    fn read_property(&mut self, max: usize, deadline: Instant) -> Conv {
        let failed = || {
            Conv::Data(ReadResult {
                bytes: Zeroizing::new(Vec::new()),
                end: ReadEnd::Failed,
            })
        };
        let Some((type_, _, head)) = self.property(false, 0, 4) else {
            return failed();
        };
        if type_ == self.atoms.incr {
            let hint = head
                .get(..4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map_or(0, |b| u32::from_ne_bytes(b) as usize);
            return self.read_incr(max, hint, deadline);
        }
        let mut asm = Assembler::new(max, 0);
        let mut offset: u32 = 0;
        let end = loop {
            let want = asm.room().min(PROPERTY_CHUNK_BYTES);
            let Some((_, after, value)) = self.property(false, offset, want) else {
                break ReadEnd::Failed;
            };
            let step = asm.append(&value);
            if after == 0 {
                break ReadEnd::Complete;
            }
            if step == Step::Capped || value.is_empty() {
                break ReadEnd::Capped;
            }
            offset = offset.saturating_add(u32::try_from(value.len() / 4).unwrap_or(u32::MAX));
        };
        let _ = self.conn.delete_property(self.win, self.atoms.transfer);
        Conv::Data(ReadResult {
            bytes: asm.into_bytes(),
            end,
        })
    }

    fn read_incr(&mut self, max: usize, hint: usize, deadline: Instant) -> Conv {
        let mut asm = Assembler::new(max, hint);
        // Deleting the INCR property starts the transfer (ICCCM 2.7.2).
        let _ = self.conn.delete_property(self.win, self.atoms.transfer);
        let end = loop {
            let Some(ev) = self.next_event(deadline) else {
                break if self.broken {
                    ReadEnd::Failed
                } else {
                    ReadEnd::TimedOut
                };
            };
            match ev {
                Event::PropertyNotify(e)
                    if e.window == self.win
                        && e.atom == self.atoms.transfer
                        && e.state == Property::NEW_VALUE =>
                {
                    let Some((_, _, chunk)) = self.property(true, 0, asm.room() + 4) else {
                        break ReadEnd::Failed;
                    };
                    match asm.push_incr(&chunk) {
                        Step::More => {}
                        Step::Done => break ReadEnd::Complete,
                        Step::Capped => break ReadEnd::Capped,
                    }
                }
                other => {
                    if self.handle(other) {
                        return Conv::Stale;
                    }
                }
            }
        };
        let _ = self.conn.delete_property(self.win, self.atoms.transfer);
        Conv::Data(ReadResult {
            bytes: asm.into_bytes(),
            end,
        })
    }

    /// Converts CLIPBOARD to `target` for generation `g`.
    fn convert(&mut self, g: Generation, target: Atom, max: usize, timeout: Duration) -> Conv {
        let deadline = Instant::now() + timeout;
        let _ = self.conn.delete_property(self.win, self.atoms.transfer);
        if self
            .conn
            .convert_selection(
                self.win,
                self.atoms.clipboard,
                target,
                self.atoms.transfer,
                g.timestamp,
            )
            .is_err()
        {
            self.broken = true;
            return Conv::Refused;
        }
        self.tracker.begin(target);
        loop {
            let Some(ev) = self.next_event(deadline) else {
                return Conv::Data(ReadResult {
                    bytes: Zeroizing::new(Vec::new()),
                    end: if self.broken {
                        ReadEnd::Failed
                    } else {
                        ReadEnd::TimedOut
                    },
                });
            };
            match ev {
                Event::SelectionNotify(e)
                    if e.requestor == self.win && e.selection == self.atoms.clipboard =>
                {
                    if !self.tracker.accept(e.time, e.target) {
                        continue; // reply to an older request
                    }
                    if e.property == NONE {
                        return Conv::Refused;
                    }
                    return self.read_property(max, deadline);
                }
                other => {
                    if self.handle(other) {
                        return Conv::Stale;
                    }
                }
            }
        }
    }

    /// Reads the text of generation `g`: TARGETS first, then the text type.
    fn fetch(&mut self, g: Generation, max: usize, timeout: Duration) -> Got {
        if g.owner == NONE {
            return Got::Skip(EmptyReason::NoText);
        }
        if g.owner == self.win {
            return match &self.owned {
                Some((data, _)) => {
                    let n = data.len().min(max);
                    Got::Text(ReadResult {
                        bytes: Zeroizing::new(data[..n].to_vec()),
                        end: if n < data.len() {
                            ReadEnd::Capped
                        } else {
                            ReadEnd::Complete
                        },
                    })
                }
                None => Got::Skip(EmptyReason::NoText),
            };
        }
        let types = match self.convert(g, self.atoms.targets, TARGETS_MAX_BYTES, timeout) {
            Conv::Stale => return Got::Stale,
            Conv::Data(r) if r.end == ReadEnd::Complete || r.end == ReadEnd::Capped => {
                let atoms: Vec<Atom> = r
                    .bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_ne_bytes(*c))
                    .collect();
                self.atoms.offer_types(&atoms)
            }
            // An owner without TARGETS: try UTF8_STRING blind (no hint
            // could be checked; such owners predate the convention).
            Conv::Refused => OfferTypes::from_types(["UTF8_STRING"]),
            Conv::Data(r) => return Got::Text(r),
        };
        match types.decide() {
            OfferDecision::Skip(reason) => Got::Skip(reason),
            OfferDecision::Read(name) => {
                let atom = self.atoms.text_atom(name);
                match self.convert(g, atom, max, timeout) {
                    Conv::Stale => Got::Stale,
                    Conv::Data(r) => Got::Text(r),
                    Conv::Refused => Got::Text(ReadResult {
                        bytes: Zeroizing::new(Vec::new()),
                        end: ReadEnd::Failed,
                    }),
                }
            }
        }
    }

    fn owner_name(&mut self, owner: Window) -> Option<String> {
        if owner == NONE || owner == self.win {
            return None;
        }
        if let Some((w, name)) = &self.owner_cache
            && *w == owner
        {
            return name.clone();
        }
        let name = window_pid(&self.conn, owner).and_then(process_name);
        self.owner_cache = Some((owner, name.clone()));
        name
    }

    /// Processes pending changes until one is read without being superseded.
    fn process(&mut self, emitter: &mut Emitter) {
        while let Some((g, at)) = self.pending.take() {
            let got = self.fetch(
                g,
                DATA_CONTROL_READ_MAX_BYTES,
                Duration::from_millis(DATA_CONTROL_READ_TIMEOUT_MS),
            );
            let event = match got {
                Got::Stale => continue,
                Got::Skip(reason) => ClipEvent::Empty {
                    sequence: g.sequence,
                    reason,
                },
                Got::Text(r) => {
                    let mut ev = event_from_read(g.sequence, r, false);
                    if let ClipEvent::Text(t) = &mut ev {
                        t.owner_process = self.owner_name(g.owner);
                    }
                    ev
                }
            };
            emitter.emit(event, at);
        }
    }

    // ---- writing --------------------------------------------------------------

    /// A server timestamp (append zero bytes to a property, read the
    /// PropertyNotify time).
    fn server_time(&mut self) -> Option<u32> {
        self.conn
            .change_property8(
                PropMode::APPEND,
                self.win,
                self.atoms.time,
                AtomEnum::STRING,
                &[],
            )
            .ok()?;
        let deadline = Instant::now() + Duration::from_millis(SERVER_TIME_TIMEOUT_MS);
        loop {
            let ev = self.next_event(deadline)?;
            match ev {
                Event::PropertyNotify(e) if e.window == self.win && e.atom == self.atoms.time => {
                    return Some(e.time);
                }
                other => {
                    self.handle(other);
                }
            }
        }
    }

    /// Makes our window the owner with `data`, or clears the selection.
    fn set(&mut self, data: Option<Shared>) -> bool {
        let Some(time) = self.server_time() else {
            return false;
        };
        let owner = if data.is_some() { self.win } else { NONE };
        if self
            .conn
            .set_selection_owner(owner, self.atoms.clipboard, time)
            .is_err()
        {
            return false;
        }
        let Ok(Ok(r)) = self
            .conn
            .get_selection_owner(self.atoms.clipboard)
            .map(|c| c.reply())
        else {
            return false;
        };
        if r.owner != owner {
            return false;
        }
        self.owned = data.map(|d| (d, time));
        true
    }

    /// Serves a conversion request for our selection (text targets only).
    fn serve(&mut self, e: &SelectionRequestEvent) {
        let prop = if e.property == NONE {
            e.target
        } else {
            e.property
        };
        let ok = match &self.owned {
            Some((data, time)) if e.selection == self.atoms.clipboard && e.owner == self.win => {
                if e.target == self.atoms.targets {
                    let mut list = vec![self.atoms.targets, self.atoms.timestamp];
                    list.extend_from_slice(&self.atoms.write);
                    self.conn
                        .change_property32(
                            PropMode::REPLACE,
                            e.requestor,
                            prop,
                            AtomEnum::ATOM,
                            &list,
                        )
                        .is_ok()
                } else if e.target == self.atoms.timestamp {
                    self.conn
                        .change_property32(
                            PropMode::REPLACE,
                            e.requestor,
                            prop,
                            AtomEnum::INTEGER,
                            &[*time],
                        )
                        .is_ok()
                } else if self.atoms.write.contains(&e.target) && data.len() <= self.max_property {
                    // x11rb copies the bytes into its (unzeroized) send buffer.
                    self.conn
                        .change_property8(PropMode::REPLACE, e.requestor, prop, e.target, data)
                        .is_ok()
                } else {
                    // Larger than one request: sending INCR is not implemented.
                    false
                }
            }
            _ => false,
        };
        let notify = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: e.time,
            requestor: e.requestor,
            selection: e.selection,
            target: e.target,
            property: if ok { prop } else { NONE },
        };
        let _ = self
            .conn
            .send_event(false, e.requestor, EventMask::NO_EVENT, notify);
        let _ = self.conn.flush();
    }

    /// Drains events already received.
    fn drain(&mut self) {
        loop {
            match self.conn.poll_for_event() {
                Ok(Some(ev)) => {
                    self.handle(ev);
                }
                Ok(None) => return,
                Err(_) => {
                    self.broken = true;
                    return;
                }
            }
        }
    }

    /// Waits until the server has sent everything our requests caused.
    fn sync(&mut self) -> bool {
        let ok = matches!(self.conn.get_input_focus().map(|c| c.reply()), Ok(Ok(_)));
        self.drain();
        ok
    }

    fn write(&mut self, data: Option<Shared>, emitter: &mut Emitter) -> Result<u32, ClipError> {
        if let Some(d) = &data {
            emitter.record_write(Emitter::write_hash(d));
        }
        if !self.set(data) || !self.sync() {
            return Err(ClipError::WriteFailed);
        }
        let seq = self.seq;
        self.process(emitter);
        Ok(seq)
    }

    fn full_bytes(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let g = self.tracker.current()?;
        match self.fetch(
            g,
            FULL_READ_MAX_BYTES,
            Duration::from_millis(FULL_READ_TIMEOUT_MS),
        ) {
            Got::Text(r) if matches!(r.end, ReadEnd::Complete | ReadEnd::Capped) => Some(r.bytes),
            _ => None,
        }
    }

    fn run(&mut self, cmd: Command, emitter: &mut Emitter) -> bool {
        match cmd {
            Command::WriteText(text, reply) => {
                let data = Arc::new(Zeroizing::new(text.as_bytes().to_vec()));
                let _ = reply.send(self.write(Some(data), emitter));
            }
            Command::Clear(reply) => {
                let _ = reply.send(self.write(None, emitter));
            }
            Command::ReadFull(reply) => {
                let _ = reply.send(self.full_bytes().map(|b| decode_utf8_lossy(&b)));
            }
            Command::Snapshot(reply) => {
                let _ = reply.send(Snapshot {
                    text: self.full_bytes(),
                });
            }
            Command::Restore(snap, reply) => {
                let _ = reply.send(self.write(snap.text.map(Arc::new), emitter));
            }
            Command::Sequence(reply) => {
                let _ = reply.send(self.seq);
            }
            Command::Quit => return false,
        }
        true
    }
}

/// `pw-clip` main for X11 / XWayland.
pub(crate) fn run(env: &Env, mut t: Thread, ready: SyncSender<bool>) {
    let Some(mut x) = X11::open(env) else {
        let _ = ready.send(false);
        return;
    };
    if !x.seed() {
        let _ = ready.send(false);
        return;
    }
    if !t.initial_check {
        x.pending = None;
    }
    let _ = ready.send(true);

    loop {
        x.drain();
        if x.broken {
            return;
        }
        if x.pending.is_some() {
            x.process(&mut t.emitter);
            continue;
        }
        if x.conn.flush().is_err() {
            return;
        }
        let woken = {
            let fd = x.conn.stream().as_fd();
            wait_readable(&[fd, t.wake.fd()], None)[1]
        };
        if !woken {
            continue;
        }
        t.wake.drain();
        loop {
            match t.commands.try_recv() {
                Ok(cmd) => {
                    if !x.run(cmd, &mut t.emitter) {
                        return;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
    }
}
