//! Wayland data-control backend (phase-4.md §4.9.2, S5). `ext` and `wlr`
//! have the same shape; [`Proto`] picks one and the wrappers below hide the
//! difference.
//!
//! Two connections: `pw-clip` watches the selection, `pw-clip-write` owns
//! our data sources. Reading our own write therefore never waits on the
//! thread that has to serve it (S5 pitfall 5: we see our own writes).
//!
//! Reads happen after `dispatch_pending` returns and after `flush()`, never
//! inside a dispatch callback (S5 pitfall 4), with a byte cap and a timeout.

use std::collections::HashMap;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wayland_client::backend::ObjectId;
use wayland_client::globals::{GlobalList, GlobalListContents, registry_queue_init};
use wayland_client::protocol::{wl_registry, wl_seat};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle, event_created_child};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1 as ext_dev, ext_data_control_manager_v1 as ext_mgr,
    ext_data_control_offer_v1 as ext_offer, ext_data_control_source_v1 as ext_src,
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1 as wlr_dev, zwlr_data_control_manager_v1 as wlr_mgr,
    zwlr_data_control_offer_v1 as wlr_offer, zwlr_data_control_source_v1 as wlr_src,
};
use zeroize::Zeroizing;

use super::backend::{Env, WaylandGlobals};
use super::io::{Waker, pipe, read_capped, wait_readable, waker, write_all_timeout};
use super::monitor::{ClipError, Command, Emitter, Snapshot, Thread};
use super::text::{
    DATA_CONTROL_READ_MAX_BYTES, DATA_CONTROL_READ_TIMEOUT_MS, FULL_READ_MAX_BYTES,
    FULL_READ_TIMEOUT_MS, OfferDecision, OfferTypes, ReadEnd, ReadResult, WRITE_MIME_TYPES,
    WRITE_TIMEOUT_MS, decode_utf8_lossy, event_from_read,
};
use crate::clipboard::{ClipEvent, EmptyReason};

/// Global names (registry `interface` strings).
pub const EXT_DATA_CONTROL: &str = "ext_data_control_manager_v1";
pub const WLR_DATA_CONTROL: &str = "zwlr_data_control_manager_v1";
pub const WLR_FOREIGN_TOPLEVEL: &str = "zwlr_foreign_toplevel_manager_v1";
pub const WL_SEAT: &str = "wl_seat";
/// Offers whose `selection` has not arrived yet, at most (custom; normally
/// one or two). New offers past this are destroyed unread.
pub const MAX_PENDING_OFFERS: usize = 8;
/// How often a `finished` device is re-created before giving up (custom).
pub const MAX_DEVICE_RECREATE: u32 = 3;
/// Writes served to other clients that are queued at most (custom).
pub const MAX_PENDING_SENDS: usize = 16;

/// Which data-control protocol to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Ext,
    Wlr,
}

/// Connects to the compositor named by `env`.
pub(crate) fn connect(env: &Env) -> Option<Connection> {
    let stream = UnixStream::connect(env.wayland_socket()?).ok()?;
    Connection::from_socket(stream).ok()
}

/// Lists the globals that matter for [`super::backend::select`]. `None`
/// when there is no Wayland display or it cannot be reached.
pub fn probe_globals(env: &Env) -> Option<WaylandGlobals> {
    let conn = connect(env)?;
    let (globals, _queue) = registry_queue_init::<Probe>(&conn).ok()?;
    Some(globals_of(&globals))
}

pub(crate) fn globals_of(globals: &GlobalList) -> WaylandGlobals {
    globals.contents().with_list(|list| {
        let has = |name: &str| list.iter().any(|g| g.interface == name);
        WaylandGlobals {
            ext_data_control: has(EXT_DATA_CONTROL),
            wlr_data_control: has(WLR_DATA_CONTROL),
            wlr_foreign_toplevel: has(WLR_FOREIGN_TOPLEVEL),
            seat: has(WL_SEAT),
        }
    })
}

struct Probe;

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for Probe {
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

// ---- protocol wrappers ------------------------------------------------

#[derive(Clone)]
enum Offer {
    Ext(ext_offer::ExtDataControlOfferV1),
    Wlr(wlr_offer::ZwlrDataControlOfferV1),
}

impl Offer {
    fn id(&self) -> ObjectId {
        match self {
            Offer::Ext(o) => o.id(),
            Offer::Wlr(o) => o.id(),
        }
    }

    fn receive(&self, mime: &str, fd: std::os::fd::BorrowedFd<'_>) {
        match self {
            Offer::Ext(o) => o.receive(mime.to_owned(), fd),
            Offer::Wlr(o) => o.receive(mime.to_owned(), fd),
        }
    }

    fn destroy(&self) {
        match self {
            Offer::Ext(o) => o.destroy(),
            Offer::Wlr(o) => o.destroy(),
        }
    }
}

enum Source {
    Ext(ext_src::ExtDataControlSourceV1),
    Wlr(wlr_src::ZwlrDataControlSourceV1),
}

impl Source {
    fn id(&self) -> ObjectId {
        match self {
            Source::Ext(s) => s.id(),
            Source::Wlr(s) => s.id(),
        }
    }

    fn offer(&self, mime: &str) {
        match self {
            Source::Ext(s) => s.offer(mime.to_owned()),
            Source::Wlr(s) => s.offer(mime.to_owned()),
        }
    }

    fn destroy(&self) {
        match self {
            Source::Ext(s) => s.destroy(),
            Source::Wlr(s) => s.destroy(),
        }
    }
}

enum Device {
    Ext(ext_dev::ExtDataControlDeviceV1),
    Wlr(wlr_dev::ZwlrDataControlDeviceV1),
}

impl Device {
    fn set_selection(&self, source: Option<&Source>) {
        match (self, source) {
            (Device::Ext(d), Some(Source::Ext(s))) => d.set_selection(Some(s)),
            (Device::Wlr(d), Some(Source::Wlr(s))) => d.set_selection(Some(s)),
            (Device::Ext(d), None) => d.set_selection(None),
            (Device::Wlr(d), None) => d.set_selection(None),
            // Mixed protocols cannot happen: one Session binds one manager.
            _ => {}
        }
    }

    fn destroy(&self) {
        match self {
            Device::Ext(d) => d.destroy(),
            Device::Wlr(d) => d.destroy(),
        }
    }
}

enum Manager {
    Ext(ext_mgr::ExtDataControlManagerV1),
    Wlr(wlr_mgr::ZwlrDataControlManagerV1),
}

impl Manager {
    fn bind(globals: &GlobalList, qh: &QueueHandle<Wl>, proto: Proto) -> Option<Manager> {
        Some(match proto {
            Proto::Ext => Manager::Ext(globals.bind(qh, 1..=1, ()).ok()?),
            Proto::Wlr => Manager::Wlr(globals.bind(qh, 1..=1, ()).ok()?),
        })
    }

    fn device(&self, seat: &wl_seat::WlSeat, qh: &QueueHandle<Wl>) -> Device {
        match self {
            Manager::Ext(m) => Device::Ext(m.get_data_device(seat, qh, ())),
            Manager::Wlr(m) => Device::Wlr(m.get_data_device(seat, qh, ())),
        }
    }

    fn source(&self, qh: &QueueHandle<Wl>) -> Source {
        match self {
            Manager::Ext(m) => Source::Ext(m.create_data_source(qh, ())),
            Manager::Wlr(m) => Source::Wlr(m.create_data_source(qh, ())),
        }
    }
}

// ---- event state --------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Monitor,
    Writer,
}

type Shared = Arc<Zeroizing<Vec<u8>>>;

struct Wl {
    role: Role,
    offers: HashMap<ObjectId, (Offer, OfferTypes)>,
    current: Option<(Offer, OfferTypes)>,
    /// Selection changes seen (the sequence number).
    seq: u32,
    /// A selection event arrived that has not been processed yet.
    changed: bool,
    change_at: Instant,
    finished: bool,
    /// Writer: our live source and its bytes.
    source: Option<(Source, Shared)>,
    /// Writer: `send` requests to serve after dispatch.
    sends: Vec<(OwnedFd, Shared)>,
}

impl Wl {
    fn new(role: Role) -> Wl {
        Wl {
            role,
            offers: HashMap::new(),
            current: None,
            seq: 0,
            changed: false,
            change_at: Instant::now(),
            finished: false,
            source: None,
            sends: Vec::new(),
        }
    }

    fn on_new_offer(&mut self, offer: Offer) {
        if self.role == Role::Writer || self.offers.len() >= MAX_PENDING_OFFERS {
            offer.destroy();
            return;
        }
        self.offers.insert(offer.id(), (offer, OfferTypes::new()));
    }

    fn on_mime(&mut self, id: &ObjectId, mime: &str) {
        if let Some((_, types)) = self.offers.get_mut(id) {
            types.add(mime);
        }
    }

    fn on_selection(&mut self, offer: Option<Offer>) {
        let entry = offer.map(|o| {
            self.offers
                .remove(&o.id())
                .unwrap_or_else(|| (o, OfferTypes::new()))
        });
        if self.role == Role::Writer {
            if let Some((o, _)) = entry {
                o.destroy();
            }
            return;
        }
        if let Some((old, _)) = std::mem::replace(&mut self.current, entry) {
            old.destroy();
        }
        self.seq = self.seq.wrapping_add(1);
        self.changed = true;
        self.change_at = Instant::now();
    }

    fn on_primary(&mut self, offer: Option<Offer>) {
        // PRIMARY is not watched in 4b (phase-4.md §4.10 item 2).
        if let Some(o) = offer {
            let o = self.offers.remove(&o.id()).map_or(o, |(o, _)| o);
            o.destroy();
        }
    }

    fn on_send(&mut self, id: &ObjectId, fd: OwnedFd) {
        match &self.source {
            Some((s, data)) if &s.id() == id && self.sends.len() < MAX_PENDING_SENDS => {
                self.sends.push((fd, Arc::clone(data)));
            }
            // Stale source or too many requests: closing the fd ends it.
            _ => drop(fd),
        }
    }

    fn on_cancelled(&mut self, id: &ObjectId, source_destroy: impl FnOnce()) {
        if matches!(&self.source, Some((s, _)) if &s.id() == id) {
            self.source = None;
        }
        source_destroy();
    }
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for Wl {
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

impl Dispatch<wl_seat::WlSeat, ()> for Wl {
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

macro_rules! data_control_dispatch {
    ($variant:ident, $mgr:ident, $dev:ident, $offer:ident, $src:ident,
     $Mgr:ty, $Dev:ty, $Off:ty, $Src:ty) => {
        impl Dispatch<$Mgr, ()> for Wl {
            fn event(
                _: &mut Self,
                _: &$Mgr,
                _: $mgr::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
            }
        }

        impl Dispatch<$Dev, ()> for Wl {
            fn event(
                st: &mut Self,
                _: &$Dev,
                event: $dev::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
                match event {
                    $dev::Event::DataOffer { id } => st.on_new_offer(Offer::$variant(id)),
                    $dev::Event::Selection { id } => st.on_selection(id.map(Offer::$variant)),
                    $dev::Event::PrimarySelection { id } => {
                        st.on_primary(id.map(Offer::$variant))
                    }
                    $dev::Event::Finished => st.finished = true,
                    _ => {}
                }
            }

            event_created_child!(Wl, $Dev, [
                $dev::EVT_DATA_OFFER_OPCODE => ($Off, ()),
            ]);
        }

        impl Dispatch<$Off, ()> for Wl {
            fn event(
                st: &mut Self,
                offer: &$Off,
                event: $offer::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
                if let $offer::Event::Offer { mime_type } = event {
                    st.on_mime(&offer.id(), &mime_type);
                }
            }
        }

        impl Dispatch<$Src, ()> for Wl {
            fn event(
                st: &mut Self,
                source: &$Src,
                event: $src::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
                match event {
                    $src::Event::Send { fd, .. } => st.on_send(&source.id(), fd),
                    $src::Event::Cancelled => st.on_cancelled(&source.id(), || source.destroy()),
                    _ => {}
                }
            }
        }
    };
}

data_control_dispatch!(
    Ext,
    ext_mgr,
    ext_dev,
    ext_offer,
    ext_src,
    ext_mgr::ExtDataControlManagerV1,
    ext_dev::ExtDataControlDeviceV1,
    ext_offer::ExtDataControlOfferV1,
    ext_src::ExtDataControlSourceV1
);
data_control_dispatch!(
    Wlr,
    wlr_mgr,
    wlr_dev,
    wlr_offer,
    wlr_src,
    wlr_mgr::ZwlrDataControlManagerV1,
    wlr_dev::ZwlrDataControlDeviceV1,
    wlr_offer::ZwlrDataControlOfferV1,
    wlr_src::ZwlrDataControlSourceV1
);

// ---- one connection -------------------------------------------------------

struct Session {
    conn: Connection,
    queue: EventQueue<Wl>,
    qh: QueueHandle<Wl>,
    state: Wl,
    manager: Manager,
    seat: wl_seat::WlSeat,
    device: Device,
    recreated: u32,
}

impl Session {
    fn open(env: &Env, proto: Proto, role: Role) -> Option<Session> {
        let conn = connect(env)?;
        let (globals, mut queue) = registry_queue_init::<Wl>(&conn).ok()?;
        let qh = queue.handle();
        let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=1, ()).ok()?;
        let manager = Manager::bind(&globals, &qh, proto)?;
        let device = manager.device(&seat, &qh);
        let mut state = Wl::new(role);
        // Delivers the current selection (initial check).
        queue.roundtrip(&mut state).ok()?;
        Some(Session {
            conn,
            queue,
            qh,
            state,
            manager,
            seat,
            device,
            recreated: 0,
        })
    }

    fn roundtrip(&mut self) -> bool {
        self.queue.roundtrip(&mut self.state).is_ok()
    }

    /// Dispatches what has been read; re-creates a `finished` device.
    /// `false` = the connection is unusable.
    fn dispatch(&mut self) -> bool {
        if self.queue.dispatch_pending(&mut self.state).is_err() {
            return false;
        }
        if self.state.finished {
            self.state.finished = false;
            self.recreated += 1;
            if self.recreated > MAX_DEVICE_RECREATE {
                return false;
            }
            self.device.destroy();
            self.device = self.manager.device(&self.seat, &self.qh);
        }
        self.conn.flush().is_ok()
    }

    /// Blocks until the connection or `wake` has something. `false` = the
    /// connection broke. Returns whether `wake` fired.
    fn wait(&mut self, wake: std::os::fd::BorrowedFd<'_>) -> Option<bool> {
        let Some(guard) = self.queue.prepare_read() else {
            return Some(false); // events already queued
        };
        let ready = wait_readable(&[guard.connection_fd(), wake], None);
        if ready[0] {
            match guard.read() {
                Ok(_) => {}
                Err(wayland_client::backend::WaylandError::Io(e))
                    if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return None,
            }
        } else {
            drop(guard);
        }
        Some(ready[1])
    }

    /// Reads `mime` of `offer` through a pipe (after flush, outside dispatch).
    fn receive(&self, offer: &Offer, mime: &str, max: usize, timeout: Duration) -> ReadResult {
        let failed = || ReadResult {
            bytes: Zeroizing::new(Vec::new()),
            end: ReadEnd::Failed,
        };
        let Ok((read, write)) = pipe() else {
            return failed();
        };
        offer.receive(mime, write.as_fd());
        drop(write);
        if self.conn.flush().is_err() {
            return failed();
        }
        read_capped(read.as_fd(), max, timeout)
    }

    /// Reads the current selection's text with the given caps. `None` when
    /// there is no text or it is marked as a password.
    fn read_current(&self, max: usize, timeout: Duration) -> Option<ReadResult> {
        let (offer, types) = self.state.current.as_ref()?;
        match types.decide() {
            OfferDecision::Read(mime) => Some(self.receive(offer, mime, max, timeout)),
            OfferDecision::Skip(_) => None,
        }
    }
}

// ---- writer thread -----------------------------------------------------------

enum WriteCmd {
    Set(Shared, SyncSender<bool>),
    Clear(SyncSender<bool>),
    Quit,
}

/// `pw-clip-write`: owns our data sources on a second connection.
struct Writer {
    tx: Sender<WriteCmd>,
    waker: Waker,
    join: Option<JoinHandle<()>>,
}

impl Writer {
    fn start(env: &Env, proto: Proto) -> Option<Writer> {
        let env = env.clone();
        let (tx, rx) = mpsc::channel();
        let (waker, wake) = waker().ok()?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let join = std::thread::Builder::new()
            .name("pw-clip-write".into())
            .spawn(move || {
                let Some(mut s) = Session::open(&env, proto, Role::Writer) else {
                    let _ = ready_tx.send(false);
                    return;
                };
                let _ = ready_tx.send(true);
                writer_loop(&mut s, &rx, &wake);
            })
            .ok()?;
        if ready_rx.recv() != Ok(true) {
            let _ = join.join();
            return None;
        }
        Some(Writer {
            tx,
            waker,
            join: Some(join),
        })
    }

    fn call(&self, make: impl FnOnce(SyncSender<bool>) -> WriteCmd) -> bool {
        let (tx, rx) = mpsc::sync_channel(1);
        if self.tx.send(make(tx)).is_err() {
            return false;
        }
        self.waker.wake();
        rx.recv_timeout(Duration::from_millis(
            super::monitor::CLIPBOARD_COMMAND_TIMEOUT_MS,
        ))
        .unwrap_or(false)
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.tx.send(WriteCmd::Quit);
        self.waker.wake();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn serve_sends(s: &mut Session) {
    for (fd, data) in std::mem::take(&mut s.state.sends) {
        // A reader that does not read within the timeout loses the data.
        let _ = write_all_timeout(fd.as_fd(), &data, Duration::from_millis(WRITE_TIMEOUT_MS));
    }
}

fn writer_loop(s: &mut Session, rx: &Receiver<WriteCmd>, wake: &super::io::WakeReceiver) {
    loop {
        if !s.dispatch() {
            return;
        }
        serve_sends(s);
        let Some(woken) = s.wait(wake.fd()) else {
            return;
        };
        if !woken {
            continue;
        }
        wake.drain();
        loop {
            let cmd = match rx.try_recv() {
                Ok(c) => c,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            };
            match cmd {
                WriteCmd::Set(data, reply) => {
                    let src = s.manager.source(&s.qh);
                    for m in WRITE_MIME_TYPES {
                        src.offer(m);
                    }
                    s.device.set_selection(Some(&src));
                    if let Some((old, _)) = s.state.source.replace((src, data)) {
                        old.destroy();
                    }
                    let ok = s.roundtrip();
                    let _ = reply.send(ok);
                }
                WriteCmd::Clear(reply) => {
                    s.device.set_selection(None);
                    if let Some((old, _)) = s.state.source.take() {
                        old.destroy();
                    }
                    let ok = s.roundtrip();
                    let _ = reply.send(ok);
                }
                WriteCmd::Quit => return,
            }
            serve_sends(s);
        }
    }
}

// ---- monitor thread ------------------------------------------------------------

struct MonitorState {
    s: Session,
    writer: Writer,
}

impl MonitorState {
    /// Turns the latest selection change into an event.
    fn process(&mut self, emitter: &mut Emitter) {
        if !self.s.state.changed {
            return;
        }
        self.s.state.changed = false;
        let sequence = self.s.state.seq;
        let at = self.s.state.change_at;
        let event = match &self.s.state.current {
            None => ClipEvent::Empty {
                sequence,
                reason: EmptyReason::NoText,
            },
            Some((_, types)) => match types.decide() {
                OfferDecision::Skip(reason) => ClipEvent::Empty { sequence, reason },
                OfferDecision::Read(_) => {
                    let read = self
                        .s
                        .read_current(
                            DATA_CONTROL_READ_MAX_BYTES,
                            Duration::from_millis(DATA_CONTROL_READ_TIMEOUT_MS),
                        )
                        .unwrap_or(ReadResult {
                            bytes: Zeroizing::new(Vec::new()),
                            end: ReadEnd::Failed,
                        });
                    event_from_read(sequence, read, false)
                }
            },
        };
        emitter.emit(event, at);
    }

    /// Sets the selection through the writer and waits until our own
    /// connection has seen (and analyzed) the change.
    fn write(&mut self, data: Option<Shared>, emitter: &mut Emitter) -> Result<u32, ClipError> {
        if let Some(d) = &data {
            emitter.record_write(Emitter::write_hash(d));
        }
        let ok = match data {
            Some(d) => self.writer.call(|r| WriteCmd::Set(d, r)),
            None => self.writer.call(WriteCmd::Clear),
        };
        if !ok || !self.s.roundtrip() {
            return Err(ClipError::WriteFailed);
        }
        let seq = self.s.state.seq;
        self.process(emitter);
        Ok(seq)
    }

    fn full_bytes(&self) -> Option<Zeroizing<Vec<u8>>> {
        let r = self.s.read_current(
            FULL_READ_MAX_BYTES,
            Duration::from_millis(FULL_READ_TIMEOUT_MS),
        )?;
        matches!(r.end, ReadEnd::Complete | ReadEnd::Capped).then_some(r.bytes)
    }

    /// Runs one command; `false` means quit.
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
                let data = snap.text.map(Arc::new);
                let _ = reply.send(self.write(data, emitter));
            }
            Command::Sequence(reply) => {
                let _ = reply.send(self.s.state.seq);
            }
            Command::Quit => return false,
        }
        true
    }
}

/// `pw-clip` main for the Wayland backends. Sends `true` on `ready` once
/// both connections are up, `false` if either fails.
pub(crate) fn run(env: &Env, proto: Proto, mut t: Thread, ready: SyncSender<bool>) {
    let Some(writer) = Writer::start(env, proto) else {
        let _ = ready.send(false);
        return;
    };
    let Some(s) = Session::open(env, proto, Role::Monitor) else {
        let _ = ready.send(false);
        return;
    };
    let mut m = MonitorState { s, writer };
    if !t.initial_check {
        m.s.state.changed = false;
    }
    let _ = ready.send(true);

    loop {
        if !m.s.dispatch() {
            return;
        }
        m.process(&mut t.emitter);
        if m.s.conn.flush().is_err() {
            return;
        }
        let Some(woken) = m.s.wait(t.wake.fd()) else {
            return;
        };
        if !woken {
            continue;
        }
        t.wake.drain();
        loop {
            match t.commands.try_recv() {
                Ok(cmd) => {
                    if !m.run(cmd, &mut t.emitter) {
                        return;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
    }
}
