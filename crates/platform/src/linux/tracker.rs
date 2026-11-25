//! Foreground trackers (phase-4.md §4.9.2): `_NET_ACTIVE_WINDOW` on X11,
//! `zwlr_foreign_toplevel_manager_v1` on Wayland. Each runs on its own
//! `pw-fg` thread with its own connection and pushes into a
//! [`SharedForeground`].

use std::collections::HashMap;
use std::os::fd::AsFd;
use std::thread::JoinHandle;
use std::time::Instant;

use wayland_client::backend::ObjectId;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_registry;
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle, event_created_child};
use wayland_protocols_wlr::foreign_toplevel::v1::client::{
    zwlr_foreign_toplevel_handle_v1 as handle, zwlr_foreign_toplevel_manager_v1 as manager,
};
use x11rb::connection::Connection as _;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ChangeWindowAttributesAux, ConnectionExt as _, EventMask, Window,
};
use x11rb::rust_connection::RustConnection;

use super::backend::{Env, ForegroundSource};
use super::foreground::{ForegroundApp, SharedForeground, WM_CLASS_MAX_BYTES, parse_wm_class};
use super::io::{WakeReceiver, Waker, wait_readable, waker};
use super::x11::{connect as x11_connect, process_name, window_pid};

/// Toplevels tracked at most (custom); more are ignored.
pub const MAX_TOPLEVELS: usize = 512;
/// `zwlr_foreign_toplevel_handle_v1.state` value for "activated".
const STATE_ACTIVATED: u32 = 2;

/// Owns a `pw-fg` thread; dropping it stops the thread.
pub struct ForegroundTracker {
    waker: Waker,
    join: Option<JoinHandle<()>>,
}

impl ForegroundTracker {
    /// Starts tracking with `source` (from [`super::backend::select`]).
    /// `None` when the source is [`ForegroundSource::None`] or the display
    /// cannot be reached.
    pub fn start(
        env: &Env,
        source: ForegroundSource,
        history: SharedForeground,
    ) -> Option<ForegroundTracker> {
        let (waker, wake) = waker().ok()?;
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let env = env.clone();
        let spawn = std::thread::Builder::new().name("pw-fg".into());
        let join = match source {
            ForegroundSource::X11ActiveWindow => spawn.spawn(move || {
                let Some(x) = X11Fg::open(&env, history) else {
                    let _ = ready_tx.send(false);
                    return;
                };
                let _ = ready_tx.send(true);
                x.run(&wake);
            }),
            ForegroundSource::WlrForeignToplevel => spawn.spawn(move || {
                wayland_main(&env, history, &wake, ready_tx);
            }),
            ForegroundSource::None => return None,
        }
        .ok()?;
        if ready_rx.recv() != Ok(true) {
            let _ = join.join();
            return None;
        }
        Some(ForegroundTracker {
            waker,
            join: Some(join),
        })
    }
}

impl Drop for ForegroundTracker {
    fn drop(&mut self) {
        self.waker.wake();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

// ---- X11 -----------------------------------------------------------------------

struct X11Fg {
    conn: RustConnection,
    root: Window,
    net_active: Atom,
    history: SharedForeground,
}

impl X11Fg {
    fn open(env: &Env, history: SharedForeground) -> Option<X11Fg> {
        let (conn, screen) = x11_connect(env)?;
        let root = conn.setup().roots.get(screen)?.root;
        let net_active = conn
            .intern_atom(false, b"_NET_ACTIVE_WINDOW")
            .ok()?
            .reply()
            .ok()?
            .atom;
        conn.change_window_attributes(
            root,
            &ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )
        .ok()?;
        conn.flush().ok()?;
        let x = X11Fg {
            conn,
            root,
            net_active,
            history,
        };
        x.record();
        Some(x)
    }

    fn active_window(&self) -> Option<Window> {
        let r = self
            .conn
            .get_property(false, self.root, self.net_active, AtomEnum::WINDOW, 0, 1)
            .ok()?
            .reply()
            .ok()?;
        r.value32()?.next().filter(|&w| w != 0)
    }

    fn app(&self, w: Window) -> ForegroundApp {
        let units = u32::try_from(WM_CLASS_MAX_BYTES / 4).unwrap_or(u32::MAX);
        let (instance, class) = self
            .conn
            .get_property(false, w, AtomEnum::WM_CLASS, AtomEnum::STRING, 0, units)
            .ok()
            .and_then(|c| c.reply().ok())
            .map(|r| parse_wm_class(&r.value))
            .unwrap_or((None, None));
        let pid = window_pid(&self.conn, w);
        let process = pid.and_then(process_name);
        ForegroundApp::new(class, instance, process, pid, u64::from(w))
    }

    fn record(&self) {
        let Some(w) = self.active_window() else {
            return;
        };
        let app = self.app(w);
        if let Ok(mut h) = self.history.lock() {
            h.push(app, Instant::now());
        }
    }

    fn run(self, wake: &WakeReceiver) {
        loop {
            loop {
                match self.conn.poll_for_event() {
                    Ok(Some(Event::PropertyNotify(e)))
                        if e.window == self.root && e.atom == self.net_active =>
                    {
                        self.record();
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
            if self.conn.flush().is_err() {
                return;
            }
            let fd = self.conn.stream().as_fd();
            if wait_readable(&[fd, wake.fd()], None)[1] {
                return;
            }
        }
    }
}

// ---- Wayland -------------------------------------------------------------------

#[derive(Default)]
struct Toplevel {
    app_id: Option<String>,
    activated: bool,
}

struct Fg {
    toplevels: HashMap<ObjectId, Toplevel>,
    /// Toplevel last pushed as active.
    active: Option<ObjectId>,
    history: SharedForeground,
    finished: bool,
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for Fg {
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

impl Dispatch<manager::ZwlrForeignToplevelManagerV1, ()> for Fg {
    fn event(
        st: &mut Self,
        _: &manager::ZwlrForeignToplevelManagerV1,
        event: manager::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            manager::Event::Toplevel { toplevel } => {
                if st.toplevels.len() < MAX_TOPLEVELS {
                    st.toplevels.insert(toplevel.id(), Toplevel::default());
                } else {
                    toplevel.destroy();
                }
            }
            manager::Event::Finished => st.finished = true,
            _ => {}
        }
    }

    event_created_child!(Fg, manager::ZwlrForeignToplevelManagerV1, [
        manager::EVT_TOPLEVEL_OPCODE => (handle::ZwlrForeignToplevelHandleV1, ()),
    ]);
}

impl Dispatch<handle::ZwlrForeignToplevelHandleV1, ()> for Fg {
    fn event(
        st: &mut Self,
        h: &handle::ZwlrForeignToplevelHandleV1,
        event: handle::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let id = h.id();
        match event {
            handle::Event::AppId { app_id } => {
                if let Some(t) = st.toplevels.get_mut(&id) {
                    t.app_id = Some(app_id);
                }
            }
            handle::Event::State { state } => {
                if let Some(t) = st.toplevels.get_mut(&id) {
                    t.activated = state
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .any(|c| u32::from_ne_bytes(*c) == STATE_ACTIVATED);
                }
            }
            handle::Event::Done => {
                let Some(t) = st.toplevels.get(&id) else {
                    return;
                };
                if t.activated && st.active.as_ref() != Some(&id) {
                    let app = ForegroundApp::new(
                        t.app_id.clone(),
                        None,
                        None,
                        None,
                        u64::from(id.protocol_id()),
                    );
                    st.active = Some(id);
                    if let Ok(mut hist) = st.history.lock() {
                        hist.push(app, Instant::now());
                    }
                } else if !t.activated && st.active.as_ref() == Some(&id) {
                    st.active = None;
                }
            }
            handle::Event::Closed => {
                st.toplevels.remove(&id);
                if st.active.as_ref() == Some(&id) {
                    st.active = None;
                }
                h.destroy();
            }
            _ => {}
        }
    }
}

fn wayland_main(
    env: &Env,
    history: SharedForeground,
    wake: &WakeReceiver,
    ready: std::sync::mpsc::SyncSender<bool>,
) {
    let setup = || {
        let conn = super::wayland::connect(env)?;
        let (globals, queue) = registry_queue_init::<Fg>(&conn).ok()?;
        let qh = queue.handle();
        let _mgr: manager::ZwlrForeignToplevelManagerV1 = globals.bind(&qh, 1..=3, ()).ok()?;
        Some((conn, queue, _mgr))
    };
    let Some((conn, mut queue, _mgr)) = setup() else {
        let _ = ready.send(false);
        return;
    };
    let mut st = Fg {
        toplevels: HashMap::new(),
        active: None,
        history,
        finished: false,
    };
    if queue.roundtrip(&mut st).is_err() {
        let _ = ready.send(false);
        return;
    }
    let _ = ready.send(true);
    loop {
        if queue.dispatch_pending(&mut st).is_err() || st.finished || conn.flush().is_err() {
            return;
        }
        let Some(guard) = queue.prepare_read() else {
            continue;
        };
        let r = wait_readable(&[guard.connection_fd(), wake.fd()], None);
        if r[1] {
            return;
        }
        if r[0] {
            match guard.read() {
                Ok(_) => {}
                Err(wayland_client::backend::WaylandError::Io(e))
                    if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        } else {
            drop(guard);
        }
    }
}
