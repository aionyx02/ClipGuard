//! The Linux [`Host`](crate::host::Host) (phase-4.md §4.2, §4.9.2): the
//! clipboard monitor and the foreground tracker behind the
//! platform-independent interface `pw-work` drives. 4b does no paste
//! interception on Linux, so there is no hook: [`Host::paste_into`] is
//! `Unsupported` and [`Host::check_hook`] is `NotApplicable`.
//!
//! The mapping from the backend selection to `ProtectionStatus` is pure and
//! tested on every OS; the host itself is Linux only.
//!
//! Threads: `pw-clip` (monitor), `pw-fg` (tracker), and `pw-host`, which
//! reports foreground changes every [`FOREGROUND_POLL_MS`]. Nothing has to
//! run on the main thread.
//!
//! Window titles are not read (the trackers only keep `WM_CLASS` / `app_id`
//! and the process name), so entry warnings that need a title (file
//! dialogs) do not fire on Linux.
//!
//! [`Host::paste_into`]: crate::host::Host::paste_into
//! [`Host::check_hook`]: crate::host::Host::check_hook

use super::backend::{self, ForegroundSource, LinuxStatus};
use super::foreground::ForegroundApp;
use crate::host::{ForegroundInfo, WindowId};
use crate::status::{Capability, ProtectionStatus, Reason};

/// How often `pw-host` looks for a foreground change (custom, same as
/// macOS: the trackers have no callback into the host).
pub const FOREGROUND_POLL_MS: u64 = 100;

/// A backend reason as a `status::Reason` (§4.9.4).
pub fn reason(r: backend::Reason) -> Reason {
    match r {
        backend::Reason::NoDataControl => Reason::NoDataControl,
        backend::Reason::XWaylandUnverified => Reason::XWaylandUnverified,
        backend::Reason::CosmicDisabled => Reason::CosmicDisabled,
        backend::Reason::NoForeignToplevel => Reason::NoForeignToplevel,
        backend::Reason::WaylandNoIntercept => Reason::WaylandNoIntercept,
        backend::Reason::X11NoIntercept => Reason::X11NoIntercept,
        backend::Reason::NoDisplay => Reason::NoDisplay,
    }
}

/// A backend capability as a `status::Capability`.
pub fn capability(c: backend::Capability) -> Capability {
    match c {
        backend::Capability::Active => Capability::Active,
        backend::Capability::Degraded(r) => Capability::Degraded(reason(r)),
        backend::Capability::Unavailable(r) => Capability::Unavailable(reason(r)),
    }
}

/// How starting the clipboard monitor went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorState {
    Running,
    /// The selection found no backend; its status already says why.
    NoBackend,
    /// A backend was selected but the display could not be reached or lacks
    /// a needed extension.
    ConnectFailed,
}

/// §4.8.1 / §4.9.2 for Linux: the selection's report, corrected by what
/// actually started. `tracker_running`: the foreground tracker is up.
pub fn status_from(
    selected: LinuxStatus,
    fg_source: ForegroundSource,
    monitor: MonitorState,
    tracker_running: bool,
) -> ProtectionStatus {
    let mut s = ProtectionStatus {
        watch: capability(selected.watch),
        write: capability(selected.write),
        foreground: capability(selected.foreground),
        intercept: capability(selected.intercept),
    };
    if monitor == MonitorState::ConnectFailed {
        s.watch = Capability::Unavailable(Reason::NoDisplay);
        s.write = Capability::Unavailable(Reason::NoDisplay);
    }
    if !tracker_running && s.foreground.is_active() {
        s.foreground = Capability::Unavailable(match fg_source {
            ForegroundSource::WlrForeignToplevel => Reason::NoForeignToplevel,
            ForegroundSource::X11ActiveWindow | ForegroundSource::None => Reason::NoDisplay,
        });
    }
    s
}

/// A foreground window as the worker sees it: the X11 window id (or the
/// tracker's toplevel id) is the window and its root; `class` is the
/// `WM_CLASS` class or Wayland `app_id`, `process` is `/proc/<pid>/comm`.
pub fn foreground_info(app: &ForegroundApp) -> ForegroundInfo {
    let window = WindowId::try_from(app.window).unwrap_or(0);
    ForegroundInfo {
        window,
        root: window,
        class: app.class.clone(),
        title: None,
        process: app.process.clone(),
        elevated: false,
    }
}

#[cfg(target_os = "linux")]
pub use imp::start_host;

#[cfg(target_os = "linux")]
mod imp {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use zeroize::Zeroizing;

    use super::super::foreground::{ForegroundHistory, SharedForeground};
    use super::super::monitor::{
        ClipError, ClipboardHandle, ClipboardMonitor, MonitorOptions, StartError, env_from_process,
        probe,
    };
    use super::super::tracker::ForegroundTracker;
    use super::{FOREGROUND_POLL_MS, MonitorState, foreground_info, status_from};
    use crate::gate::PasteGate;
    use crate::host::{
        EventSink, HookCheck, Host, HostError, HostEvent, HostOptions, HostSnapshot, WindowId,
    };
    use crate::status::ProtectionStatus;

    type SharedSink = Arc<Mutex<EventSink>>;

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn emit(sink: &SharedSink, ev: HostEvent) {
        (lock(sink))(ev);
    }

    fn clip_err(e: ClipError) -> HostError {
        match e {
            ClipError::Busy => HostError::Timeout,
            ClipError::WriteFailed => HostError::Clipboard,
        }
    }

    /// Starts the Linux host from the process environment. A session
    /// without a usable backend (GNOME without XWayland, no display) still
    /// starts: [`Host::status`] says why, and clipboard operations return
    /// `Unsupported`. `opts` is ignored: there is no interception to install.
    pub fn start_host(sink: EventSink, opts: HostOptions) -> Result<Box<dyn Host>, HostError> {
        let _ = opts;
        let sink: SharedSink = Arc::new(Mutex::new(sink));
        let env = env_from_process();
        let selection = probe(&env);
        let history = ForegroundHistory::shared();

        let clip_sink = Arc::clone(&sink);
        let started = ClipboardMonitor::start_with(
            MonitorOptions {
                env: Some(env.clone()),
                backend: None,
                foreground: Some(Arc::clone(&history)),
            },
            Box::new(move |e| emit(&clip_sink, HostEvent::Clip(e))),
        );
        let (monitor, state) = match started {
            Ok(m) => (Some(m), MonitorState::Running),
            Err(StartError::Unavailable(_)) => (None, MonitorState::NoBackend),
            Err(StartError::Connect) => (None, MonitorState::ConnectFailed),
            Err(StartError::ThreadGone) => return Err(HostError::Stopped),
        };
        // The monitor's own probe may differ from ours if the compositor
        // changed in between; trust the one that started.
        let selection = monitor.as_ref().map_or(selection, |m| m.selection());

        let tracker = ForegroundTracker::start(&env, selection.foreground, Arc::clone(&history));
        let status = status_from(
            selection.status,
            selection.foreground,
            state,
            tracker.is_some(),
        );

        let quit = Arc::new(AtomicBool::new(false));
        let forwarder = match tracker {
            Some(_) => {
                let quit = Arc::clone(&quit);
                let sink = Arc::clone(&sink);
                let history = Arc::clone(&history);
                Some(
                    std::thread::Builder::new()
                        .name("pw-host".into())
                        .spawn(move || forward_foreground(&sink, &history, &quit))
                        .map_err(|_| HostError::Stopped)?,
                )
            }
            None => None,
        };

        Ok(Box::new(LinuxHost {
            gate: Arc::new(PasteGate::new()),
            status,
            clip: monitor.as_ref().map(ClipboardMonitor::handle),
            quit,
            forwarder,
            _tracker: tracker.map(Mutex::new),
            _monitor: monitor.map(Mutex::new),
        }))
    }

    fn forward_foreground(sink: &SharedSink, history: &SharedForeground, quit: &AtomicBool) {
        let mut last = None;
        while !quit.load(Ordering::Acquire) {
            let current = lock(history).current().cloned();
            if let Some(app) = current {
                let key = (app.window, app.class.clone(), app.pid);
                if last.as_ref() != Some(&key) {
                    last = Some(key);
                    emit(sink, HostEvent::Foreground(foreground_info(&app)));
                }
            }
            std::thread::sleep(Duration::from_millis(FOREGROUND_POLL_MS));
        }
    }

    struct LinuxHost {
        gate: Arc<PasteGate>,
        /// Fixed at start: the backend does not change while running.
        status: ProtectionStatus,
        clip: Option<ClipboardHandle>,
        quit: Arc<AtomicBool>,
        forwarder: Option<JoinHandle<()>>,
        // Held for their `Drop` (stop and join the threads). Wrapped in a
        // `Mutex` so the host is `Sync` whatever the types hold.
        _tracker: Option<Mutex<ForegroundTracker>>,
        _monitor: Option<Mutex<ClipboardMonitor>>,
    }

    impl LinuxHost {
        fn clip(&self) -> Result<&ClipboardHandle, HostError> {
            self.clip.as_ref().ok_or(HostError::Unsupported)
        }
    }

    impl Host for LinuxHost {
        fn gate(&self) -> &Arc<PasteGate> {
            &self.gate
        }

        fn status(&self) -> ProtectionStatus {
            self.status
        }

        fn write_text(&self, text: &str) -> Result<u32, HostError> {
            self.clip()?.write_text(text).map_err(clip_err)
        }

        fn clear(&self) -> Result<u32, HostError> {
            self.clip()?.clear().map_err(clip_err)
        }

        fn read_full(&self) -> Option<Zeroizing<String>> {
            self.clip.as_ref()?.read_full()
        }

        fn snapshot(&self) -> Result<HostSnapshot, HostError> {
            let snap = self.clip()?.snapshot().map_err(clip_err)?;
            Ok(HostSnapshot(Box::new(snap)))
        }

        fn restore(&self, snap: HostSnapshot) -> Result<u32, HostError> {
            let snap = snap
                .0
                .downcast::<super::super::monitor::Snapshot>()
                .map_err(|_| HostError::Clipboard)?;
            self.clip()?.restore(*snap).map_err(clip_err)
        }

        /// No interception on Linux in 4b (§4.9.2), so nothing to re-send.
        fn paste_into(&self, _target: WindowId) -> Result<(), HostError> {
            Err(HostError::Unsupported)
        }

        /// Not implemented on Linux (would need XScreenSaver / ext-idle-notify):
        /// unknown, so core's swap detector only applies the fast-replacement
        /// window to address-only content.
        fn idle_ms(&self) -> Option<u64> {
            None
        }

        fn set_intercept(&self, enabled: bool) -> Result<(), HostError> {
            if enabled {
                Err(HostError::Unsupported)
            } else {
                Ok(())
            }
        }

        fn check_hook(&self) -> HookCheck {
            HookCheck::NotApplicable
        }

        fn reinstall_hook(&self) -> Result<(), HostError> {
            Err(HostError::Unsupported)
        }
    }

    impl Drop for LinuxHost {
        fn drop(&mut self) {
            self.quit.store(true, Ordering::Release);
            if let Some(t) = self.forwarder.take() {
                let _ = t.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::backend::{Env, WaylandGlobals, select};
    use super::*;

    fn sel(
        wl: bool,
        x: bool,
        desktop: Option<&str>,
        g: Option<WaylandGlobals>,
    ) -> backend::Selection {
        select(
            &Env::from_vars(
                wl.then(|| "wayland-1".into()),
                x.then(|| ":0".into()),
                desktop.map(Into::into),
            ),
            g,
        )
    }

    fn globals(ext: bool, wlr: bool, toplevel: bool) -> Option<WaylandGlobals> {
        Some(WaylandGlobals {
            ext_data_control: ext,
            wlr_data_control: wlr,
            wlr_foreign_toplevel: toplevel,
            seat: true,
        })
    }

    fn status(s: backend::Selection, m: MonitorState, tracker: bool) -> ProtectionStatus {
        status_from(s.status, s.foreground, m, tracker)
    }

    #[test]
    fn every_reason_maps_to_the_same_id() {
        use backend::Reason as B;
        for (b, r) in [
            (B::NoDataControl, Reason::NoDataControl),
            (B::XWaylandUnverified, Reason::XWaylandUnverified),
            (B::CosmicDisabled, Reason::CosmicDisabled),
            (B::NoForeignToplevel, Reason::NoForeignToplevel),
            (B::WaylandNoIntercept, Reason::WaylandNoIntercept),
            (B::X11NoIntercept, Reason::X11NoIntercept),
            (B::NoDisplay, Reason::NoDisplay),
        ] {
            assert_eq!(reason(b), r);
        }
        assert_eq!(
            capability(backend::Capability::Degraded(B::XWaylandUnverified)),
            Capability::Degraded(Reason::XWaylandUnverified)
        );
    }

    #[test]
    fn wayland_with_data_control_and_toplevel() {
        let s = status(
            sel(true, true, None, globals(true, false, true)),
            MonitorState::Running,
            true,
        );
        assert!(s.watch.is_active() && s.write.is_active() && s.foreground.is_active());
        assert_eq!(
            s.intercept,
            Capability::Unavailable(Reason::WaylandNoIntercept)
        );
    }

    #[test]
    fn wayland_without_foreign_toplevel() {
        let s = status(
            sel(true, false, Some("KDE"), globals(true, false, false)),
            MonitorState::Running,
            false,
        );
        assert!(s.watch.is_active());
        assert_eq!(
            s.foreground,
            Capability::Unavailable(Reason::NoForeignToplevel)
        );
    }

    #[test]
    fn toplevel_advertised_but_tracker_failed() {
        let s = status(
            sel(true, false, None, globals(true, false, true)),
            MonitorState::Running,
            false,
        );
        assert_eq!(
            s.foreground,
            Capability::Unavailable(Reason::NoForeignToplevel)
        );
    }

    #[test]
    fn x11_session() {
        let s = status(sel(false, true, None, None), MonitorState::Running, true);
        assert!(s.watch.is_active() && s.foreground.is_active());
        assert_eq!(s.intercept, Capability::Unavailable(Reason::X11NoIntercept));
        let s = status(sel(false, true, None, None), MonitorState::Running, false);
        assert_eq!(s.foreground, Capability::Unavailable(Reason::NoDisplay));
    }

    #[test]
    fn x11_connect_failure() {
        let s = status(
            sel(false, true, None, None),
            MonitorState::ConnectFailed,
            false,
        );
        assert_eq!(s.watch, Capability::Unavailable(Reason::NoDisplay));
        assert_eq!(s.write, Capability::Unavailable(Reason::NoDisplay));
    }

    #[test]
    fn gnome_xwayland_fallback() {
        let s = status(
            sel(true, true, Some("GNOME"), globals(false, false, false)),
            MonitorState::Running,
            false,
        );
        assert_eq!(s.watch, Capability::Degraded(Reason::XWaylandUnverified));
        assert_eq!(
            s.foreground,
            Capability::Unavailable(Reason::NoForeignToplevel)
        );
        assert_eq!(
            s.intercept,
            Capability::Unavailable(Reason::WaylandNoIntercept)
        );
    }

    #[test]
    fn gnome_without_xwayland() {
        let s = status(
            sel(true, false, Some("GNOME"), globals(false, false, false)),
            MonitorState::NoBackend,
            false,
        );
        assert_eq!(s.watch, Capability::Unavailable(Reason::NoDataControl));
    }

    #[test]
    fn cosmic_without_data_control() {
        // §4.9.4 table: Unavailable (open question §4.10 item 6 proposes
        // Degraded when the XWayland fallback runs; not decided).
        let s = status(
            sel(true, true, Some("COSMIC"), globals(false, false, true)),
            MonitorState::Running,
            true,
        );
        assert_eq!(s.watch, Capability::Unavailable(Reason::CosmicDisabled));
    }

    #[test]
    fn no_display() {
        let s = status(
            sel(false, false, None, None),
            MonitorState::NoBackend,
            false,
        );
        for (_, c) in s.areas() {
            assert_eq!(c, Capability::Unavailable(Reason::NoDisplay));
        }
    }

    #[test]
    fn foreground_info_fields() {
        let app = ForegroundApp::new(
            Some("XTerm".into()),
            Some("xterm".into()),
            Some("xterm".into()),
            Some(42),
            0x1a0_0007,
        );
        let f = foreground_info(&app);
        assert_eq!((f.window, f.root), (0x1a0_0007, 0x1a0_0007));
        assert_eq!(f.class.as_deref(), Some("XTerm"));
        assert_eq!(f.process.as_deref(), Some("xterm"));
        assert_eq!(f.title, None);
        let huge = ForegroundApp::new(None, None, None, None, u64::MAX);
        assert_eq!(foreground_info(&huge).window, 0, "out of range is unknown");
    }
}
