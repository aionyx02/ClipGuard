//! The Windows [`Host`] (docs/plan/phase-4.md §4.2): `pw-clip` (clipboard,
//! foreground, session lock) from [`ClipboardMonitor`], `pw-hook` from
//! [`PasteHook`], and a small `pw-hook-events` thread that turns the hook's
//! bounded channel into [`HostEvent`]s, so the hook callback never runs the
//! worker's sink.
//!
//! The host never analyzes anything (P7) and never formats clipboard text or
//! window titles into errors or logs (P3).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

use zeroize::Zeroizing;

use super::clipboard::Snapshot;
use super::monitor::{ClipboardHandle, ClipboardMonitor, MonitorOptions};
use super::paste_hook::{HOOK_EVENT_QUEUE_LEN, HookMsg, PasteHook};
use super::{input, send, session};
use crate::clipboard::ClipEvent;
use crate::gate::PasteGate;
use crate::host::{
    EventSink, HookCheck, Host, HostError, HostEvent, HostOptions, HostSnapshot, WindowId,
};
use crate::status::{Capability, ProtectionStatus, Reason};

type SharedSink = Arc<Mutex<EventSink>>;

/// Calls the worker's sink; a panicking sink loses that one event instead of
/// unwinding into a Win32 callback.
fn emit(sink: &SharedSink, event: HostEvent) {
    let mut guard = match sink.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let _ = catch_unwind(AssertUnwindSafe(|| (guard)(event)));
}

struct HookSlot {
    hook: Option<PasteHook>,
    /// `HostOptions::intercept` / [`Host::set_intercept`].
    wanted: bool,
    /// Installing failed the last time we tried.
    failed: bool,
    /// Debug builds: dropped on purpose, reinstalling is a no-op.
    debug_dropped: bool,
}

/// The Windows OS side. Created by [`start_host`].
pub struct WindowsHost {
    gate: Arc<PasteGate>,
    monitor: Option<ClipboardMonitor>,
    clip: ClipboardHandle,
    hook: Mutex<HookSlot>,
    hook_events: Mutex<Option<SyncSender<HookMsg>>>,
    forwarder: Option<JoinHandle<()>>,
}

/// Starts `pw-clip` (and `pw-hook` when `opts.intercept`). A hook that fails
/// to install does not fail the host: it shows up in [`Host::status`].
pub fn start_host(sink: EventSink, opts: HostOptions) -> Result<Box<dyn Host>, HostError> {
    let gate = Arc::new(PasteGate::new());
    let sink: SharedSink = Arc::new(Mutex::new(sink));

    let clip_sink = Arc::clone(&sink);
    let clip_gate = Arc::clone(&gate);
    let fg_sink = Arc::clone(&sink);
    let session_sink = Arc::clone(&sink);
    let monitor = ClipboardMonitor::start_with(
        Box::new(move |e: ClipEvent| {
            let seq = match &e {
                ClipEvent::Text(t) => t.sequence,
                ClipEvent::Empty { sequence, .. } => *sequence,
            };
            clip_gate.set_clipboard_seq(seq);
            emit(&clip_sink, HostEvent::Clip(e));
        }),
        MonitorOptions {
            foreground: Some(Box::new(move |f| emit(&fg_sink, HostEvent::Foreground(f)))),
            session: Some(Box::new(move |locked| {
                emit(&session_sink, HostEvent::SessionLocked(locked));
            })),
        },
    )
    .map_err(|_| HostError::Clipboard)?;

    let (tx, rx) = mpsc::sync_channel(HOOK_EVENT_QUEUE_LEN);
    let fwd_sink = Arc::clone(&sink);
    let forwarder = std::thread::Builder::new()
        .name("pw-hook-events".into())
        .spawn(move || forward(rx, fwd_sink))
        .map_err(|_| HostError::Stopped)?;

    let host = WindowsHost {
        gate,
        clip: monitor.handle(),
        monitor: Some(monitor),
        hook: Mutex::new(HookSlot {
            hook: None,
            wanted: opts.intercept,
            failed: false,
            debug_dropped: false,
        }),
        hook_events: Mutex::new(Some(tx)),
        forwarder: Some(forwarder),
    };
    if opts.intercept {
        let _ = host.install_hook(&mut host.slot());
    }
    Ok(Box::new(host))
}

fn forward(rx: Receiver<HookMsg>, sink: SharedSink) {
    while let Ok(msg) = rx.recv() {
        let event = match msg {
            HookMsg::PasteSwallowed { target, reason } => {
                HostEvent::PasteSwallowed { target, reason }
            }
            HookMsg::EnterSwallowed { target } => HostEvent::EnterSwallowed { target },
            HookMsg::ProbeAnswered => HostEvent::ProbeAnswered,
        };
        emit(&sink, event);
    }
}

impl WindowsHost {
    fn slot(&self) -> MutexGuard<'_, HookSlot> {
        match self.hook.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn install_hook(&self, slot: &mut HookSlot) -> Result<(), HostError> {
        if slot.hook.is_some() {
            return Ok(());
        }
        let events = match self.hook_events.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
        .ok_or(HostError::Stopped)?;
        match PasteHook::start(Arc::clone(&self.gate), events) {
            Ok(h) => {
                slot.hook = Some(h);
                slot.failed = false;
                Ok(())
            }
            Err(_) => {
                slot.failed = true;
                Err(HostError::Hook)
            }
        }
    }
}

impl Host for WindowsHost {
    fn gate(&self) -> &Arc<PasteGate> {
        &self.gate
    }

    fn status(&self) -> ProtectionStatus {
        let slot = self.slot();
        // `debug_dropped` still reports Active: the worker has to notice
        // through the probe (§4.8.4 item 6).
        let intercept = if !slot.wanted {
            Capability::Unavailable(Reason::DisabledInSettings)
        } else if slot.hook.is_some() {
            Capability::Active
        } else {
            // No dedicated reason for "could not install" yet (reported).
            Capability::Unavailable(Reason::HookLost)
        };
        let foreground_ok = self
            .monitor
            .as_ref()
            .is_some_and(ClipboardMonitor::foreground_active);
        ProtectionStatus {
            watch: Capability::Active,
            write: Capability::Active,
            foreground: if foreground_ok {
                Capability::Active
            } else {
                Capability::Unavailable(Reason::HookLost)
            },
            intercept,
        }
    }

    fn write_text(&self, text: &str) -> Result<u32, HostError> {
        self.clip.write_text(text).map_err(|_| HostError::Clipboard)
    }

    fn clear(&self) -> Result<u32, HostError> {
        self.clip.clear().map_err(|_| HostError::Clipboard)
    }

    fn read_full(&self) -> Option<Zeroizing<String>> {
        self.clip.read_full()
    }

    fn snapshot(&self) -> Result<HostSnapshot, HostError> {
        let snap = self.clip.snapshot().map_err(|_| HostError::Clipboard)?;
        Ok(HostSnapshot(Box::new(snap)))
    }

    fn restore(&self, snap: HostSnapshot) -> Result<u32, HostError> {
        let snap = snap
            .0
            .downcast::<Snapshot>()
            .map_err(|_| HostError::Clipboard)?;
        self.clip.restore(*snap).map_err(|_| HostError::Clipboard)
    }

    fn paste_into(&self, target: WindowId) -> Result<(), HostError> {
        send::paste_into(target)
    }

    fn idle_ms(&self) -> u64 {
        input::idle_ms()
    }

    fn set_intercept(&self, enabled: bool) -> Result<(), HostError> {
        let mut slot = self.slot();
        slot.wanted = enabled;
        if enabled {
            self.install_hook(&mut slot)
        } else {
            // Dropping joins `pw-hook` after unhooking (§4.3: unhook first).
            slot.hook = None;
            slot.failed = false;
            slot.debug_dropped = false;
            Ok(())
        }
    }

    fn check_hook(&self) -> HookCheck {
        let slot = self.slot();
        if !slot.wanted || slot.hook.is_none() {
            return HookCheck::NotApplicable;
        }
        drop(slot);
        if send::send_probe() {
            HookCheck::ProbeSent
        } else {
            HookCheck::NotApplicable
        }
    }

    fn reinstall_hook(&self) -> Result<(), HostError> {
        let mut slot = self.slot();
        if !slot.wanted || slot.debug_dropped {
            return Ok(());
        }
        match &slot.hook {
            Some(h) => h.reinstall().map_err(|_| HostError::Hook),
            None => self.install_hook(&mut slot),
        }
    }

    fn secure_desktop_active(&self) -> bool {
        session::secure_desktop_active()
    }

    #[cfg(debug_assertions)]
    fn debug_drop_hook(&self) {
        let mut slot = self.slot();
        if let Some(h) = &slot.hook {
            let _ = h.remove();
            slot.debug_dropped = true;
        }
    }

    #[cfg(debug_assertions)]
    fn debug_restore_hook(&self) {
        let mut slot = self.slot();
        if slot.debug_dropped {
            slot.debug_dropped = false;
            if let Some(h) = &slot.hook {
                let _ = h.reinstall();
            }
        }
    }
}

impl Drop for WindowsHost {
    fn drop(&mut self) {
        // Unhook first (§4.3), then stop the forwarder, then `pw-clip`.
        self.slot().hook = None;
        match self.hook_events.lock() {
            Ok(mut g) => *g = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
        if let Some(t) = self.forwarder.take() {
            let _ = t.join();
        }
        self.monitor = None;
    }
}
