//! Tauri application set-up (phase-4.md §4.2): single instance, tray,
//! windows, the `pw-work` thread and the platform host.
//!
//! The desktop app contacts no network endpoint: there is no HTTP plugin, the
//! CSP only allows the IPC origin, and AI features (Phase 5) are off.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::Arc;
use std::sync::mpsc::{self, sync_channel};
use std::time::{Duration, Instant};

use paste_warden_core::Platform;
use paste_warden_core::policy::registered::KEY_LENGTH;
use paste_warden_core::policy::windows::WindowsRules;
use paste_warden_i18n::locale::map_locale;
use paste_warden_platform::host::{EventSink, Host};
use tauri::{AppHandle, Manager, RunEvent, Runtime, WindowEvent};

use crate::bridge::LocalProbe;
use crate::host_impl::{NullHost, start_host};
use crate::persist::{MemoryPersistence, Persistence};
use crate::ui::{TauriUi, WINDOW_CONFIRM, WINDOW_ONBOARDING, WorkerTx, create_tray, show_window};
use crate::worker::{Boot, PasteChoice, UiCommand, Worker, WorkerConfig, WorkerMsg};

/// How long quitting waits for `pw-work` to remove the hook.
pub const SHUTDOWN_TIMEOUT_MS: u64 = 2_000;
/// macOS bundle id (also our `own_ids` entry there).
pub const BUNDLE_ID: &str = "org.pastewarden.app";

fn platform() -> (Platform, &'static WindowsRules) {
    use paste_warden_core::policy::{linux, macos, windows};
    if cfg!(windows) {
        (Platform::Windows, windows::windows_rules())
    } else if cfg!(target_os = "macos") {
        (Platform::MacOs, macos::macos_rules())
    } else {
        (Platform::Linux, linux::linux_rules())
    }
}

/// The OS UI language mapped to `zh-TW` / `en`.
fn system_locale() -> &'static str {
    map_locale(&sys_locale::get_locale().unwrap_or_default())
}

/// Process names / bundle ids of our own windows.
fn own_ids() -> Vec<String> {
    let mut ids = vec![BUNDLE_ID.to_owned(), "PasteWarden".to_owned()];
    if let Some(stem) = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
    {
        ids.push(stem);
    }
    ids
}

/// A per-process random key for [`MemoryPersistence`] (never stored).
fn ephemeral_key() -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    for chunk in key.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0x5057);
        chunk.copy_from_slice(&h.finish().to_le_bytes()[..chunk.len()]);
    }
    key
}

/// INTEGRATION POINT: replace with the `paste_warden_platform::store`
/// implementation of [`Persistence`].
fn open_persistence() -> Box<dyn Persistence> {
    Box::new(MemoryPersistence::new(ephemeral_key()))
}

/// Stops `pw-work` (which removes the hook first), then exits.
pub fn quit<R: Runtime>(app: &AppHandle<R>) {
    let (reply, rx) = sync_channel(1);
    if app.state::<WorkerTx>().send(UiCommand::Shutdown(reply)) {
        let _ = rx.recv_timeout(Duration::from_millis(SHUTDOWN_TIMEOUT_MS));
    }
    app.exit(0);
}

fn setup<R: Runtime>(app: &AppHandle<R>) -> Result<(), Box<dyn std::error::Error>> {
    let system_locale = system_locale();
    let mut persist = open_persistence();
    let boot = Boot::load(&mut *persist, env!("CARGO_PKG_VERSION"));

    let (tx, rx) = mpsc::channel::<WorkerMsg>();
    let sink_tx = tx.clone();
    // Unbounded channel: host callbacks never block.
    let sink: EventSink = Box::new(move |ev| {
        let _ = sink_tx.send(WorkerMsg::Host(ev));
    });
    let host: Arc<dyn Host> = match start_host(sink, boot.host_options()) {
        Ok(h) => Arc::from(h),
        Err(_) => Arc::new(NullHost::new()),
    };
    app.manage(WorkerTx(tx));

    let locale = match boot.settings.locale.as_str() {
        "system" => system_locale,
        l => l,
    };
    create_tray(app, paste_warden_report::localizer(locale))?;

    let onboarding = !boot.settings.onboarding_done;
    let (platform, rules) = platform();
    let cfg = WorkerConfig {
        rules,
        platform,
        own_ids: own_ids(),
        system_locale,
    };
    let ui = TauriUi::new(app.clone(), system_locale);
    let start = Instant::now();
    std::thread::Builder::new()
        .name("pw-work".into())
        .spawn(move || {
            let worker = Worker::new(
                boot,
                host,
                Box::new(ui),
                persist,
                // INTEGRATION POINT: `paste_warden_platform::nmh` bridge.
                None,
                // INTEGRATION POINT: `paste_warden_platform::probe`.
                Box::new(LocalProbe::new(0)),
                cfg,
                0,
            );
            worker.run(rx, move || {
                u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
            });
        })?;

    if onboarding {
        show_window(app, WINDOW_ONBOARDING);
    }
    Ok(())
}

/// Closing a window hides it (the app lives in the tray); closing the
/// confirmation cancels the paste.
fn on_window_event<R: Runtime>(window: &tauri::Window<R>, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        api.prevent_close();
        let _ = window.hide();
        if window.label() == WINDOW_CONFIRM {
            let (reply, _rx) = sync_channel(1);
            window
                .app_handle()
                .state::<WorkerTx>()
                .send(UiCommand::PasteChoice(PasteChoice::Cancel, reply));
        }
    }
}

/// Runs the app.
pub fn run() {
    let app = tauri::Builder::default()
        // First: a second instance exits right away (legacy #9).
        .plugin(tauri_plugin_single_instance::init(|_app, _argv, _cwd| {}))
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(crate::commands::handler())
        .setup(|app| setup(app.handle()))
        .on_window_event(on_window_event)
        .build(tauri::generate_context!())
        .expect("PasteWarden failed to start");
    app.run(|_app, event| {
        // The last window closing must not end protection; only `quit` does.
        if let RunEvent::ExitRequested {
            api, code: None, ..
        } = event
        {
            api.prevent_exit();
        }
    });
}
