//! Tauri application set-up (phase-4.md §4.2): single instance, tray,
//! windows, the `pw-work` thread, the platform host, the store and the
//! Native Messaging bridge.
//!
//! The desktop app contacts no network endpoint: there is no HTTP plugin, the
//! CSP only allows the IPC origin, and AI features (Phase 5) are off. The
//! Native Messaging IPC is a per-user Unix socket / named pipe, not a port.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use paste_warden_core::Platform;
use paste_warden_core::policy::registered::KEY_LENGTH;
use paste_warden_core::policy::windows::WindowsRules;
use paste_warden_i18n::locale::map_locale;
use paste_warden_platform::host::{EventSink, Host};
use paste_warden_platform::nmh::{self, IpcError, IpcServer};
use paste_warden_platform::status::ProtectionStatus;
use paste_warden_platform::store;
use tauri::{AppHandle, Manager, RunEvent, Runtime, WindowEvent};

use crate::bridge::{NmhBridge, SharedNmh};
use crate::diag;
use crate::host_impl::{NullHost, start_host};
use crate::persist::{MemoryPersistence, Persistence, StorePersistence};
use crate::ui::{TauriUi, WINDOW_CONFIRM, WINDOW_ONBOARDING, WorkerTx, create_tray, show_window};
use crate::worker::{Boot, PasteChoice, UiCommand, Worker, WorkerConfig, WorkerMsg};

/// How long quitting waits for `pw-work` to remove the hook.
pub const SHUTDOWN_TIMEOUT_MS: u64 = 2_000;
/// macOS bundle id (also our `own_ids` entry there).
pub const BUNDLE_ID: &str = "org.pastewarden.app";
/// The Native Messaging host shipped next to the app executable
/// (`bundle.externalBin` in `tauri.release.conf.json`).
pub const NMH_BINARY: &str = if cfg!(windows) {
    "paste-warden-nmh.exe"
} else {
    "paste-warden-nmh"
};

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

/// A per-process random key for the [`MemoryPersistence`] fallback (never
/// stored).
fn ephemeral_key() -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    for chunk in key.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0x5057);
        chunk.copy_from_slice(&h.finish().to_le_bytes()[..chunk.len()]);
    }
    key
}

/// The platform store (data directory + OS keyring). Without a data
/// directory the app still protects, on in-memory settings, and says so.
fn open_persistence() -> (Box<dyn Persistence>, Option<crate::persist::PersistError>) {
    match StorePersistence::open_default() {
        Ok(p) => (Box::new(p), None),
        Err(e) => {
            diag!("store unavailable ({}), using memory", e.message_id());
            (Box::new(MemoryPersistence::new(ephemeral_key())), Some(e))
        }
    }
}

/// One line per area: `watch=active write=active foreground=degraded(...)`.
fn status_line(s: &ProtectionStatus) -> String {
    s.areas()
        .iter()
        .map(|(name, c)| match c.reason() {
            Some(r) => format!("{name}={}({})", c.state_id(), r.id()),
            None => format!("{name}={}", c.state_id()),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Where the browser should start `paste-warden-nmh`: the binary next to
/// the app executable. An AppImage is mounted at a new path on every run,
/// so there the binary is copied to the data directory first.
fn nmh_host_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bundled = exe.parent()?.join(NMH_BINARY);
    if !bundled.is_file() {
        return None;
    }
    if cfg!(target_os = "linux") && std::env::var_os("APPIMAGE").is_some() {
        let dir = store::data_dir().ok()?;
        return copy_executable(&bundled, &dir.join(NMH_BINARY)).ok();
    }
    Some(bundled)
}

/// Copies `from` to `to` (temp file + rename, mode 0755) unless identical.
fn copy_executable(from: &Path, to: &Path) -> std::io::Result<PathBuf> {
    let src = std::fs::read(from)?;
    if std::fs::read(to).is_ok_and(|old| old == src) {
        return Ok(to.to_path_buf());
    }
    if let Some(dir) = to.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = to.with_extension("tmp");
    std::fs::write(&tmp, &src)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, to)?;
    Ok(to.to_path_buf())
}

/// Registers `paste-warden-nmh` with the browsers (idempotent; user level
/// only: manifests under the browsers' config directories, `HKCU` keys on
/// Windows). Runs off the main thread. Debug builds skip it, so a dev run
/// never points the browsers at `target/debug`.
fn install_nmh() {
    if cfg!(debug_assertions) {
        diag!("debug build: native messaging host not registered");
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("pw-nmh-install".into())
        .spawn(|| match nmh_host_path() {
            None => diag!("{NMH_BINARY} is not next to the app; native messaging not installed"),
            Some(path) => match nmh::install::install(&path) {
                Ok(browsers) => diag!(
                    "native messaging host registered for {} browsers",
                    browsers.len()
                ),
                Err(e) => diag!(
                    "native messaging install failed: {}",
                    install_error_kind(&e)
                ),
            },
        });
    if spawned.is_err() {
        diag!("native messaging install thread did not start");
    }
}

/// The error without paths.
fn install_error_kind(e: &nmh::install::InstallError) -> String {
    use nmh::install::InstallError;
    match e {
        InstallError::RelativeHostPath => "relative-host-path".into(),
        InstallError::NoHome => "no-home".into(),
        InstallError::Unsupported => "unsupported".into(),
        InstallError::Io(e) => format!("io {:?}", e.kind()),
    }
}

/// Keeps the IPC server alive until the process ends (dropping it removes the
/// socket / pipe).
struct NmhServer(#[allow(dead_code)] Mutex<Option<IpcServer>>);

/// Starts the Native Messaging IPC server. Another instance already serving
/// (or no endpoint) only disables the bridge; the app keeps protecting.
fn start_nmh<R: Runtime>(app: &AppHandle<R>, shared: &SharedNmh) {
    match nmh::serve(Arc::new(shared.clone())) {
        Ok(server) => {
            diag!("native messaging bridge listening");
            app.manage(NmhServer(Mutex::new(Some(server))));
        }
        Err(IpcError::AlreadyRunning) => {
            diag!("native messaging bridge already served by another instance");
        }
        Err(e) => diag!("native messaging bridge not started: {e}"),
    }
}

#[cfg(target_os = "macos")]
thread_local! {
    /// The NSWorkspace activation observer; must live (and be dropped) on
    /// the main thread for the app's lifetime.
    static FOREGROUND_OBSERVER: std::cell::RefCell<
        Option<paste_warden_platform::macos::foreground::ForegroundObserver>,
    > = const { std::cell::RefCell::new(None) };
}

/// macOS: subscribe to app activations on the main thread (setup runs
/// there), feeding the foreground history the host reads.
fn register_foreground_observer() {
    #[cfg(target_os = "macos")]
    {
        match objc2::MainThreadMarker::new() {
            Some(mtm) => {
                let obs = paste_warden_platform::macos::host::register_foreground_observer(mtm);
                FOREGROUND_OBSERVER.with(|o| *o.borrow_mut() = Some(obs));
            }
            None => diag!("setup is not on the main thread; no foreground observer"),
        }
    }
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
    diag!("starting {}", env!("CARGO_PKG_VERSION"));
    let system_locale = system_locale();
    let (mut persist, store_problem) = open_persistence();
    let mut boot = Boot::load(&mut *persist, env!("CARGO_PKG_VERSION"));
    boot.problems.extend(store_problem);
    // Windows only (`legacy_data_dir` is None elsewhere): delete the C#
    // app's files and ask once to register again (§4.5).
    if let Some(dir) = store::legacy_data_dir() {
        boot.legacy_cleaned = store::cleanup_legacy(&dir);
    }

    register_foreground_observer();

    let (tx, rx) = mpsc::channel::<WorkerMsg>();
    let sink_tx = tx.clone();
    // Unbounded channel: host callbacks never block.
    let sink: EventSink = Box::new(move |ev| {
        let _ = sink_tx.send(WorkerMsg::Host(ev));
    });
    let host: Arc<dyn Host> = match start_host(sink, boot.host_options()) {
        Ok(h) => Arc::from(h),
        Err(e) => {
            diag!("platform host failed to start ({e:?})");
            Arc::new(NullHost::new())
        }
    };
    diag!("host started: {}", status_line(&host.status()));
    app.manage(WorkerTx(tx));

    let nmh_shared = SharedNmh::new(env!("CARGO_PKG_VERSION"));
    start_nmh(app, &nmh_shared);
    install_nmh();

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
            // `Worker::new` publishes the first state; until then the bridge
            // answers `policy.get` with the defaults.
            let nmh: Box<dyn NmhBridge> = Box::new(nmh_shared);
            let worker = Worker::new(boot, host, Box::new(ui), persist, Some(nmh), cfg, 0);
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

#[cfg(test)]
mod tests {
    use paste_warden_platform::status::{Capability, Reason};

    use super::*;

    #[test]
    fn status_line_has_ids_only() {
        let s = ProtectionStatus {
            intercept: Capability::Unavailable(Reason::HostFailed),
            ..Default::default()
        };
        assert_eq!(
            status_line(&s),
            "watch=active write=active foreground=active intercept=unavailable(host-failed)"
        );
    }

    #[test]
    fn copy_executable_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let from = dir.path().join("a");
        std::fs::write(&from, b"bin").unwrap();
        let to = dir.path().join("sub").join(NMH_BINARY);
        assert_eq!(copy_executable(&from, &to).unwrap(), to);
        assert_eq!(copy_executable(&from, &to).unwrap(), to);
        assert_eq!(std::fs::read(&to).unwrap(), b"bin");
    }
}
