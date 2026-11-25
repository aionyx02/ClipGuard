//! Tauri commands (phase-4.md §4.3). Every argument is re-validated here or by
//! the worker with core's checks; errors carry only a Fluent id and a field.
//! Which window may call which command is decided by `capabilities/*.json`.

use std::sync::mpsc::sync_channel;
use std::time::Duration;

use tauri::{AppHandle, Manager, Runtime, State};
use zeroize::Zeroizing;

use crate::model::{
    CmdResult, CommandError, ConfirmPayload, LocalePref, RegisteredId, SecretInfo, SettingsPayload,
    StatusPayload, ThemePref,
};
use crate::ui::{WINDOW_ONBOARDING, WorkerTx};
use crate::worker::{PasteChoice, Reply, UiCommand};

/// How long a command waits for `pw-work`.
pub const COMMAND_TIMEOUT_MS: u64 = 5_000;
/// Longest string argument accepted before it reaches the worker (secrets,
/// labels and app names are far shorter; this only bounds memory).
pub const MAX_ARG_CHARS: usize = 4_096;

/// macOS "Privacy & Security → Accessibility" (§4.9.1).
pub const ACCESSIBILITY_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";

fn stopped() -> CommandError {
    CommandError::new("ui-desktop-error-worker-stopped")
}

fn invalid(field: &'static str) -> CommandError {
    CommandError::new("ui-desktop-error-invalid-argument").field(field)
}

fn bounded(s: &str, field: &'static str) -> CmdResult<()> {
    if s.len() > MAX_ARG_CHARS * 4 || s.chars().count() > MAX_ARG_CHARS {
        Err(invalid(field))
    } else {
        Ok(())
    }
}

/// Sends a command to `pw-work` and waits for the reply off the async
/// runtime's worker threads.
async fn ask<T: Send + 'static>(
    tx: &WorkerTx,
    make: impl FnOnce(Reply<T>) -> UiCommand,
) -> CmdResult<T> {
    let (reply, rx) = sync_channel(1);
    if !tx.send(make(reply)) {
        return Err(stopped());
    }
    tauri::async_runtime::spawn_blocking(move || {
        rx.recv_timeout(Duration::from_millis(COMMAND_TIMEOUT_MS))
    })
    .await
    .map_err(|_| stopped())?
    .map_err(|_| stopped())
}

#[tauri::command]
pub async fn get_protection_status(tx: State<'_, WorkerTx>) -> CmdResult<StatusPayload> {
    ask(&tx, UiCommand::GetStatus).await
}

#[tauri::command]
pub async fn get_settings(tx: State<'_, WorkerTx>) -> CmdResult<SettingsPayload> {
    ask(&tx, UiCommand::GetSettings).await
}

#[tauri::command]
pub async fn set_locale(tx: State<'_, WorkerTx>, locale: String) -> CmdResult<()> {
    let l = LocalePref::parse(&locale).ok_or_else(|| invalid("locale"))?;
    ask(&tx, |r| UiCommand::SetLocale(l, r)).await?
}

#[tauri::command]
pub async fn set_theme(tx: State<'_, WorkerTx>, theme: String) -> CmdResult<()> {
    let t = ThemePref::parse(&theme).ok_or_else(|| invalid("theme"))?;
    ask(&tx, |r| UiCommand::SetTheme(t, r)).await?
}

#[tauri::command]
pub async fn set_paste_guard(
    tx: State<'_, WorkerTx>,
    registered: bool,
    detected: bool,
) -> CmdResult<()> {
    ask(&tx, |reply| UiCommand::SetPasteGuard {
        registered,
        detected,
        reply,
    })
    .await?
}

#[tauri::command]
pub async fn allowlist_add(tx: State<'_, WorkerTx>, name: String) -> CmdResult<()> {
    bounded(&name, "name")?;
    ask(&tx, |r| UiCommand::AllowlistAdd(name, r)).await?
}

#[tauri::command]
pub async fn allowlist_remove(tx: State<'_, WorkerTx>, name: String) -> CmdResult<()> {
    bounded(&name, "name")?;
    ask(&tx, |r| UiCommand::AllowlistRemove(name, r)).await?
}

#[tauri::command]
pub async fn complete_onboarding<R: Runtime>(
    app: AppHandle<R>,
    tx: State<'_, WorkerTx>,
) -> CmdResult<()> {
    ask(&tx, UiCommand::CompleteOnboarding).await??;
    if let Some(w) = app.get_webview_window(WINDOW_ONBOARDING) {
        let _ = w.hide();
    }
    Ok(())
}

#[tauri::command]
pub async fn register_secret(
    tx: State<'_, WorkerTx>,
    secret: String,
    confirm: String,
    label: String,
) -> CmdResult<RegisteredId> {
    // Zeroize the inputs as soon as they are ours (P3).
    let secret = Zeroizing::new(secret);
    let confirm = Zeroizing::new(confirm);
    bounded(&secret, "secret")?;
    bounded(&confirm, "confirm")?;
    bounded(&label, "label")?;
    let now_wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    ask(&tx, |reply| UiCommand::RegisterSecret {
        secret,
        confirm,
        label,
        now_wall_ms,
        reply,
    })
    .await?
}

#[tauri::command]
pub async fn list_secrets(tx: State<'_, WorkerTx>) -> CmdResult<Vec<SecretInfo>> {
    ask(&tx, UiCommand::ListSecrets).await?
}

#[tauri::command]
pub async fn remove_secret(tx: State<'_, WorkerTx>, id: String) -> CmdResult<()> {
    if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("id"));
    }
    ask(&tx, |r| UiCommand::RemoveSecret(id, r)).await?
}

/// Addition to §4.3: the confirm window asks on mount (it may load after
/// the `paste-confirm` event was emitted).
#[tauri::command]
pub async fn get_pending_paste(tx: State<'_, WorkerTx>) -> CmdResult<Option<ConfirmPayload>> {
    ask(&tx, UiCommand::GetPendingPaste).await
}

#[tauri::command]
pub async fn paste_choice(tx: State<'_, WorkerTx>, choice: String) -> CmdResult<()> {
    let c = PasteChoice::parse(&choice).ok_or_else(|| invalid("choice"))?;
    ask(&tx, |r| UiCommand::PasteChoice(c, r)).await?
}

#[tauri::command]
pub async fn restore(tx: State<'_, WorkerTx>) -> CmdResult<()> {
    ask(&tx, UiCommand::Restore).await?
}

#[tauri::command]
pub fn quit<R: Runtime>(app: AppHandle<R>) {
    crate::app::quit(&app);
}

#[tauri::command]
pub fn open_accessibility_settings() -> CmdResult<()> {
    #[cfg(target_os = "macos")]
    {
        // A system URL scheme handled by System Settings; no network.
        std::process::Command::new("/usr/bin/open")
            .arg(ACCESSIBILITY_SETTINGS_URL)
            .spawn()
            .map(|_| ())
            .map_err(|_| CommandError::new("ui-desktop-error-open-settings-failed"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CommandError::new("ui-desktop-error-unsupported"))
    }
}

#[cfg(debug_assertions)]
#[tauri::command]
pub fn debug_drop_hook(tx: State<'_, WorkerTx>) {
    tx.send(UiCommand::DebugDropHook);
}

#[cfg(debug_assertions)]
#[tauri::command]
pub fn debug_restore_hook(tx: State<'_, WorkerTx>) {
    tx.send(UiCommand::DebugRestoreHook);
}

/// The invoke handler (debug builds add the §4.8.4 debug commands).
#[cfg(debug_assertions)]
pub fn handler<R: Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        get_protection_status,
        get_settings,
        set_locale,
        set_theme,
        set_paste_guard,
        allowlist_add,
        allowlist_remove,
        complete_onboarding,
        register_secret,
        list_secrets,
        remove_secret,
        get_pending_paste,
        paste_choice,
        restore,
        quit,
        open_accessibility_settings,
        debug_drop_hook,
        debug_restore_hook,
    ]
}

#[cfg(not(debug_assertions))]
pub fn handler<R: Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        get_protection_status,
        get_settings,
        set_locale,
        set_theme,
        set_paste_guard,
        allowlist_add,
        allowlist_remove,
        complete_onboarding,
        register_secret,
        list_secrets,
        remove_secret,
        get_pending_paste,
        paste_choice,
        restore,
        quit,
        open_accessibility_settings,
    ]
}
