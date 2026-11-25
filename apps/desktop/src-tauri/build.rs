//! Tauri build script. Listing the app commands makes Tauri generate one
//! `allow-<command>` permission per command, so each window's capability
//! (`capabilities/*.json`) can allow only what it needs (phase-4.md §4.3).

const COMMANDS: &[&str] = &[
    "get_protection_status",
    "get_settings",
    "set_locale",
    "set_theme",
    "set_paste_guard",
    "allowlist_add",
    "allowlist_remove",
    "complete_onboarding",
    "register_secret",
    "list_secrets",
    "remove_secret",
    "get_pending_paste",
    "paste_choice",
    "restore",
    "quit",
    "open_accessibility_settings",
    // Registered only in debug builds (§4.8.4 item 6).
    "debug_drop_hook",
    "debug_restore_hook",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build script");
}
