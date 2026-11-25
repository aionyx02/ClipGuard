//! Linux policy data (`rules/policy/linux.json`, phase-4.md §4.9.2): the same
//! layout as `windows.json`, with X11 `WM_CLASS` classes / Wayland `app_id`s
//! where Windows has window classes, and `/proc/<pid>/comm` names where it
//! has process names.

use std::sync::OnceLock;

use super::windows::WindowsRules;

const LINUX_JSON: &str = include_str!("../../../../rules/policy/linux.json");

/// The embedded Linux policy data, parsed into the shared rules layout. A file
/// that fails to parse (caught by the unit tests) yields empty lists: nothing
/// is recognized, nothing is allowlisted.
pub fn linux_rules() -> &'static WindowsRules {
    static RULES: OnceLock<WindowsRules> = OnceLock::new();
    RULES.get_or_init(|| serde_json::from_str(LINUX_JSON).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::entry::{EntryPoint, classify_with};
    use crate::policy::paste::{PasteGuardSettings, PasteTarget, is_allowed_with};

    #[test]
    fn embedded_rules_parse() {
        let parsed: Result<WindowsRules, _> = serde_json::from_str(LINUX_JSON);
        let r = parsed.expect("rules/policy/linux.json must parse");
        assert!(!r.entry.terminal_classes.is_empty());
        assert!(!r.entry.terminal_processes.is_empty());
        assert!(!r.paste.allowed_apps.is_empty());
    }

    #[test]
    fn terminals_classify_by_class_or_process() {
        let e = &linux_rules().entry;
        // X11: WM_CLASS class + comm.
        assert_eq!(classify_with(e, "XTerm", "", "xterm"), EntryPoint::Terminal);
        assert_eq!(
            classify_with(e, "Gnome-terminal", "", "gnome-terminal-"),
            EntryPoint::Terminal
        );
        // Class alone, any case (comm unknown: the pid was gone).
        assert_eq!(classify_with(e, "KITTY", "", ""), EntryPoint::Terminal);
        // Wayland: app_id passed as both.
        let id = "org.gnome.Console";
        assert_eq!(classify_with(e, id, "", id), EntryPoint::Terminal);
        assert_eq!(classify_with(e, "foot", "", "foot"), EntryPoint::Terminal);
        // Process alone.
        assert_eq!(
            classify_with(e, "", "", "wezterm-gui"),
            EntryPoint::Terminal
        );
    }

    #[test]
    fn other_windows_are_not_entries() {
        let e = &linux_rules().entry;
        for (class, process) in [
            ("firefox", "firefox"),
            ("org.gnome.Nautilus", "nautilus"),
            ("org.kde.dolphin", "dolphin"),
            ("", ""),
        ] {
            assert_eq!(
                classify_with(e, class, "", process),
                EntryPoint::None,
                "{class}"
            );
        }
        // The sentinels never match a real (or missing) window.
        assert_eq!(classify_with(e, "", "Run", ""), EntryPoint::None);
    }

    #[test]
    fn password_managers_are_allowlisted() {
        let rules = &linux_rules().paste;
        let settings = PasteGuardSettings::default();
        let allowed = |process: &str, class: &str| {
            is_allowed_with(
                rules,
                &PasteTarget {
                    process,
                    class,
                    own: false,
                },
                &settings,
            )
        };
        // KeePassXC on X11 (S5: comm keepassxc, WM_CLASS keepassxc/KeePassXC).
        assert!(allowed("keepassxc", "KeePassXC"));
        // KeePassXC on Wayland (app_id as both).
        let id = "org.keepassxc.KeePassXC";
        assert!(allowed(id, id));
        assert!(allowed("", "Bitwarden"), "class alone, exact");
        assert!(!allowed("", "bitwarden"), "window classes compare exactly");
        assert!(!allowed("firefox", "firefox"));
        assert!(!allowed("", ""));
        // macOS bundle ids do not leak into the Linux allowlist.
        assert!(!allowed("com.apple.Passwords", ""));
    }
}
