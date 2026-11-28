//! macOS policy data (`rules/policy/macos.json`, phase-4.md §4.9.1): the same
//! layout as `windows.json`, with bundle ids where Windows has window classes
//! and process names. The platform layer passes the frontmost app's bundle id
//! as both `class` and `process`.

use std::sync::OnceLock;

use super::windows::WindowsRules;

const MACOS_JSON: &str = include_str!("../../../../rules/policy/macos.json");

/// The embedded macOS policy data, parsed into the shared rules layout. A file
/// that fails to parse (caught by the unit tests) yields empty lists: nothing
/// is recognized, nothing is allowlisted.
pub fn macos_rules() -> &'static WindowsRules {
    static RULES: OnceLock<WindowsRules> = OnceLock::new();
    RULES.get_or_init(|| serde_json::from_str(MACOS_JSON).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::entry::{EntryPoint, classify_with};
    use crate::policy::paste::{PasteGuardSettings, PasteTarget, is_allowed_with};

    #[test]
    fn embedded_rules_parse() {
        let parsed: Result<WindowsRules, _> = serde_json::from_str(MACOS_JSON);
        let r = parsed.expect("rules/policy/macos.json must parse");
        assert!(!r.entry.terminal_processes.is_empty());
        assert!(!r.paste.allowed_apps.is_empty());
    }

    #[test]
    fn terminals_classify_and_others_do_not() {
        let e = &macos_rules().entry;
        let term = "com.apple.Terminal";
        assert_eq!(classify_with(e, term, "", term), EntryPoint::Terminal);
        // Bundle ids compare case-insensitively.
        let ghostty = "COM.MITCHELLH.GHOSTTY";
        assert_eq!(classify_with(e, ghostty, "", ghostty), EntryPoint::Terminal);
        let notes = "com.apple.Notes";
        assert_eq!(classify_with(e, notes, "", notes), EntryPoint::None);
    }

    #[test]
    fn password_managers_are_allowlisted_by_bundle_id() {
        let rules = &macos_rules().paste;
        let settings = PasteGuardSettings::default();
        let target = |id| PasteTarget {
            process: id,
            class: id,
            own: false,
        };
        assert!(is_allowed_with(
            rules,
            &target("com.apple.Passwords"),
            &settings
        ));
        assert!(!is_allowed_with(
            rules,
            &target("com.apple.Notes"),
            &settings
        ));
        // Windows names do not leak into the macOS allowlist.
        assert!(!is_allowed_with(rules, &target("KeePassXC"), &settings));
    }
}
