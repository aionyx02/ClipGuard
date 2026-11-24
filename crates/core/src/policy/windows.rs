//! Windows-specific policy data (`rules/policy/windows.json`): window classes,
//! window titles and process names. Rules are data; the engine only holds the
//! generic matching logic.

use std::sync::OnceLock;

use serde::Deserialize;

const WINDOWS_JSON: &str = include_str!("../../../../rules/policy/windows.json");

/// Execution-entry data (detection-rules.md §4).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EntryRules {
    /// Class of standard dialogs (Run, Open). Compared exactly.
    pub dialog_class: String,
    /// The shell process that owns the Run dialog and File Explorer.
    pub shell_process: String,
    pub run_dialog_titles: Vec<String>,
    pub file_dialog_titles: Vec<String>,
    /// Compared exactly (case-sensitive), like the legacy `is "CabinetWClass" or …`.
    pub file_explorer_classes: Vec<String>,
    pub terminal_classes: Vec<String>,
    pub terminal_processes: Vec<String>,
}

/// Paste-guard allowlist data (detection-rules.md §5.3).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PasteRules {
    /// Built-in allowlisted processes (password managers, Windows credential UI).
    pub allowed_apps: Vec<String>,
    /// Window classes allowed from any process. Compared exactly.
    pub allowed_window_classes: Vec<String>,
}

/// Parsed `rules/policy/windows.json`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WindowsRules {
    pub entry: EntryRules,
    pub paste: PasteRules,
}

/// The embedded Windows policy data. A file that fails to parse (caught by the
/// unit tests) yields empty lists: nothing is recognized, nothing is allowlisted.
pub fn windows_rules() -> &'static WindowsRules {
    static RULES: OnceLock<WindowsRules> = OnceLock::new();
    RULES.get_or_init(|| serde_json::from_str(WINDOWS_JSON).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_parse() {
        let parsed: Result<WindowsRules, _> = serde_json::from_str(WINDOWS_JSON);
        let r = parsed.expect("rules/policy/windows.json must parse");
        assert_eq!(r.entry.dialog_class, "#32770");
        assert!(!r.entry.terminal_classes.is_empty());
        assert!(r.paste.allowed_apps.iter().any(|a| a == "KeePassXC"));
    }
}
