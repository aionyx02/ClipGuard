//! Execution-entry guard (legacy `ExecutionEntryGuard`, `EntryWarningGate`;
//! detection-rules.md §4): is the foreground window a place where pasted text
//! runs (Win+R, File Explorer, a file dialog, a terminal), and should the user
//! be warned given the current clipboard state?
//!
//! Window data is plain strings (class, title, process); the platform layer
//! reads them. The Windows values live in `rules/policy/windows.json`.

use std::collections::HashSet;

use super::eq_ignore_case;
use super::windows::{EntryRules, windows_rules};
use crate::{Level, Message};

/// A place where the user can "paste and run".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryPoint {
    None,
    /// The Win+R Run dialog.
    RunDialog,
    /// File Explorer (FileFix: "paste this into the address bar").
    FileExplorer,
    /// An Open / Upload file dialog (FileFix uses its address bar too).
    FileDialog,
    /// Windows Terminal, conhost cmd / PowerShell, WezTerm…
    Terminal,
}

impl EntryPoint {
    /// snake_case name (corpus, settings, Fluent selectors).
    pub fn as_str(self) -> &'static str {
        match self {
            EntryPoint::None => "none",
            EntryPoint::RunDialog => "run_dialog",
            EntryPoint::FileExplorer => "file_explorer",
            EntryPoint::FileDialog => "file_dialog",
            EntryPoint::Terminal => "terminal",
        }
    }
}

/// A warning to show when an entry point gains focus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryWarning {
    pub entry: EntryPoint,
    /// `Suspicious` or `Malicious`.
    pub level: Level,
    pub title: Message,
    /// Body lines; the UI joins them with `\n`.
    pub body: Vec<Message>,
}

/// Strips surrounding whitespace and a trailing `.exe` (any case).
fn process_base(process: &str) -> &str {
    let p = process.trim();
    let n = p.len();
    if n >= 4 && p.is_char_boundary(n - 4) && p[n - 4..].eq_ignore_ascii_case(".exe") {
        &p[..n - 4]
    } else {
        p
    }
}

fn any_ci(list: &[String], value: &str) -> bool {
    list.iter().any(|x| eq_ignore_case(x, value))
}

/// Classifies a window with the given rules.
pub fn classify_with(rules: &EntryRules, class: &str, title: &str, process: &str) -> EntryPoint {
    let title = title.trim();
    let process = process_base(process);
    let is_shell = eq_ignore_case(process, &rules.shell_process);

    if class == rules.dialog_class {
        if is_shell && any_ci(&rules.run_dialog_titles, title) {
            return EntryPoint::RunDialog;
        }
        if any_ci(&rules.file_dialog_titles, title) {
            return EntryPoint::FileDialog;
        }
        return EntryPoint::None;
    }
    if is_shell && rules.file_explorer_classes.iter().any(|c| c == class) {
        return EntryPoint::FileExplorer;
    }
    if any_ci(&rules.terminal_classes, class) || any_ci(&rules.terminal_processes, process) {
        return EntryPoint::Terminal;
    }
    EntryPoint::None
}

/// Classifies the foreground window (legacy `ExecutionEntryGuard.Classify`).
/// Missing values are passed as `""`.
pub fn classify(class: &str, title: &str, process: &str) -> EntryPoint {
    classify_with(&windows_rules().entry, class, title, process)
}

/// Warning for an entry point given the clipboard state (legacy `Decide`).
///
/// - `level`: the current clipboard verdict ([`super::guard::ClipboardGuardState::level`]).
/// - `quarantined`: a malicious command was just blocked and the user has not copied
///   anything else since ([`super::guard::ClipboardGuardState::quarantine_active`]).
pub fn decide_for(entry: EntryPoint, level: Level, quarantined: bool) -> Option<EntryWarning> {
    if entry == EntryPoint::None {
        return None;
    }
    let where_ = entry.as_str();
    if quarantined || level == Level::Malicious {
        let first = if quarantined {
            "entry-malicious-quarantined"
        } else {
            "entry-malicious-in-clipboard"
        };
        return Some(EntryWarning {
            entry,
            level: Level::Malicious,
            title: Message::new("entry-malicious-title").arg("entry", where_),
            body: vec![Message::new(first), Message::new("entry-malicious-advice")],
        });
    }
    if level == Level::Suspicious {
        return Some(EntryWarning {
            entry,
            level: Level::Suspicious,
            title: Message::new("entry-suspicious-title").arg("entry", where_),
            body: vec![Message::new("entry-suspicious-body")],
        });
    }
    None
}

/// [`classify`] then [`decide_for`].
pub fn decide(
    class: &str,
    title: &str,
    process: &str,
    level: Level,
    quarantined: bool,
) -> Option<EntryWarning> {
    decide_for(classify(class, title, process), level, quarantined)
}

/// Upper bound on remembered windows per clipboard generation; past it the set
/// is cleared (worst case: a window is warned twice).
pub const MAX_WARNED_WINDOWS: usize = 4096;

/// Warns once per window for the same clipboard content (legacy `EntryWarningGate`).
#[derive(Debug, Clone, Default)]
pub struct EntryWarningGate {
    generation: Option<u64>,
    warned: HashSet<u64>,
    /// Short-lived dialogs already warned about (see [`Self::try_enter_entry`]).
    warned_kinds: HashSet<EntryPoint>,
}

impl EntryWarningGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` the first time `window` is seen for clipboard `generation`.
    /// A different generation forgets every window.
    pub fn try_enter(&mut self, window: u64, generation: u64) -> bool {
        if self.generation != Some(generation) {
            self.generation = Some(generation);
            self.warned.clear();
            self.warned_kinds.clear();
        }
        if self.warned.len() >= MAX_WARNED_WINDOWS && !self.warned.contains(&window) {
            self.warned.clear();
        }
        self.warned.insert(window)
    }

    /// Like [`Self::try_enter`], but the Run dialog and file dialogs count
    /// once per kind: each Win+R or Open dialog is a new window, so closing
    /// and reopening it would warn every time (manual test C5). File
    /// Explorer and terminals stay open and keep the per-window rule.
    pub fn try_enter_entry(&mut self, entry: EntryPoint, window: u64, generation: u64) -> bool {
        match entry {
            EntryPoint::RunDialog | EntryPoint::FileDialog => {
                // Resets the windows on a new generation, as `try_enter` does.
                if self.generation != Some(generation) {
                    self.try_enter(window, generation);
                }
                self.warned_kinds.insert(entry)
            }
            _ => self.try_enter(window, generation),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_entries() {
        assert_eq!(
            classify("#32770", "Run", "Explorer.EXE"),
            EntryPoint::RunDialog
        );
        assert_eq!(
            classify("#32770", " run ", "explorer"),
            EntryPoint::RunDialog
        );
        assert_eq!(classify("#32770", "執行", "notepad"), EntryPoint::None);
        assert_eq!(classify("#32770", "開啟", "chrome"), EntryPoint::FileDialog);
        assert_eq!(
            classify("CabinetWClass", "x", "explorer"),
            EntryPoint::FileExplorer
        );
        assert_eq!(classify("cabinetwclass", "x", "explorer"), EntryPoint::None);
        assert_eq!(classify("mintty", "", ""), EntryPoint::Terminal);
        assert_eq!(classify("", "", "alacritty.exe"), EntryPoint::Terminal);
        assert_eq!(classify("", "", ""), EntryPoint::None);
        // Multi-byte input near the `.exe` check must not panic.
        assert_eq!(classify("", "", "終端"), EntryPoint::None);
    }

    #[test]
    fn decides_levels() {
        let w = decide("#32770", "Run", "explorer", Level::None, true).unwrap();
        assert_eq!(w.level, Level::Malicious);
        assert_eq!(w.body[0].id, "entry-malicious-quarantined");
        let w = decide("#32770", "Run", "explorer", Level::Suspicious, false).unwrap();
        assert_eq!(w.level, Level::Suspicious);
        assert!(decide("#32770", "Run", "explorer", Level::None, false).is_none());
        assert!(decide("Notepad", "x", "notepad", Level::Malicious, true).is_none());
    }

    #[test]
    fn gate_warns_once_per_generation() {
        let mut g = EntryWarningGate::new();
        assert!(g.try_enter(1, 0));
        assert!(!g.try_enter(1, 0));
        assert!(g.try_enter(2, 0));
        assert!(g.try_enter(1, 1));
    }

    /// Manual test C5 (2026-11-28): closing Win+R and opening it again warned
    /// again, because every Run dialog is a new window.
    #[test]
    fn short_lived_dialogs_warn_once_per_kind() {
        use EntryPoint::*;
        let mut g = EntryWarningGate::new();
        assert!(g.try_enter_entry(RunDialog, 10, 0));
        assert!(!g.try_enter_entry(RunDialog, 11, 0), "Win+R opened again");
        assert!(g.try_enter_entry(FileDialog, 12, 0));
        assert!(!g.try_enter_entry(FileDialog, 13, 0));
        // Explorer and terminals stay open: once per window.
        assert!(g.try_enter_entry(Terminal, 20, 0));
        assert!(!g.try_enter_entry(Terminal, 20, 0));
        assert!(g.try_enter_entry(Terminal, 21, 0), "another terminal");
        assert!(g.try_enter_entry(FileExplorer, 30, 0));
        // A new clipboard warns again everywhere.
        assert!(g.try_enter_entry(RunDialog, 14, 1));
        assert!(g.try_enter_entry(Terminal, 20, 1));
    }
}
