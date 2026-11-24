//! Clipboard guard state machine (legacy `ClipboardGuardState`; detection-rules.md §2):
//! verdict → quarantine → restore.
//!
//! Pure logic: the app reads / writes the clipboard and shows notifications. The
//! command analyzer is injected (a closure returning a [`Verdict`]), so this module
//! does not depend on the command detector. Quarantined text lives only in this
//! object and is zeroized when dropped or replaced.
//!
//! Trust is tracked by **content**, not by "skip the next notification": one
//! clipboard write may raise zero or many notifications.

use zeroize::Zeroizing;

use crate::{Level, Verdict};

/// What the app should do after a clipboard notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardAction {
    /// Nothing (clean, empty, or the restored content the user confirmed).
    None,
    /// Warn without clearing.
    WarnSuspicious,
    /// Clear the clipboard and notify; the content is now in quarantine.
    Quarantine,
}

impl ClipboardAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ClipboardAction::None => "none",
            ClipboardAction::WarnSuspicious => "warn_suspicious",
            ClipboardAction::Quarantine => "quarantine",
        }
    }
}

/// See the module docs.
#[derive(Debug, Default)]
pub struct ClipboardGuardState {
    /// Content restored from quarantine: confirmed by the user, not blocked again
    /// while the clipboard still holds exactly this text.
    trusted: Option<Zeroizing<String>>,
    /// The (possibly truncated) text that was analyzed when quarantining. After a
    /// restore the app reads back the same prefix, so this is what trust compares.
    quarantined_key: Option<Zeroizing<String>>,
    quarantined: Option<Zeroizing<String>>,
    level: Level,
    quarantine_active: bool,
    generation: u64,
    last_verdict: Verdict,
}

impl ClipboardGuardState {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cleared content that can be restored, if any.
    pub fn quarantined(&self) -> Option<&str> {
        self.quarantined.as_deref().map(String::as_str)
    }

    /// Verdict of the current clipboard content for the entry guard
    /// (`None` once the clipboard was cleared).
    pub fn level(&self) -> Level {
        self.level
    }

    /// A malicious command was just blocked and the user has not copied other text since.
    pub fn quarantine_active(&self) -> bool {
        self.quarantine_active
    }

    /// Bumped whenever the clipboard content changes (for "warn once per content").
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The most recent analyzer verdict.
    pub fn last_verdict(&self) -> &Verdict {
        &self.last_verdict
    }

    /// A clipboard notification without text (empty, image, files — including the
    /// notification caused by our own clearing, which must keep the quarantine state).
    pub fn on_clipboard_empty(&mut self) -> ClipboardAction {
        if !self.quarantine_active {
            self.level = Level::None;
            self.last_verdict = Verdict::CLEAN;
            self.generation = self.generation.wrapping_add(1);
        }
        ClipboardAction::None
    }

    /// A clipboard notification with `text` (already cut to
    /// [`crate::limits::MAX_ANALYZED_CHARS`]).
    ///
    /// - `analyze`: the command analyzer (`command::analyze`).
    /// - `read_full`: reads the complete clipboard text when `text` was truncated;
    ///   called **only** when quarantining. `None` = unavailable (the prefix is kept).
    pub fn on_clipboard_text(
        &mut self,
        text: &str,
        analyze: impl FnOnce(&str) -> Verdict,
        read_full: impl FnOnce() -> Option<String>,
    ) -> ClipboardAction {
        self.generation = self.generation.wrapping_add(1);
        self.quarantine_active = false;

        if self.trusted.as_deref().is_some_and(|t| t.as_str() == text) {
            // Confirmed by the user but still a command: entry points warn gently.
            self.level = Level::Suspicious;
            return ClipboardAction::None;
        }
        self.trusted = None;

        self.last_verdict = analyze(text);
        match self.last_verdict.level {
            Level::Malicious => {
                let full = read_full().unwrap_or_else(|| text.to_owned());
                self.quarantined = Some(Zeroizing::new(full));
                self.quarantined_key = Some(Zeroizing::new(text.to_owned()));
                self.quarantine_active = true;
                self.level = Level::None;
                ClipboardAction::Quarantine
            }
            Level::Suspicious => {
                self.level = Level::Suspicious;
                ClipboardAction::WarnSuspicious
            }
            Level::None => {
                self.level = Level::None;
                ClipboardAction::None
            }
        }
    }

    /// Starts a restore: returns the content to write back (`None` when nothing is
    /// quarantined) and trusts it **first** (the write's notification may arrive
    /// before the write completes).
    pub fn begin_restore(&mut self) -> Option<String> {
        let q = self.quarantined.as_ref()?;
        let key = self.quarantined_key.as_ref().unwrap_or(q);
        self.trusted = Some(Zeroizing::new(key.as_str().to_owned()));
        Some(q.as_str().to_owned())
    }

    /// Result of writing the restored content. On failure the quarantine is kept
    /// (the user can retry) but no longer trusted.
    pub fn end_restore(&mut self, succeeded: bool) {
        if succeeded {
            self.quarantined = None;
            self.quarantine_active = false;
        } else {
            self.trusted = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(text: &str) -> Verdict {
        Verdict {
            level: if text.contains("evil") {
                Level::Malicious
            } else if text.contains("cmd") {
                Level::Suspicious
            } else {
                Level::None
            },
            reasons: Vec::new(),
        }
    }

    #[test]
    fn quarantine_and_restore() {
        let mut s = ClipboardGuardState::new();
        let a = s.on_clipboard_text("evil", fake, || Some("evil-full".into()));
        assert_eq!(a, ClipboardAction::Quarantine);
        assert_eq!(s.quarantined(), Some("evil-full"));
        assert!(s.quarantine_active());
        let g = s.generation();
        s.on_clipboard_empty();
        assert_eq!(s.generation(), g);
        assert!(s.quarantine_active());

        assert_eq!(s.begin_restore().as_deref(), Some("evil-full"));
        // The prefix that is read back is trusted, many times.
        for _ in 0..3 {
            let a = s.on_clipboard_text("evil", |_| unreachable!(), || unreachable!());
            assert_eq!(a, ClipboardAction::None);
            assert_eq!(s.level(), Level::Suspicious);
        }
        s.end_restore(true);
        assert_eq!(s.quarantined(), None);
        // Other text clears trust; the same command is blocked again.
        s.on_clipboard_text("hello", fake, || None);
        assert_eq!(
            s.on_clipboard_text("evil", fake, || None),
            ClipboardAction::Quarantine
        );
    }

    #[test]
    fn read_full_only_when_quarantining() {
        let mut s = ClipboardGuardState::new();
        let a = s.on_clipboard_text("cmd /c dir", fake, || panic!("must not read"));
        assert_eq!(a, ClipboardAction::WarnSuspicious);
        assert_eq!(s.begin_restore(), None);
    }

    #[test]
    fn failed_restore_keeps_quarantine_untrusted() {
        let mut s = ClipboardGuardState::new();
        s.on_clipboard_text("evil", fake, || None);
        s.begin_restore();
        s.end_restore(false);
        assert_eq!(s.quarantined(), Some("evil"));
        assert_eq!(
            s.on_clipboard_text("evil", fake, || None),
            ClipboardAction::Quarantine
        );
    }
}
