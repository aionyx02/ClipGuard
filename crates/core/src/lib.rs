//! PasteWarden detection engine.
//!
//! Pure logic: no IO, no environment, no clock (time is passed in), no OS or GUI
//! dependencies, and it builds for `wasm32-unknown-unknown`. Every public entry
//! point must be total: no panics and linear-ish time on any input.
//!
//! Start with [`Engine`]: `Engine::new(settings).analyze(text, &ctx)` returns a
//! [`Report`] with the recommended [`Action`].
//!
//! Module map (legacy C# names in parentheses; see docs/plan/phase-1.md §1.2):
//! - [`command`]: ClickFix / FileFix command detection, normalization, explanations
//!   (CommandDetector, CommandNormalizer, DownloadExecution, CommandExplainer)
//! - [`secret`]: PII and API-key detection, masking, packs, checksums
//!   (SecretDetector, SecretRules, SecretTextNormalizer, Checksums, SecretMasker, SecretPacks, PiiFormats)
//! - [`hidden`]: invisible characters, homoglyphs, trailing newline (HiddenCharDetector)
//! - [`wallet`]: wallet address parsing and swap detection (WalletAddress, WalletSwapDetector)
//! - [`policy`]: state machines and decisions used by the apps (ClipboardGuardState,
//!   ExecutionEntryGuard, NotificationThrottle, PasteGuard, RegisteredSecretStore matching, SecretRegistration)
//! - [`pastejack`]: page-written vs selected text comparison (extension pastejack.js)
//! - [`limits`]: analysis limits (ClipboardLimits)
//!
//! User-facing text is never produced here: findings carry [`Message`]s (an id plus
//! arguments) that the UI renders with Fluent (`locales/`, crate `paste-warden-i18n`).
#![forbid(unsafe_code)]

pub mod command;
pub mod context;
pub mod engine;
pub mod hidden;
pub mod limits;
pub mod msg;
pub mod pastejack;
pub mod policy;
pub mod secret;
pub mod text;
pub mod wallet;

pub use context::{Context, Platform, Source, SourceKind};
pub use engine::{Action, AiSettings, Engine, Report, Settings};
pub use msg::{Arg, Message};

/// Threat level of a piece of clipboard text (legacy `ThreatLevel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Level {
    #[default]
    None,
    /// Looks like a command that executes something; possibly legitimate. Warn only.
    Suspicious,
    /// Has scam / ClickFix traits; the clipboard should be cleared.
    Malicious,
}

impl Level {
    /// snake_case name used by the corpus and settings files.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::None => "none",
            Level::Suspicious => "suspicious",
            Level::Malicious => "malicious",
        }
    }
}

/// Verdict with reasons (legacy `Verdict`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    pub level: Level,
    pub reasons: Vec<Message>,
}

impl Verdict {
    pub const CLEAN: Verdict = Verdict {
        level: Level::None,
        reasons: Vec::new(),
    };
}
