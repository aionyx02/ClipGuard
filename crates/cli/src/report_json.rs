//! The shared Report JSON — **reference implementation of docs/plan/phase-2.md §2.2**.
//!
//! `paste-warden scan --json`, the MCP `analyze` tool and the agent hooks all
//! serialize a [`paste_warden_core::Report`] through [`ReportJson::new`]. The
//! WASM binding (`crates/wasm`, `@paste-warden/core`) produces the same shape;
//! field names, enum spellings and the UTF-16 span convention here are the
//! contract. Change §2.2 first, then this module and the WASM side together.
//!
//! Invariants (P4):
//! - no secret plaintext: secrets carry only `masked` and a UTF-16 span;
//!   `trace[].preview` is already masked by the engine;
//! - no wallet address text, only currency and span;
//! - every `text` is rendered with `paste-warden-i18n` in the requested locale.

use paste_warden_core::secret::SecretMatch;
use paste_warden_core::{Action, Level, Message, Report, Verdict};
use paste_warden_i18n::Localizer;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Version of this JSON shape (`schema` field).
pub const SCHEMA_VERSION: u32 = 1;

/// §2.2 top level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReportJson {
    /// Always [`SCHEMA_VERSION`].
    pub schema: u32,
    /// Recommended action.
    pub action: ActionJson,
    /// Only a prefix (1 Mi chars) of the text was analyzed.
    pub truncated: bool,
    pub command: CommandJson,
    pub secrets: Vec<SecretJson>,
    pub hidden: HiddenJson,
    pub wallets: Vec<WalletJson>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionJson {
    Allow,
    Warn,
    Quarantine,
}

impl From<Action> for ActionJson {
    fn from(a: Action) -> Self {
        match a {
            Action::Allow => ActionJson::Allow,
            Action::Warn => ActionJson::Warn,
            Action::Quarantine => ActionJson::Quarantine,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LevelJson {
    None,
    Suspicious,
    Malicious,
}

impl From<Level> for LevelJson {
    fn from(l: Level) -> Self {
        match l {
            Level::None => LevelJson::None,
            Level::Suspicious => LevelJson::Suspicious,
            Level::Malicious => LevelJson::Malicious,
        }
    }
}

/// A rendered message: Fluent id plus the text in the requested locale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReasonJson {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommandJson {
    pub level: LevelJson,
    /// 0–100 (docs/spec/detection-rules.md §3.6).
    pub risk_score: u8,
    pub reasons: Vec<ReasonJson>,
    pub trace: Vec<TraceStepJson>,
    /// Download hosts, lowercase.
    pub hosts: Vec<String>,
}

/// One deobfuscation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceStepJson {
    /// Step kind (`caret`, `backtick`, `concat`, `base64`, …; `StepKind::as_str`).
    pub kind: String,
    /// What the step did, localized.
    pub text: String,
    /// Text after the step around the change; secrets masked. Untrusted.
    pub preview: String,
}

/// One detected secret. Never contains the plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretJson {
    /// `national_id`, `api_key`, … (`SecretKind::as_str`).
    pub kind: String,
    /// Rule id (`tw-national-id`, `gitleaks.…`); empty for registered secrets.
    pub rule_id: String,
    /// Localized label.
    pub label: String,
    /// Masked value (`A12****789`).
    pub masked: String,
    /// `[start, end)` in UTF-16 code units of the input text.
    pub span_utf16: [usize; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HiddenJson {
    pub level: LevelJson,
    pub reasons: Vec<ReasonJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WalletJson {
    /// `btc`, `eth`, … (`Cryptocurrency::as_str`).
    pub currency: String,
    /// `[start, end)` in UTF-16 code units of the input text.
    pub span_utf16: [usize; 2],
}

impl ReportJson {
    /// Serializes `report` (from `Engine::analyze(text, …)`) with messages
    /// rendered by `l10n`. `text` is only used to convert byte offsets to UTF-16.
    pub fn new(report: &Report, text: &str, l10n: &Localizer) -> ReportJson {
        let mut offsets = Utf16Offsets::new(text);
        let command = &report.command;
        ReportJson {
            schema: SCHEMA_VERSION,
            action: report.action.into(),
            truncated: report.truncated,
            command: CommandJson {
                level: command.verdict.level.into(),
                risk_score: command.risk_score,
                reasons: reasons(&command.verdict, l10n),
                trace: command
                    .trace
                    .iter()
                    .map(|s| TraceStepJson {
                        kind: s.kind.as_str().to_owned(),
                        text: l10n.format(&s.message),
                        preview: s.preview.clone(),
                    })
                    .collect(),
                hosts: command.hosts.clone(),
            },
            secrets: secrets(&report.secrets, &mut offsets, l10n),
            hidden: HiddenJson {
                level: report.hidden.level.into(),
                reasons: reasons(&report.hidden, l10n),
            },
            wallets: report
                .wallets
                .iter()
                .map(|w| WalletJson {
                    currency: w.currency.as_str().to_owned(),
                    span_utf16: offsets.span(w.start, w.start + w.len),
                })
                .collect(),
        }
    }
}

/// Renders secret matches found in `text` (shared with the MCP `scan_secrets` tool).
pub fn secrets_json(matches: &[SecretMatch], text: &str, l10n: &Localizer) -> Vec<SecretJson> {
    secrets(matches, &mut Utf16Offsets::new(text), l10n)
}

fn secrets(
    matches: &[SecretMatch],
    offsets: &mut Utf16Offsets<'_>,
    l10n: &Localizer,
) -> Vec<SecretJson> {
    matches
        .iter()
        .map(|m| SecretJson {
            kind: m.kind.as_str().to_owned(),
            rule_id: m.rule_id.clone(),
            label: l10n.format(&m.label),
            masked: m.masked.clone(),
            span_utf16: offsets.span(m.span.start, m.span.end),
        })
        .collect()
}

/// Renders a verdict's reasons.
pub fn reasons(v: &Verdict, l10n: &Localizer) -> Vec<ReasonJson> {
    v.reasons.iter().map(|m| reason(m, l10n)).collect()
}

pub fn reason(m: &Message, l10n: &Localizer) -> ReasonJson {
    ReasonJson {
        id: m.id.to_string(),
        text: l10n.format(m),
    }
}

/// Converts UTF-8 byte offsets to UTF-16 offsets, incrementally when offsets
/// increase (linear over a report instead of quadratic).
struct Utf16Offsets<'a> {
    text: &'a str,
    byte: usize,
    utf16: usize,
}

impl<'a> Utf16Offsets<'a> {
    fn new(text: &'a str) -> Self {
        Utf16Offsets {
            text,
            byte: 0,
            utf16: 0,
        }
    }

    fn at(&mut self, byte: usize) -> usize {
        let mut byte = byte.min(self.text.len());
        while !self.text.is_char_boundary(byte) {
            byte -= 1;
        }
        if byte < self.byte {
            self.byte = 0;
            self.utf16 = 0;
        }
        self.utf16 += self.text[self.byte..byte]
            .chars()
            .map(char::len_utf16)
            .sum::<usize>();
        self.byte = byte;
        self.utf16
    }

    /// `[start, length]` in UTF-16 code units (phase-2.md §2.2, same as the corpus).
    fn span(&mut self, start: usize, end: usize) -> [usize; 2] {
        let s = self.at(start);
        let e = self.at(end);
        [s, e.saturating_sub(s)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paste_warden_core::{Context, Engine};

    #[test]
    fn utf16_offsets_handle_any_order() {
        let text = "a🔑中b";
        let mut o = Utf16Offsets::new(text);
        assert_eq!(o.at(5), 3);
        assert_eq!(o.at(1), 1);
        assert_eq!(o.at(text.len()), 5);
        assert_eq!(o.at(99), 5);
    }

    #[test]
    fn report_has_the_spec_shape_and_no_plaintext() {
        let text = "🔑 身分證 A123456789";
        let report = Engine::default().analyze(text, &Context::default());
        let json = ReportJson::new(&report, text, &Localizer::new("en"));
        let v = serde_json::to_value(&json).unwrap();
        for key in [
            "schema",
            "action",
            "truncated",
            "command",
            "secrets",
            "hidden",
            "wallets",
        ] {
            assert!(v.get(key).is_some(), "{key}");
        }
        assert_eq!(v["action"], "warn");
        assert_eq!(v["command"]["level"], "none");
        let s = &v["secrets"][0];
        assert_eq!(s["kind"], "national_id");
        assert_eq!(s["span_utf16"], serde_json::json!([7, 10])); // [start, length]
        assert!(!v.to_string().contains("A123456789"));
    }
}
