//! Guardrail ③: the model's answer and its strict validation.
//!
//! The JSON schema sent in the request is generated from [`LlmOutput`] with
//! `schemars`; the answer is parsed with `serde` (`deny_unknown_fields`,
//! enums, no duplicate keys) and then checked against the length limits. Any
//! failure discards the whole answer: nothing is ever partially used.
//!
//! The `jsonschema` crate is not used: its `pattern` support pulls in
//! `fancy-regex` (a backtracking engine, banned by CLAUDE.md).

use paste_warden_core::Level;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{LLM_MAX_EXPLANATION_CHARS, LLM_MAX_TECHNIQUES};

/// The model's risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LlmLevel {
    None,
    Suspicious,
    Malicious,
}

impl From<LlmLevel> for Level {
    fn from(l: LlmLevel) -> Level {
        match l {
            LlmLevel::None => Level::None,
            LlmLevel::Suspicious => Level::Suspicious,
            LlmLevel::Malicious => Level::Malicious,
        }
    }
}

/// Technique labels the model may use. A fixed list, so the UI can localize
/// them and a model cannot smuggle free text through this field.
// Variants carry plain comments, not doc comments, so the schema stays a
// plain string enum (variant doc comments would turn it into a oneOf).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Technique {
    // Fake verification page asking the user to paste into Run / a terminal.
    Clickfix,
    // Fake file-explorer / upload dialog variant of ClickFix.
    Filefix,
    // Downloads and runs code.
    DownloadExecute,
    // Base64 / encoded command.
    EncodedCommand,
    // Carets, backticks, concatenation, char codes and similar.
    Obfuscation,
    // Hidden or minimized window.
    HiddenWindow,
    // Copied text differs from what the page showed.
    Pastejacking,
    // Invisible characters or homoglyphs.
    HiddenCharacters,
    // A wallet address that may have been swapped.
    WalletSwap,
    // Steals passwords, cookies, tokens or keys.
    CredentialTheft,
    // Installs itself to run again later.
    Persistence,
    // Turns off security tools or logging.
    DefenseEvasion,
    // Text that tries to instruct an AI agent.
    PromptInjection,
    // Pressure, urgency or impersonation.
    SocialEngineering,
    Other,
}

impl Technique {
    pub fn as_str(self) -> &'static str {
        match self {
            Technique::Clickfix => "clickfix",
            Technique::Filefix => "filefix",
            Technique::DownloadExecute => "download_execute",
            Technique::EncodedCommand => "encoded_command",
            Technique::Obfuscation => "obfuscation",
            Technique::HiddenWindow => "hidden_window",
            Technique::Pastejacking => "pastejacking",
            Technique::HiddenCharacters => "hidden_characters",
            Technique::WalletSwap => "wallet_swap",
            Technique::CredentialTheft => "credential_theft",
            Technique::Persistence => "persistence",
            Technique::DefenseEvasion => "defense_evasion",
            Technique::PromptInjection => "prompt_injection",
            Technique::SocialEngineering => "social_engineering",
            Technique::Other => "other",
        }
    }
}

/// The JSON object the model must return.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LlmOutput {
    /// Risk level of the content.
    pub level: LlmLevel,
    /// Short explanation for the user, in the requested language.
    #[schemars(length(min = 1, max = LLM_MAX_EXPLANATION_CHARS))]
    pub explanation: String,
    /// Techniques seen in the content; empty when none.
    #[schemars(length(max = LLM_MAX_TECHNIQUES))]
    pub techniques: Vec<Technique>,
}

/// Why an answer was discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputError {
    /// Not JSON, wrong types, unknown or duplicate fields, unknown enum values.
    Schema,
    /// Explanation empty or longer than [`LLM_MAX_EXPLANATION_CHARS`].
    ExplanationLength,
    /// Control characters (other than newline) or bidi overrides in the explanation.
    UnsafeCharacters,
    /// More than [`LLM_MAX_TECHNIQUES`] techniques, or a repeated one.
    Techniques,
}

impl OutputError {
    pub fn code(self) -> &'static str {
        match self {
            OutputError::Schema => "schema",
            OutputError::ExplanationLength => "explanation_length",
            OutputError::UnsafeCharacters => "unsafe_characters",
            OutputError::Techniques => "techniques",
        }
    }
}

/// Parses and validates the model's JSON text. All or nothing.
pub fn parse_output(json: &str) -> Result<LlmOutput, OutputError> {
    let out: LlmOutput = serde_json::from_str(json.trim()).map_err(|_| OutputError::Schema)?;
    let n = out.explanation.chars().count();
    if n == 0 || n > LLM_MAX_EXPLANATION_CHARS || out.explanation.trim().is_empty() {
        return Err(OutputError::ExplanationLength);
    }
    if out.explanation.chars().any(unsafe_char) {
        return Err(OutputError::UnsafeCharacters);
    }
    if out.techniques.len() > LLM_MAX_TECHNIQUES {
        return Err(OutputError::Techniques);
    }
    for (i, t) in out.techniques.iter().enumerate() {
        if out.techniques[..i].contains(t) {
            return Err(OutputError::Techniques);
        }
    }
    Ok(out)
}

/// Characters that could rewrite a terminal or reorder displayed text.
fn unsafe_char(c: char) -> bool {
    (c.is_control() && c != '\n')
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

/// The full JSON schema of [`LlmOutput`] (with length limits), inlined.
pub fn output_schema() -> serde_json::Value {
    let gen_ = schemars::generate::SchemaSettings::draft2020_12()
        .with(|s| s.inline_subschemas = true)
        .into_generator();
    let mut v = gen_.into_root_schema_for::<LlmOutput>().to_value();
    if let Some(o) = v.as_object_mut() {
        o.remove("$schema");
        o.remove("title");
    }
    v
}

/// The schema sent to providers: [`output_schema`] without the keywords that
/// structured-output modes reject (`maxLength`, `minLength`, `maxItems`).
/// Those limits are enforced locally by [`parse_output`] instead.
pub fn provider_schema() -> serde_json::Value {
    let mut v = output_schema();
    strip(&mut v);
    v
}

fn strip(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(o) => {
            for k in [
                "maxLength",
                "minLength",
                "maxItems",
                "minItems",
                "uniqueItems",
            ] {
                o.remove(k);
            }
            o.values_mut().for_each(strip);
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(strip),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_output_parses() {
        let o = parse_output(
            r#"{"level":"malicious","explanation":"Runs a downloaded script.","techniques":["download_execute","hidden_window"]}"#,
        )
        .unwrap();
        assert_eq!(o.level, LlmLevel::Malicious);
        assert_eq!(o.techniques.len(), 2);
        assert!(
            parse_output(r#" {"level":"none","explanation":"ok\nfine","techniques":[]} "#).is_ok()
        );
    }

    #[test]
    fn every_violation_discards_the_answer() {
        let long = "x".repeat(LLM_MAX_EXPLANATION_CHARS + 1);
        let exact = "中".repeat(LLM_MAX_EXPLANATION_CHARS);
        assert!(
            parse_output(&format!(
                r#"{{"level":"none","explanation":"{exact}","techniques":[]}}"#
            ))
            .is_ok()
        );
        let cases = [
            ("not json", OutputError::Schema),
            ("", OutputError::Schema),
            (
                r#"{"level":"none","explanation":"a","techniques":[],"extra":1}"#,
                OutputError::Schema,
            ),
            (r#"{"level":"none","explanation":"a"}"#, OutputError::Schema),
            (
                r#"{"level":"evil","explanation":"a","techniques":[]}"#,
                OutputError::Schema,
            ),
            (
                r#"{"level":"none","explanation":"a","techniques":["rm -rf"]}"#,
                OutputError::Schema,
            ),
            (
                r#"{"level":"none","level":"malicious","explanation":"a","techniques":[]}"#,
                OutputError::Schema,
            ),
            (
                r#"{"level":"none","explanation":7,"techniques":[]}"#,
                OutputError::Schema,
            ),
            (
                r#"{"level":"none","explanation":"a","techniques":[]} trailing"#,
                OutputError::Schema,
            ),
            (
                r#"```json {"level":"none","explanation":"a","techniques":[]}```"#,
                OutputError::Schema,
            ),
            (
                r#"{"level":"none","explanation":"","techniques":[]}"#,
                OutputError::ExplanationLength,
            ),
            (
                r#"{"level":"none","explanation":"   ","techniques":[]}"#,
                OutputError::ExplanationLength,
            ),
            (
                r#"{"level":"none","explanation":"a\u001b[2Jb","techniques":[]}"#,
                OutputError::UnsafeCharacters,
            ),
            (
                r#"{"level":"none","explanation":"a\u202eb","techniques":[]}"#,
                OutputError::UnsafeCharacters,
            ),
            (
                r#"{"level":"none","explanation":"a","techniques":["other","other"]}"#,
                OutputError::Techniques,
            ),
        ];
        for (json, want) in cases {
            assert_eq!(parse_output(json), Err(want), "{json}");
        }
        assert_eq!(
            parse_output(&format!(
                r#"{{"level":"none","explanation":"{long}","techniques":[]}}"#
            )),
            Err(OutputError::ExplanationLength)
        );
        let nine: Vec<String> = [
            "clickfix",
            "filefix",
            "download_execute",
            "encoded_command",
            "obfuscation",
            "hidden_window",
            "pastejacking",
            "hidden_characters",
            "wallet_swap",
        ]
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect();
        assert_eq!(
            parse_output(&format!(
                r#"{{"level":"none","explanation":"a","techniques":[{}]}}"#,
                nine.join(",")
            )),
            Err(OutputError::Techniques)
        );
    }

    #[test]
    fn schema_is_closed_and_matches_the_limits() {
        let s = output_schema();
        assert_eq!(s["type"], "object");
        assert_eq!(s["additionalProperties"], false);
        let mut req: Vec<&str> = s["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        req.sort_unstable();
        assert_eq!(req, ["explanation", "level", "techniques"]);
        assert_eq!(
            s["properties"]["explanation"]["maxLength"],
            LLM_MAX_EXPLANATION_CHARS
        );
        assert_eq!(
            s["properties"]["techniques"]["maxItems"],
            LLM_MAX_TECHNIQUES
        );
        assert_eq!(
            s["properties"]["level"]["enum"],
            serde_json::json!(["none", "suspicious", "malicious"])
        );
        assert!(!s.to_string().contains("$ref") && !s.to_string().contains("\"oneOf\""));
        let p = provider_schema().to_string();
        assert!(!p.contains("maxLength") && !p.contains("maxItems"));
        assert!(p.contains("\"additionalProperties\":false"));
        // Every enum value round-trips through as_str.
        for t in s["properties"]["techniques"]["items"]["enum"]
            .as_array()
            .unwrap()
        {
            let parsed: Technique = serde_json::from_value(t.clone()).unwrap();
            assert_eq!(parsed.as_str(), t.as_str().unwrap());
        }
    }
}
