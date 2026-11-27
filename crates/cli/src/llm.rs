//! `scan --llm` and `llm check` (phase-5.md §5.6).
//!
//! AI is off unless the config file exists **and** says `enabled = true`.
//! Otherwise nothing is built that could connect: the CLI prints the
//! "AI is off" notice and the Tier 1 result stands. Every failure (bad
//! config, refused by a guardrail, invalid answer) keeps the Tier 1 result
//! and prints a code, never request or response content.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use paste_warden_core::{Engine, Level, Report};
use paste_warden_i18n::Localizer;
use paste_warden_llm::{
    Client, EnabledConfig, EnabledConfigInput, Explanation, LlmConfig, LlmError, NoAudit,
    ProviderKind, Tier1Input,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::l10n::t;
use crate::report_json::{LevelJson, LlmJson};

/// `llm.toml`. Unknown keys are an error (a typo must not silently enable
/// something else).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: Option<ProviderName>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub model: String,
    /// Name of the environment variable holding the API key.
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub local: bool,
    /// Default `true`: only ask the model about suspicious or malicious commands.
    #[serde(default = "yes")]
    pub only_high_risk: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderName {
    OpenaiCompatible,
    Anthropic,
}

/// Why a config could not be used. Messages carry codes and the path only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Read,
    Parse,
    ApiKeyEnvMissing,
    Invalid(&'static str),
}

impl LoadError {
    pub fn code(&self) -> &'static str {
        match self {
            LoadError::Read => "read",
            LoadError::Parse => "parse",
            LoadError::ApiKeyEnvMissing => "api_key_env_missing",
            LoadError::Invalid(c) => c,
        }
    }
}

/// `~/.config/paste-warden/llm.toml`, or `%APPDATA%\PasteWarden\llm.toml` on Windows.
pub fn default_config_path() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("PasteWarden").join("llm.toml"))
    } else {
        std::env::var_os("HOME").map(|h| {
            PathBuf::from(h)
                .join(".config")
                .join("paste-warden")
                .join("llm.toml")
        })
    }
}

/// Parses `llm.toml` text. `env` looks up the API key variable.
pub fn parse_config(
    text: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Result<LlmConfig, LoadError> {
    let f: FileConfig = toml::from_str(text).map_err(|_| LoadError::Parse)?;
    if !f.enabled {
        return Ok(LlmConfig::Disabled);
    }
    let api_key = match f.api_key_env.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(var) => Some(Zeroizing::new(env(var).ok_or(LoadError::ApiKeyEnvMissing)?)),
    };
    let cfg = EnabledConfig::new(EnabledConfigInput {
        provider: f.provider.map(|p| match p {
            ProviderName::OpenaiCompatible => ProviderKind::OpenAiCompatible,
            ProviderName::Anthropic => ProviderKind::Anthropic,
        }),
        base_url: f.base_url,
        model: f.model,
        api_key,
        local: f.local,
        only_high_risk: f.only_high_risk,
    })
    .map_err(|e| LoadError::Invalid(e.code()))?;
    Ok(LlmConfig::Enabled(cfg))
}

/// Loads the config at `path` (or the default path). A missing file means
/// AI is off.
pub fn load(path: Option<&Path>) -> (PathBuf, Result<LlmConfig, LoadError>) {
    let Some(path) = path.map(Path::to_path_buf).or_else(default_config_path) else {
        return (PathBuf::new(), Ok(LlmConfig::Disabled));
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (path, Ok(LlmConfig::Disabled));
        }
        Err(_) => return (path, Err(LoadError::Read)),
    };
    let r = parse_config(&text, |k| std::env::var(k).ok());
    (path, r)
}

/// The client for a loaded config, or the notice to print instead.
fn client(path: Option<&Path>, l10n: &Localizer) -> Result<Client, String> {
    let (path, cfg) = load(path);
    match cfg {
        Ok(cfg) => match cfg.enabled() {
            // `enabled = false` or no file: no client, no connection.
            None => Err(t(l10n, "cli-llm-disabled", &[])),
            Some(c) => Ok(Client::with_default_transport(c)),
        },
        Err(e) => Err(t(
            l10n,
            "cli-llm-config-error",
            &[
                ("code", e.code().into()),
                ("path", path.display().to_string().into()),
            ],
        )),
    }
}

/// What `scan --llm` adds to the report.
#[derive(Debug)]
pub struct ScanLlm {
    pub json: LlmJson,
    pub level: Level,
}

fn error_notice(e: LlmError, l10n: &Localizer) -> String {
    match e {
        LlmError::RefusedSecretsPresent => t(l10n, "cli-llm-refused-secrets", &[]),
        LlmError::SkippedNotHighRisk => t(l10n, "cli-llm-skipped", &[]),
        e => t(l10n, "cli-llm-failed", &[("code", e.to_string().into())]),
    }
}

/// Runs Tier 2 for `scan --llm`. Returns `Err(notice)` (for stderr) when AI
/// is off or no validated answer was produced; the Tier 1 result then stands.
pub fn scan(
    text: &str,
    report: &Report,
    engine: &Engine,
    config: Option<&Path>,
    l10n: &Localizer,
) -> Result<ScanLlm, String> {
    let client = client(config, l10n)?;
    let pem = l10n.format(&paste_warden_core::secret::pem_body_mask_message());
    let input = Tier1Input::from_report(engine, text, report, &pem);
    match client.explain(&input, l10n.locale(), &mut NoAudit) {
        Ok(e) => Ok(ScanLlm {
            level: e.level,
            json: to_json(&e),
        }),
        Err(e) => Err(error_notice(e, l10n)),
    }
}

fn to_json(e: &Explanation) -> LlmJson {
    LlmJson {
        level: LevelJson::from(e.level),
        explanation: e.explanation.clone(),
        techniques: e.techniques.iter().map(|t| t.as_str().to_owned()).collect(),
        provider: e.provider.as_str().to_owned(),
        model: e.model.clone(),
    }
}

/// `paste-warden llm check`: sends the built-in harmless sample. Returns the
/// line to print and whether it succeeded.
pub fn check(config: Option<&Path>, l10n: &Localizer) -> (String, bool) {
    let client = match client(config, l10n) {
        Ok(c) => c,
        Err(notice) => return (notice, false),
    };
    match client.check(&Tier1Input::sample(), l10n.locale(), &mut NoAudit) {
        Ok(e) => (
            t(
                l10n,
                "cli-llm-check-ok",
                &[
                    ("provider", e.provider.as_str().into()),
                    ("model", e.model.clone().into()),
                    ("level", e.level.as_str().into()),
                ],
            ),
            true,
        ),
        Err(e) => (
            t(
                l10n,
                "cli-llm-check-failed",
                &[("code", e.to_string().into())],
            ),
            false,
        ),
    }
}

/// The human-readable Tier 2 section of `scan --llm`.
pub fn render_human(j: &LlmJson, l10n: &Localizer) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n{}",
        t(
            l10n,
            "cli-llm-heading",
            &[
                ("provider", j.provider.clone().into()),
                ("model", j.model.clone().into()),
            ],
        )
    );
    let level = match j.level {
        LevelJson::None => "cli-level-none",
        LevelJson::Suspicious => "cli-level-suspicious",
        LevelJson::Malicious => "cli-level-malicious",
    };
    let _ = writeln!(
        out,
        "  {}",
        t(
            l10n,
            "cli-llm-level",
            &[("level", t(l10n, level, &[]).into())]
        )
    );
    for line in j.explanation.lines() {
        let _ = writeln!(out, "  {line}");
    }
    if !j.techniques.is_empty() {
        let _ = writeln!(
            out,
            "  {}",
            t(
                l10n,
                "cli-llm-techniques",
                &[("list", j.techniques.join(", ").into())]
            )
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn disabled_unless_enabled_is_true() {
        for text in [
            "",
            "enabled = false\nbase_url = \"http://127.0.0.1:1/v1\"\nmodel = \"m\"",
            "model = \"m\"",
        ] {
            assert!(
                !parse_config(text, env_none).unwrap().is_enabled(),
                "{text}"
            );
        }
    }

    #[test]
    fn enabled_config_parses() {
        let c = parse_config(
            "enabled = true\nprovider = \"openai_compatible\"\nbase_url = \"http://127.0.0.1:11434/v1\"\nmodel = \"qwen3:0.6b\"\nlocal = true",
            env_none,
        )
        .unwrap()
        .enabled()
        .unwrap();
        assert!(c.is_local() && c.only_high_risk());
        let a = parse_config(
            "enabled = true\nprovider = \"anthropic\"\nmodel = \"claude-opus-5-5\"\napi_key_env = \"K\"",
            |k| (k == "K").then(|| "sk-x".to_owned()),
        )
        .unwrap()
        .enabled()
        .unwrap();
        assert_eq!(a.provider(), ProviderKind::Anthropic);
        assert!(!a.is_local());
    }

    #[test]
    fn bad_configs_are_errors_without_content() {
        assert_eq!(
            parse_config(
                "enabled = true\nmodel = \"m\"\nbase_url = \"http://127.0.0.1\"\ntypo = 1",
                env_none
            )
            .unwrap_err(),
            LoadError::Parse
        );
        assert_eq!(
            parse_config("enabled = true\nmodel = \"m\"\nbase_url = \"https://h.example.invalid\"\napi_key_env = \"NOPE\"", env_none).unwrap_err(),
            LoadError::ApiKeyEnvMissing
        );
        assert_eq!(
            parse_config(
                "enabled = true\nmodel = \"m\"\nbase_url = \"http://h.example.invalid\"",
                env_none
            )
            .unwrap_err(),
            LoadError::Invalid("insecure_scheme")
        );
        assert_eq!(
            parse_config(
                "enabled = true\nprovider = \"gpt\"\nmodel = \"m\"",
                env_none
            )
            .unwrap_err(),
            LoadError::Parse
        );
    }
}
