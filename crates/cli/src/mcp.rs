//! `paste-warden mcp`: stdio MCP server, `guard` profile (phase-2.md §2.5).
//!
//! Analysis and explanation only — enforcement is the hook's job, since a model
//! may simply not call these tools. Every tool is read-only, takes its input as
//! an argument and returns masked output. **There is no clipboard tool** (T9):
//! a prompt-injected agent must not be able to read the clipboard through us.
//! stdio only, no network port; nothing is logged (stdout carries the protocol).
//!
//! Tool logic lives in [`Tools`] (plain functions, unit-tested); [`GuardServer`]
//! is the thin rmcp wrapper.

use paste_warden_core::command::deobfuscate::deobfuscate;
use paste_warden_core::limits::MAX_ANALYZED_CHARS;
use paste_warden_core::secret::{self, PackSet, pem_body_mask_message};
use paste_warden_core::{Context, Engine, Settings};
use paste_warden_i18n::Localizer;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{Json, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::l10n::{parse_locale, t};
use crate::report_json::{ReportJson, SecretJson, TraceStepJson, secrets_json};

/// Longest accepted tool input, in chars (1 Mi). Longer input is an error.
pub const MAX_INPUT_CHARS: usize = MAX_ANALYZED_CHARS;
/// Longest `output_preview` of `deobfuscate_trace`, in chars.
pub const MAX_OUTPUT_PREVIEW_CHARS: usize = 2000;
/// MCP server name used in printed configs (the hook ignores this server).
pub const SERVER_NAME: &str = crate::hook::policy::OWN_MCP_SERVER;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TextInput {
    /// Text to analyze (a command, a snippet, a message). Never echoed back.
    pub text: String,
    /// `zh-TW` or `en` (default: the server's locale).
    #[serde(default)]
    pub locale: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SecretsInput {
    /// Text to scan for secrets. Never echoed back.
    pub text: String,
    /// PII packs (`universal`, `tw`, `us`, …). Default: universal + tw.
    #[serde(default)]
    pub packs: Option<Vec<String>>,
    /// `zh-TW` or `en` for labels (default: the server's locale).
    #[serde(default)]
    pub locale: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MaskInput {
    /// Text whose secrets should be masked.
    pub text: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeobfuscateOutput {
    /// Deobfuscation steps (previews masked).
    pub trace: Vec<TraceStepJson>,
    /// The fully peeled text, secrets masked, cut to 2000 chars (`…` when cut).
    pub output_preview: String,
    /// A safety cap stopped peeling early.
    pub capped: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SecretsOutput {
    /// Kind, rule, label, masked value and UTF-16 span; never the plaintext.
    pub secrets: Vec<SecretJson>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MaskOutput {
    /// The text with every detected secret masked.
    pub masked: String,
}

/// The guard tools as plain functions. Errors are localized messages that
/// never contain the input.
#[derive(Debug, Clone)]
pub struct Tools {
    locale: &'static str,
}

impl Tools {
    pub fn new(default_locale: &str) -> Tools {
        Tools {
            locale: parse_locale(default_locale),
        }
    }

    fn l10n(&self, locale: Option<&str>) -> Localizer {
        Localizer::new(locale.map_or(self.locale, parse_locale))
    }

    fn check(&self, text: &str, l10n: &Localizer) -> Result<(), String> {
        if text.len() > MAX_INPUT_CHARS && text.chars().count() > MAX_INPUT_CHARS {
            return Err(t(l10n, "cli-mcp-too-long", &[]));
        }
        Ok(())
    }

    pub fn analyze(&self, text: &str, locale: Option<&str>) -> Result<ReportJson, String> {
        let l10n = self.l10n(locale);
        self.check(text, &l10n)?;
        let report = Engine::default().analyze(text, &Context::default());
        Ok(ReportJson::new(&report, text, &l10n))
    }

    pub fn deobfuscate_trace(
        &self,
        text: &str,
        locale: Option<&str>,
    ) -> Result<DeobfuscateOutput, String> {
        let l10n = self.l10n(locale);
        self.check(text, &l10n)?;
        let d = deobfuscate(text);
        Ok(DeobfuscateOutput {
            trace: d
                .layers
                .iter()
                .map(|s| TraceStepJson {
                    kind: s.kind.as_str().to_owned(),
                    text: l10n.format(&s.message),
                    preview: s.preview.clone(),
                })
                .collect(),
            output_preview: preview(&mask_all(&d.output, &[], &l10n)),
            capped: d.capped,
        })
    }

    pub fn scan_secrets(
        &self,
        text: &str,
        packs: Option<&[String]>,
        locale: Option<&str>,
    ) -> Result<SecretsOutput, String> {
        let l10n = self.l10n(locale);
        self.check(text, &l10n)?;
        let packs = match packs {
            Some(p) if !p.is_empty() => PackSet::from_codes(p),
            _ => PackSet::default(),
        };
        let found = secret::find(paste_warden_core::limits::prefix(text), &packs);
        Ok(SecretsOutput {
            secrets: secrets_json(&found, text, &l10n),
        })
    }

    pub fn mask(&self, text: &str) -> Result<MaskOutput, String> {
        let l10n = self.l10n(None);
        self.check(text, &l10n)?;
        Ok(MaskOutput {
            masked: mask_all(text, &[], &l10n),
        })
    }
}

/// `text` with every secret masked (same as `paste-warden mask`).
/// `packs` empty = universal + tw.
pub fn mask_all(text: &str, packs: &[String], l10n: &Localizer) -> String {
    let settings = Settings {
        packs: packs.to_vec(),
        ..Settings::default()
    };
    let engine = Engine::new(settings);
    let report = engine.analyze(text, &Context::default());
    engine.masked(text, &report, &l10n.format(&pem_body_mask_message()))
}

fn preview(s: &str) -> String {
    match s.char_indices().nth(MAX_OUTPUT_PREVIEW_CHARS) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_owned(),
    }
}

/// The rmcp server for the `guard` profile.
#[derive(Debug, Clone)]
pub struct GuardServer {
    tools: Tools,
}

impl GuardServer {
    pub fn new(default_locale: &str) -> Self {
        GuardServer {
            tools: Tools::new(default_locale),
        }
    }
}

#[tool_router]
impl GuardServer {
    #[tool(
        description = "Analyze untrusted text (a shell command, a snippet copied from a web page, a message) for ClickFix/FileFix scam commands, hidden characters, secrets and wallet addresses. Returns PasteWarden's Report JSON: action (allow|warn|quarantine), command level, risk score, localized reasons, deobfuscation trace and download hosts, masked secrets. Read-only; never echoes the input; secrets are masked. Advisory only: the PasteWarden hook enforces.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn analyze(
        &self,
        Parameters(p): Parameters<TextInput>,
    ) -> Result<Json<ReportJson>, String> {
        self.tools.analyze(&p.text, p.locale.as_deref()).map(Json)
    }

    #[tool(
        description = "Peel obfuscation layers off a command (cmd carets, PowerShell backticks, string concatenation, -f/-join/-replace, char codes, hex/URL/base64, -EncodedCommand, cmd substrings) and show each step. Returns the localized steps and a masked preview of the decoded text. Read-only; never runs anything.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn deobfuscate_trace(
        &self,
        Parameters(p): Parameters<TextInput>,
    ) -> Result<Json<DeobfuscateOutput>, String> {
        self.tools
            .deobfuscate_trace(&p.text, p.locale.as_deref())
            .map(Json)
    }

    #[tool(
        description = "Find secrets (API keys, private keys, mnemonics, national IDs, credit cards, phone numbers, bank accounts) in text. Returns only the kind, rule id, localized label, masked value and UTF-16 span of each; never the secret itself. Read-only.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn scan_secrets(
        &self,
        Parameters(p): Parameters<SecretsInput>,
    ) -> Result<Json<SecretsOutput>, String> {
        self.tools
            .scan_secrets(&p.text, p.packs.as_deref(), p.locale.as_deref())
            .map(Json)
    }

    #[tool(
        description = "Return the text with every detected secret masked (e.g. before sharing a log or config). Read-only.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn mask(&self, Parameters(p): Parameters<MaskInput>) -> Result<Json<MaskOutput>, String> {
        self.tools.mask(&p.text).map(Json)
    }
}

#[tool_handler]
impl ServerHandler for GuardServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("paste-warden", env!("CARGO_PKG_VERSION"))
                    .with_title("PasteWarden"),
            )
            .with_instructions(
                "PasteWarden read-only analysis (guard profile). Call `analyze` on commands or \
                 snippets from untrusted sources before running them, and `mask` before sharing \
                 text that may contain secrets. There is no clipboard access.",
            )
    }
}

/// Runs the server on stdio until the client disconnects.
pub fn serve(default_locale: &str) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let service = GuardServer::new(default_locale)
            .serve(rmcp::transport::stdio())
            .await?;
        service.waiting().await?;
        anyhow::Ok(())
    })
}

/// The config snippet to register the server with an agent (MCP is never
/// installed automatically; roadmap §10).
pub fn print_config(agent: crate::hook::install::Agent, exe: &std::path::Path) -> String {
    let exe = exe.to_string_lossy();
    let v = match agent {
        crate::hook::install::Agent::ClaudeCode => serde_json::json!({
            "mcpServers": { SERVER_NAME: { "command": exe, "args": ["mcp"] } }
        }),
        crate::hook::install::Agent::Opencode => serde_json::json!({
            "$schema": "https://opencode.ai/config.json",
            "mcp": { "servers": { SERVER_NAME: { "type": "local", "command": [exe, "mcp"] } } }
        }),
    };
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_key() -> String {
        format!("gh{}_{}", "p", "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2")
    }

    #[test]
    fn tool_outputs_never_contain_a_planted_secret() {
        let key = api_key();
        let id = ["A12", "3456", "789"].concat();
        let text = format!(
            "export GITHUB_TOKEN={key}\n身分證 {id}\necho {} | bas{}e64 -d | sh",
            "Z2hwXw==", ""
        );
        let tools = Tools::new("en");
        let outputs = [
            serde_json::to_string(&tools.analyze(&text, None).unwrap()).unwrap(),
            serde_json::to_string(&tools.deobfuscate_trace(&text, Some("zh-TW")).unwrap()).unwrap(),
            serde_json::to_string(&tools.scan_secrets(&text, None, None).unwrap()).unwrap(),
            serde_json::to_string(&tools.mask(&text).unwrap()).unwrap(),
        ];
        for out in &outputs {
            assert!(!out.contains(&key), "{out}");
            assert!(!out.contains(&id), "{out}");
        }
        let secrets = tools.scan_secrets(&text, None, None).unwrap().secrets;
        assert!(secrets.iter().any(|s| s.kind == "api_key"), "{secrets:?}");
        assert!(
            secrets.iter().any(|s| s.kind == "national_id"),
            "{secrets:?}"
        );
    }

    #[test]
    fn decoded_secrets_are_masked_in_the_deobfuscated_preview() {
        let key = api_key();
        let b64 = {
            // Minimal base64 encoder (test only) so the key is not stored encoded.
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let bytes = format!("echo {key}").into_bytes();
            let mut s = String::new();
            for c in bytes.chunks(3) {
                let n = c
                    .iter()
                    .enumerate()
                    .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
                for i in 0..4 {
                    if i <= c.len() {
                        s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                    } else {
                        s.push('=');
                    }
                }
            }
            s
        };
        let text = format!("echo {b64} | bas{}e64 -d | sh", "");
        let out = Tools::new("en").deobfuscate_trace(&text, None).unwrap();
        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains(&key), "{json}");
    }

    #[test]
    fn oversize_input_is_an_error_without_echo() {
        let text = "a".repeat(MAX_INPUT_CHARS + 1);
        let err = Tools::new("en").analyze(&text, None).unwrap_err();
        assert!(err.contains("1,048,576") && err.len() < 200);
        assert!(
            Tools::new("en")
                .analyze(&"a".repeat(MAX_INPUT_CHARS), None)
                .is_ok()
        );
    }

    #[test]
    fn locale_applies_to_reasons() {
        let text = ["power", "shell -w hidden -c calc"].concat();
        let zh = Tools::new("en").analyze(&text, Some("zh-TW")).unwrap();
        let en = Tools::new("zh-TW").analyze(&text, Some("en")).unwrap();
        assert_ne!(zh.command.reasons[0].text, en.command.reasons[0].text);
        assert_eq!(zh.command.reasons[0].id, en.command.reasons[0].id);
    }
}
