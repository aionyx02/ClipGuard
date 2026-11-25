//! `scan`, `mask` and `bench` (phase-2.md §2.3).

use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;

use paste_warden_core::{Action, Arg, Context, Engine, Level, Settings};
use paste_warden_i18n::Localizer;
use serde::{Deserialize, Serialize};

use crate::l10n::t;
use paste_warden_report::ReportJson;

/// `scan` exit codes.
pub const EXIT_ALLOW: u8 = 0;
pub const EXIT_WARN: u8 = 1;
pub const EXIT_QUARANTINE: u8 = 2;
pub const EXIT_ERROR: u8 = 3;

pub fn exit_code(a: Action) -> u8 {
    match a {
        Action::Allow => EXIT_ALLOW,
        Action::Warn => EXIT_WARN,
        Action::Quarantine => EXIT_QUARANTINE,
    }
}

/// Reads a file, or stdin for `None` / `-`. Invalid UTF-8 is replaced. The
/// error message names the file, never its contents.
pub fn read_input(path: Option<&Path>, l10n: &Localizer) -> Result<String, String> {
    let mut buf = Vec::new();
    let r = match path {
        None => std::io::stdin().lock().read_to_end(&mut buf).map(|_| ()),
        Some(p) if p == Path::new("-") => std::io::stdin().lock().read_to_end(&mut buf).map(|_| ()),
        Some(p) => std::fs::read(p).map(|b| buf = b),
    };
    r.map_err(|e| {
        let cause = match path {
            Some(p) if p != Path::new("-") => format!("{}: {}", p.display(), e.kind()),
            _ => format!("stdin: {}", e.kind()),
        };
        t(l10n, "cli-error-read", &[("cause", cause.into())])
    })?;
    Ok(match String::from_utf8(buf) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

pub fn engine(packs: &[String]) -> Engine {
    Engine::new(Settings {
        packs: packs.to_vec(),
        ..Settings::default()
    })
}

/// Terminal colors (ANSI); empty strings when disabled.
#[derive(Debug, Clone, Copy)]
pub struct Colors {
    pub on: bool,
}

impl Colors {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_owned()
        }
    }
}

fn level_name(l: Level, l10n: &Localizer) -> String {
    let id = match l {
        Level::None => "cli-level-none",
        Level::Suspicious => "cli-level-suspicious",
        Level::Malicious => "cli-level-malicious",
    };
    t(l10n, id, &[])
}

/// Human-readable report: headline, command verdict, reasons, trace, hosts,
/// masked secrets, hidden characters, wallets. Never prints the input.
pub fn render_human(
    json: &ReportJson,
    report: &paste_warden_core::Report,
    l10n: &Localizer,
    c: Colors,
) -> String {
    let mut out = String::new();
    let (code, id, mark) = match report.action {
        Action::Allow => ("32", "cli-action-allow", "✓"),
        Action::Warn => ("33", "cli-action-warn", "!"),
        Action::Quarantine => ("1;31", "cli-action-quarantine", "✗"),
    };
    let _ = writeln!(
        out,
        "{}",
        c.paint(code, &format!("{mark} {}", t(l10n, id, &[])))
    );
    let cmd = &json.command;
    if report.command.verdict.level != Level::None {
        let _ = writeln!(
            out,
            "\n{}",
            t(
                l10n,
                "cli-scan-command",
                &[
                    (
                        "level",
                        level_name(report.command.verdict.level, l10n).into()
                    ),
                    ("score", Arg::from(i64::from(cmd.risk_score))),
                ],
            )
        );
        if !cmd.reasons.is_empty() {
            let _ = writeln!(out, "{}", t(l10n, "cli-scan-reasons", &[]));
            for r in &cmd.reasons {
                let _ = writeln!(out, "  - {}", r.text);
            }
        }
        if !cmd.trace.is_empty() {
            let _ = writeln!(out, "{}", t(l10n, "cli-scan-trace", &[]));
            for s in &cmd.trace {
                let _ = writeln!(out, "  - {}", s.text);
                let _ = writeln!(out, "    {}", c.paint("2", &s.preview));
            }
        }
        if !cmd.hosts.is_empty() {
            let _ = writeln!(
                out,
                "{}",
                t(
                    l10n,
                    "cli-scan-hosts",
                    &[("hosts", cmd.hosts.join(", ").into())]
                )
            );
        }
    }
    if !json.secrets.is_empty() {
        let _ = writeln!(out, "\n{}", t(l10n, "cli-scan-secrets", &[]));
        for s in &json.secrets {
            let item = t(
                l10n,
                "cli-scan-secret-item",
                &[
                    ("label", s.label.clone().into()),
                    ("masked", s.masked.clone().into()),
                ],
            );
            let _ = writeln!(out, "  - {item}");
        }
    }
    if !json.hidden.reasons.is_empty() {
        let _ = writeln!(out, "\n{}", t(l10n, "cli-scan-hidden", &[]));
        for r in &json.hidden.reasons {
            let _ = writeln!(out, "  - {}", r.text);
        }
    }
    if !json.wallets.is_empty() {
        let _ = writeln!(
            out,
            "\n{}",
            t(
                l10n,
                "cli-scan-wallets",
                &[("count", json.wallets.len().into())]
            )
        );
    }
    if json.truncated {
        let _ = writeln!(out, "\n{}", t(l10n, "cli-scan-truncated", &[]));
    }
    out
}

/// One `bench` input line.
#[derive(Debug, Deserialize)]
pub struct BenchLine {
    pub id: serde_json::Value,
    pub text: String,
}

/// One `bench` output line.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct BenchResult {
    pub id: serde_json::Value,
    pub action: paste_warden_report::ActionJson,
    pub level: paste_warden_report::LevelJson,
    pub risk_score: u8,
    pub secrets: usize,
    pub hidden: paste_warden_report::LevelJson,
}

/// Totals printed as the last `bench` line (`{"summary": …}`).
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct BenchSummary {
    pub total: usize,
    pub allow: usize,
    pub warn: usize,
    pub quarantine: usize,
    pub malicious: usize,
    pub suspicious: usize,
    pub errors: usize,
}

/// Runs `bench` over JSONL `input`; returns the output lines (JSONL, the
/// last one being the summary) and the error messages (line numbers only).
pub fn bench(input: &str, engine: &Engine, l10n: &Localizer) -> (Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut sum = BenchSummary::default();
    for (i, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(case) = serde_json::from_str::<BenchLine>(line) else {
            sum.errors += 1;
            errors.push(t(l10n, "cli-error-json", &[("line", (i + 1).into())]));
            continue;
        };
        let r = engine.analyze(&case.text, &Context::default());
        sum.total += 1;
        match r.action {
            Action::Allow => sum.allow += 1,
            Action::Warn => sum.warn += 1,
            Action::Quarantine => sum.quarantine += 1,
        }
        match r.command.verdict.level {
            Level::Malicious => sum.malicious += 1,
            Level::Suspicious => sum.suspicious += 1,
            Level::None => {}
        }
        let res = BenchResult {
            id: case.id,
            action: r.action.into(),
            level: r.command.verdict.level.into(),
            risk_score: r.command.risk_score,
            secrets: r.secrets.len(),
            hidden: r.hidden.level.into(),
        };
        out.push(serde_json::to_string(&res).unwrap_or_default());
    }
    out.push(serde_json::json!({ "summary": sum }).to_string());
    (out, errors)
}
