//! Adapters for `command` ops. See `corpus/ops/command*.md` for op definitions.

use anyhow::{Context as _, Result};
use paste_warden_core::{Context, Level, Message, Platform, Source, SourceKind, command};
use paste_warden_corpus::resolve_text;
use serde_json::Value;

use crate::{Ctx, Expect};

pub fn run(op: &str, ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    let r = match op {
        "command.analyze" => {
            analyze(ctx, exp);
            Ok(())
        }
        "command.normalize" => normalize(ctx, exp),
        "command.normalize_length" => normalize_length(ctx, exp),
        "command.explain" => {
            explain(ctx, exp);
            Ok(())
        }
        "command.explain_display" => explain_display(ctx, exp),
        "command.decode_encoded" => {
            exp.eq("output", command::decode_encoded(&ctx.input));
            Ok(())
        }
        "command.is_official_host" => {
            exp.eq("official", command::is_official_host(&ctx.input));
            Ok(())
        }
        "command.deobfuscate" => deobfuscate(ctx, exp),
        "command.analyze_in" => analyze_in(ctx, exp),
        _ => return None,
    };
    Some(r)
}

/// `args.context` → engine context (`corpus/ops/command-1b.md`).
fn context(ctx: &Ctx<'_>) -> Result<Context> {
    let Some(c) = ctx.arg("context") else {
        return Ok(Context::default());
    };
    let source = match c.get("source").and_then(Value::as_str) {
        None => None,
        Some(s) => Some(Source {
            kind: match s {
                "unknown" => SourceKind::Unknown,
                "browser" => SourceKind::Browser,
                "terminal" => SourceKind::Terminal,
                "ide" => SourceKind::Ide,
                "chat" => SourceKind::Chat,
                "password_manager" => SourceKind::PasswordManager,
                "other" => SourceKind::Other,
                other => anyhow::bail!("args.context.source: unknown {other:?}"),
            },
            app: c.get("app").and_then(Value::as_str).map(str::to_owned),
            app_id: None,
            url: c.get("url").and_then(Value::as_str).map(str::to_owned),
        }),
    };
    let platform = match c.get("platform").and_then(Value::as_str) {
        None | Some("unknown") => Platform::Unknown,
        Some("windows") => Platform::Windows,
        Some("macos") => Platform::MacOs,
        Some("linux") => Platform::Linux,
        Some("android") => Platform::Android,
        Some("ios") => Platform::Ios,
        Some("web") => Platform::Web,
        Some(other) => anyhow::bail!("args.context.platform: unknown {other:?}"),
    };
    Ok(Context { source, platform })
}

/// Distinct step kinds in order of first appearance.
fn kinds(steps: &[command::DeobfuscationStep]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in steps {
        let k = s.kind.as_str().to_owned();
        if !out.contains(&k) {
            out.push(k);
        }
    }
    out
}

/// Checks `key` (a list of step kinds) against `actual`: `<key>` exact,
/// `<key>_include` all present, `<key>_exclude` none present.
fn check_kinds(exp: &mut Expect, key: &str, actual: &[String]) {
    exp.eq(key, actual.to_vec());
    exp.include_all(&format!("{key}_include"), actual);
    if let Some(v) = exp.take(&format!("{key}_exclude")) {
        for k in crate::check::strings(&v) {
            if actual.contains(&k) {
                exp.fail(format!(
                    "expect.{key}_exclude: {k:?} is present in {actual:?}"
                ));
            }
        }
    }
}

/// Text values (or a list of them) of `key`, resolved.
fn texts(exp: &mut Expect, key: &str) -> Result<Vec<String>> {
    let Some(v) = exp.take(key) else {
        return Ok(Vec::new());
    };
    let items = match &v {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    items
        .iter()
        .map(|i| resolve_text(i).with_context(|| format!("expect.{key}")))
        .collect()
}

fn deobfuscate(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let d = command::deobfuscate(&ctx.input);
    if let Some(v) = exp.take("output") {
        let expected = resolve_text(&v).context("expect.output")?;
        if expected != d.output {
            exp.fail(format!(
                "expect.output: expected {expected:?}, got {:?}",
                d.output
            ));
        }
    }
    for s in texts(exp, "contains")? {
        if !d.output.contains(&s) {
            exp.fail(format!("expect.contains: {:?} not in {:?}", s, d.output));
        }
    }
    for s in texts(exp, "not_contains")? {
        if d.output.contains(&s) {
            exp.fail(format!("expect.not_contains: {:?} in {:?}", s, d.output));
        }
    }
    check_kinds(exp, "kinds", &kinds(&d.layers));
    let max_layer = d
        .layers
        .iter()
        .map(|l| i64::from(l.layer))
        .max()
        .unwrap_or(0);
    if let Some(v) = exp.take("max_layer_le").and_then(|v| v.as_i64())
        && max_layer > v
    {
        exp.fail(format!("expect.max_layer_le: {max_layer} > {v}"));
    }
    if let Some(v) = exp.take("output_len_le").and_then(|v| v.as_u64()) {
        let len = d.output.chars().count() as u64;
        if len > v {
            exp.fail(format!("expect.output_len_le: {len} > {v}"));
        }
    }
    exp.eq("capped", d.capped);
    let messages: Vec<String> = d.layers.iter().map(|l| ctx.render(&l.message)).collect();
    exp.contain_in_any("messages_contain", &messages);
    let previews: Vec<String> = d.layers.iter().map(|l| l.preview.clone()).collect();
    for s in texts(exp, "previews_not_contain")? {
        if previews.iter().any(|p| p.contains(&s)) {
            exp.fail(format!(
                "expect.previews_not_contain: {s:?} in {previews:?}"
            ));
        }
    }
    Ok(())
}

fn analyze_in(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let f = command::analyze_in(&ctx.input, &context(ctx)?);
    let reasons: Vec<String> = f.verdict.reasons.iter().map(|m| ctx.render(m)).collect();
    exp.eq("level", f.verdict.level.as_str());
    exp.ne("level_not", f.verdict.level.as_str());
    exp.include_all("reasons_include", &reasons);
    exp.contain_in_any("reasons_contain", &reasons);
    exp.contain_in_none("reasons_not_contain", &reasons);
    exp.eq("reasons_empty", reasons.is_empty());
    exp.eq("risk_score", i64::from(f.risk_score));
    if let Some(v) = exp.take("risk_score_min").and_then(|v| v.as_i64())
        && i64::from(f.risk_score) < v
    {
        exp.fail(format!("expect.risk_score_min: {} < {v}", f.risk_score));
    }
    if let Some(v) = exp.take("risk_score_max").and_then(|v| v.as_i64())
        && i64::from(f.risk_score) > v
    {
        exp.fail(format!("expect.risk_score_max: {} > {v}", f.risk_score));
    }
    check_kinds(exp, "trace_kinds", &kinds(&f.trace));
    exp.eq("trace_empty", f.trace.is_empty());
    exp.eq("hosts", f.hosts.clone());
    exp.include_all("hosts_include", &f.hosts);
    // The context never changes the verdict.
    let plain = command::analyze(&ctx.input);
    if plain != f.verdict {
        exp.fail("analyze_in verdict differs from analyze".to_owned());
    }
    Ok(())
}

fn analyze(ctx: &Ctx<'_>, exp: &mut Expect) {
    let v = command::analyze(&ctx.input);
    let reasons: Vec<String> = v.reasons.iter().map(|m| ctx.render(m)).collect();
    exp.eq("level", v.level.as_str());
    exp.ne("level_not", v.level.as_str());
    exp.include_all("reasons_include", &reasons);
    exp.contain_in_any("reasons_contain", &reasons);
    exp.contain_in_none("reasons_not_contain", &reasons);
    exp.eq("reasons_empty", reasons.is_empty());
}

/// `output`, `contains` and `not_contains` are Text values (may use `parts`).
fn normalize(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let out = command::normalize(&ctx.input);
    if let Some(v) = exp.take("output") {
        let expected = resolve_text(&v).context("expect.output")?;
        if expected != out {
            exp.fail(format!("expect.output: expected {expected:?}, got {out:?}"));
        }
    }
    for (key, want) in [("contains", true), ("not_contains", false)] {
        let Some(v) = exp.take(key) else { continue };
        let items = match &v {
            Value::Array(a) => a.clone(),
            other => vec![other.clone()],
        };
        for item in items {
            let s = resolve_text(&item).with_context(|| format!("expect.{key}"))?;
            if out.contains(&s) != want {
                exp.fail(format!("expect.{key}: {out:?} vs {s:?}"));
            }
        }
    }
    Ok(())
}

fn normalize_length(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let out = command::normalize(&ctx.input);
    if let Some(max) = exp.take("len_utf16_lt") {
        let max = max.as_u64().context("len_utf16_lt must be an integer")? as usize;
        let len = paste_warden_core::text::utf16_len(&out);
        if len >= max {
            exp.fail(format!("expect.len_utf16_lt: length {len} >= {max}"));
        }
    }
    Ok(())
}

/// Rendered actions, summary and display text of an explanation.
struct Rendered {
    actions: Vec<String>,
    summary: String,
}

fn render(ctx: &Ctx<'_>, e: &command::Explanation) -> Rendered {
    let actions: Vec<String> = e.actions.iter().map(|m| ctx.render(m)).collect();
    let sep = ctx.render(&Message::new(command::MSG_ACTION_SEPARATOR));
    let summary = actions.join(&sep);
    Rendered { actions, summary }
}

/// Legacy `CommandExplanation.ToDisplayText(max_length)`.
fn display_text(ctx: &Ctx<'_>, e: &command::Explanation, summary: &str, max_len: usize) -> String {
    let mut text = ctx.render(&Message::new(command::MSG_DISPLAY_SUMMARY).arg("summary", summary));
    if let Some(d) = e.decoded_one_line() {
        text.push('\n');
        text.push_str(&ctx.render(&Message::new(command::MSG_DISPLAY_DECODED).arg("decoded", d)));
    }
    command::truncate_display(&text, max_len)
}

fn explain(ctx: &Ctx<'_>, exp: &mut Expect) {
    let e = command::explain(&ctx.input);
    let r = render(ctx, &e);
    exp.eq("actions", r.actions.clone());
    exp.eq("actions_first", r.actions.first().cloned());
    exp.include_all("actions_contain", &r.actions);
    exp.eq("summary", r.summary.as_str());
    exp.eq("decoded", e.decoded.clone());
    if exp.has("display_200_starts_with") {
        let display = display_text(ctx, &e, &r.summary, 200);
        exp.starts_with("display_200_starts_with", &display);
    }
}

fn explain_display(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let max = ctx.arg_i64("max_length").context("args.max_length")?.max(0) as usize;
    let e = command::explain(&ctx.input);
    let r = render(ctx, &e);
    let display = display_text(ctx, &e, &r.summary, max);
    exp.text_contains("contains", &display);
    exp.starts_with("starts_with", &display);
    exp.ends_with("ends_with", &display);
    exp.max_utf16("max_len_utf16", &display);
    Ok(())
}

/// Benign-corpus classification: Malicious is a false positive, Suspicious a
/// warning.
pub fn benign(input: &str) -> Option<Result<super::BenignVerdict>> {
    Some(Ok(match command::analyze(input).level {
        Level::Malicious => super::BenignVerdict::Flagged,
        Level::Suspicious => super::BenignVerdict::Warned,
        Level::None => super::BenignVerdict::Clean,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command message id (reasons and deobfuscation steps) has a zh-TW and
    /// an en string.
    #[test]
    fn locales_cover_command_messages() {
        for locale in ["zh-TW", "en"] {
            let loc = crate::localizer(locale);
            for id in command::MESSAGE_IDS {
                assert!(loc.has(id), "{locale} lacks {id}");
            }
            for kind in command::StepKind::ALL {
                assert!(
                    loc.has(kind.message_id()),
                    "{locale} lacks {}",
                    kind.message_id()
                );
            }
        }
    }
}
