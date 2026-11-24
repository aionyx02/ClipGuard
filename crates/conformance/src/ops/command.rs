//! Adapters for `command` ops. See `corpus/ops/command*.md` for op definitions.

use anyhow::{Context as _, Result};
use paste_warden_core::{Level, Message, command};
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
        _ => return None,
    };
    Some(r)
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
