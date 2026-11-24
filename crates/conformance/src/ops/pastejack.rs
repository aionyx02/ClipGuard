//! Adapters for `pastejack` ops. See `corpus/ops/pastejack*.md` for op definitions.

use anyhow::{Context as _, Result};
use paste_warden_core::pastejack;
use serde_json::Value;

use crate::{Ctx, Expect, localizer};

pub fn run(op: &str, ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    match op {
        "pastejack.compare" => Some(compare(ctx, exp)),
        "pastejack.command_signals" => {
            exp.eq("any", !pastejack::command_signals(&ctx.input).is_empty());
            Some(Ok(()))
        }
        "pastejack.normalize" => {
            exp.eq("output", pastejack::normalize(&ctx.input));
            Some(Ok(()))
        }
        "pastejack.preview" => {
            let max = ctx
                .arg_i64("max")
                .map_or(pastejack::PREVIEW_MAX, |m| usize::try_from(m).unwrap_or(0));
            exp.eq("output", pastejack::preview(&ctx.input, max));
            Some(Ok(()))
        }
        _ => None,
    }
}

fn compare(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let selection = ctx.arg_str("selection").unwrap_or_default();
    let written = ctx.arg_str("written").context("args.written")?;
    let v = pastejack::compare(selection, written);
    // `args.locale` overrides the case locale (the extension's UI language).
    let loc = match ctx.arg_str("locale") {
        Some(l) => localizer(l),
        None => ctx.loc(),
    };
    let reasons: Vec<String> = v.reasons.iter().map(|m| loc.format(m)).collect();
    exp.eq("verdict", v.kind.as_str());
    exp.eq("warn", v.warn);
    exp.contain_in_any("reasons_contain", &reasons);
    exp.include_all("reasons_include", &reasons);
    exp.eq(
        "first_reason",
        reasons
            .first()
            .map_or(Value::Null, |r| Value::from(r.as_str())),
    );
    Ok(())
}
