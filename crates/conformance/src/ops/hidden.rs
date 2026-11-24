//! Adapters for `hidden` ops. See `corpus/ops/hidden*.md` for op definitions.

use anyhow::Result;
use paste_warden_core::{Level, hidden};
use serde_json::Value;

use crate::check::strings;
use crate::{Ctx, Expect};

pub fn run(op: &str, ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    match op {
        "hidden.analyze" | "hidden.reasons" => Some(analyze(ctx, exp)),
        _ => None,
    }
}

fn analyze(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let v = hidden::analyze(&ctx.input);
    let reasons: Vec<String> = v.reasons.iter().map(|m| ctx.render(m)).collect();
    exp.eq("level", v.level.as_str());
    exp.contain_in_any("reasons_contain", &reasons);
    exp.contain_in_none("reasons_not_contain", &reasons);
    exp.eq("reasons_empty", reasons.is_empty());

    // Each group: some single reason contains every string of the group.
    if let Some(groups) = exp.take("reasons_any") {
        for group in groups.as_array().cloned().unwrap_or_default() {
            let want = strings(&group);
            if !reasons.iter().any(|r| want.iter().all(|w| r.contains(w))) {
                exp.fail(format!(
                    "expect.reasons_any: no reason contains all of {want:?}; got {reasons:?}"
                ));
            }
        }
    }

    if let Some(single) = exp.take("reasons_single") {
        let field = |k: &str| single.get(k).map(strings).unwrap_or_default();
        let contain = single
            .get("contain")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let hits: Vec<&String> = reasons.iter().filter(|r| r.contains(contain)).collect();
        match hits.as_slice() {
            [r] => {
                for a in field("all") {
                    if !r.contains(&a) {
                        exp.fail(format!("expect.reasons_single: {r:?} lacks {a:?}"));
                    }
                }
                for n in field("none") {
                    if r.contains(&n) {
                        exp.fail(format!("expect.reasons_single: {r:?} contains {n:?}"));
                    }
                }
            }
            _ => exp.fail(format!(
                "expect.reasons_single: {} reasons contain {contain:?}; got {reasons:?}",
                hits.len()
            )),
        }
    }
    Ok(())
}

/// Benign-corpus classification: any hidden-character warning is a false positive.
pub fn benign(input: &str) -> Option<Result<super::BenignVerdict>> {
    let v = hidden::analyze(input);
    Some(Ok(if v.level == Level::None {
        super::BenignVerdict::Clean
    } else {
        super::BenignVerdict::Flagged
    }))
}
