//! Op adapters, one module per area. Each `run` returns `None` for ops it does
//! not handle, otherwise runs the engine and checks `exp`.
//!
//! Ownership (Phase 1 work split): `command.rs`, `secret.rs` (incl. `checksum.*`),
//! `hidden.rs`, `wallet.rs`, `pastejack.rs`, `policy.rs` (entry, guard, throttle,
//! paste, limits, registered), `i18n.rs` (`i18n.*` except `i18n.localized`).

use anyhow::{Context as _, Result};
use paste_warden_corpus::Case;
use serde_json::Value;

use crate::{Ctx, Expect, Outcome, run_ctx};

pub mod command;
pub mod hidden;
pub mod i18n;
pub mod pastejack;
pub mod policy;
pub mod secret;
pub mod wallet;

/// Routes `op` to its area adapter.
pub fn dispatch(op: &str, ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    if op == "i18n.localized" {
        return Some(localized(ctx, exp));
    }
    let area = op.split('.').next().unwrap_or_default();
    match area {
        "command" => command::run(op, ctx, exp),
        "secret" | "checksum" => secret::run(op, ctx, exp),
        "hidden" => hidden::run(op, ctx, exp),
        "wallet" => wallet::run(op, ctx, exp),
        "pastejack" => pastejack::run(op, ctx, exp),
        "entry" | "guard" | "throttle" | "paste" | "limits" | "registered" => {
            policy::run(op, ctx, exp)
        }
        "i18n" => i18n::run(op, ctx, exp),
        _ => None,
    }
}

/// `i18n.localized`: runs `args.op` with `args.input` / `args.args` in `args.locale`,
/// checking the case's whole `expect` against that op.
fn localized(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let locale = match ctx.arg_str("locale").context("args.locale")? {
        l if l.eq_ignore_ascii_case("en") => "en",
        _ => "zh-TW",
    };
    let op = ctx.arg_str("op").context("args.op")?.to_owned();
    let input = ctx.args.get("input").and_then(Value::as_str);
    let inner = Ctx {
        case: ctx.case,
        input: input.unwrap_or_default().to_owned(),
        has_input: input.is_some(),
        args: ctx.args.get("args").cloned().unwrap_or(Value::Null),
        events: ctx.events.clone(),
        locale,
    };
    // Re-run the inner op against the full expect object; consume every key here.
    let expect_value = take_all(exp);
    match run_ctx(&inner, &op, &expect_value) {
        Outcome::Pass => {}
        Outcome::Fail(f) => f
            .into_iter()
            .for_each(|m| exp.fail(format!("[{locale} {op}] {m}"))),
        Outcome::Unimplemented => exp.fail(format!("[{locale}] inner op `{op}` is unimplemented")),
        Outcome::Error(e) => exp.fail(format!("[{locale} {op}] error: {e}")),
    }
    Ok(())
}

/// Consumes every key of `exp`, returning the original object.
fn take_all(exp: &mut Expect) -> Value {
    let keys: Vec<String> = exp.keys();
    let mut m = serde_json::Map::new();
    for k in keys {
        if let Some(v) = exp.take(&k) {
            m.insert(k, v);
        }
    }
    Value::Object(m)
}

/// Benign-corpus verdict for one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenignVerdict {
    Clean,
    /// Acceptable but noisy (e.g. a Suspicious command warning).
    Warned,
    /// A false positive (Malicious command, any secret, any hidden-char warning).
    Flagged,
}

/// Runs a benign case and classifies the engine's result.
pub fn benign_verdict(case: &Case) -> Option<Result<BenignVerdict>> {
    let input = match case.input.as_ref().map(paste_warden_corpus::resolve_text) {
        Some(Ok(s)) => s,
        Some(Err(e)) => return Some(Err(e)),
        None => String::new(),
    };
    match case.area.as_str() {
        "command" => command::benign(&input),
        "secret" => secret::benign(&input),
        "hidden" => hidden::benign(&input),
        _ => None,
    }
}
