//! Adapters for `wallet` ops. See `corpus/ops/wallet*.md` for op definitions.

use anyhow::{Context as _, Result};
use paste_warden_core::text::byte_to_utf16;
use paste_warden_core::wallet::{self, SwapDetector, WalletSwap};
use serde_json::{Value, json};

use crate::check::partial_match;
use crate::{Ctx, Expect};

pub fn run(op: &str, ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    match op {
        "wallet.parse" => {
            let parsed = wallet::parse(&ctx.input);
            exp.eq("valid", parsed.is_some());
            exp.eq(
                "currency",
                parsed.as_ref().map_or(Value::Null, |p| p.0.as_str().into()),
            );
            exp.eq(
                "normalized",
                parsed.map_or(Value::Null, |p| Value::from(p.1)),
            );
            Some(Ok(()))
        }
        "wallet.find_all" => {
            let s = &ctx.input;
            let actual: Vec<Value> = wallet::find_all(s)
                .iter()
                .map(|m| {
                    let start = byte_to_utf16(s, m.start);
                    json!({
                        "currency": m.currency.as_str(),
                        "text": s.get(m.range()).unwrap_or_default(),
                        "span_utf16": [start, byte_to_utf16(s, m.start + m.len) - start],
                        "normalized": m.normalized,
                    })
                })
                .collect();
            exp.eq("count", actual.len());
            exp.list_exact("matches", &actual);
            Some(Ok(()))
        }
        "wallet.swap" => Some(swap(ctx, exp)),
        _ => None,
    }
}

fn swap_json(s: &WalletSwap) -> Value {
    json!({
        "currency": s.currency.as_str(),
        "replacement_currency": s.replacement_currency.as_str(),
        "original": s.original,
        "replacement": s.replacement,
        "elapsed_ms": s.elapsed_ms,
        "signal": s.signal.as_str(),
    })
}

fn swap(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    // Event times may be negative (clock going backwards); shift them so the
    // earliest is 0. Only differences matter to the detector.
    let times: Vec<i64> = ctx
        .events
        .iter()
        .enumerate()
        .map(|(i, e)| {
            e.get("t_ms")
                .and_then(Value::as_i64)
                .with_context(|| format!("events[{i}].t_ms"))
        })
        .collect::<Result<_>>()?;
    let base = times.iter().copied().min().unwrap_or(0).min(0);

    let mut detector = SwapDetector::new();
    for (i, (event, t)) in ctx.events.iter().zip(times).enumerate() {
        let now = u64::try_from(t - base).context("t_ms out of range")?;
        let copy = event
            .get("copy")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let idle = event
            .get("user_idle_ms")
            .and_then(Value::as_i64)
            .map(|v| u64::try_from(v).unwrap_or(0));
        let result = detector.observe(copy, now, idle);

        let Some(expect) = event.get("expect") else {
            continue;
        };
        let mut sub = Expect::new(expect).map_err(anyhow::Error::msg)?;
        if let Some(want) = sub.take("swap") {
            match (&want, &result) {
                (Value::Bool(false), None) | (Value::Bool(true), Some(_)) => {}
                (Value::Object(_), Some(s)) => {
                    if let Some(why) = partial_match(&want, &swap_json(s)) {
                        sub.fail(format!("expect.swap: {why}"));
                    }
                }
                (_, r) => sub.fail(format!(
                    "expect.swap: expected {want}, got {}",
                    r.as_ref().map_or(Value::Null, swap_json)
                )),
            }
        }
        exp.absorb(&format!("events[{i}]"), sub);
    }
    Ok(())
}
