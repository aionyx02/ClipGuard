//! Adapters for `secret` and `checksum` ops. See `corpus/ops/secret*.md` and
//! `corpus/ops/checksum.md` for op definitions.

use anyhow::{Context as _, Result, bail};
use paste_warden_core::secret::{self, PackSet, SecretKind, SecretMatch, checksum, packs};
use paste_warden_core::text::byte_to_utf16;
use paste_warden_corpus::resolve_all;
use serde_json::{Value, json};

use crate::check::{partial_match, strings};
use crate::{Ctx, Expect};

pub fn run(op: &str, ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    let f: fn(&Ctx<'_>, &mut Expect) -> Result<()> = match op {
        "secret.find" => find,
        "secret.api_keys" => api_keys,
        "secret.mask_value" => mask_value,
        "secret.mask_text" => mask_text,
        "secret.packs_country_of" => packs_country_of,
        "secret.packs_for_region" => packs_for_region,
        "secret.packs_for_locales" => packs_for_locales,
        "secret.packs_list" => packs_list,
        "secret.rules_load" => rules_load,
        "checksum.validate" => checksum_validate,
        _ => return None,
    };
    Some(with_resolved(ctx, exp, f))
}

/// Benign-corpus classification: any secret with the default packs is a false positive.
pub fn benign(input: &str) -> Option<Result<super::BenignVerdict>> {
    Some(Ok(if secret::find(input, &PackSet::default()).is_empty() {
        super::BenignVerdict::Clean
    } else {
        super::BenignVerdict::Flagged
    }))
}

/// Expect values may contain Text objects (`parts`, `rand`): resolve them, run `f`
/// against the resolved expectation and fold its failures back into `exp`.
fn with_resolved(
    ctx: &Ctx<'_>,
    exp: &mut Expect,
    f: fn(&Ctx<'_>, &mut Expect) -> Result<()>,
) -> Result<()> {
    let mut m = serde_json::Map::new();
    for k in exp.keys() {
        if let Some(v) = exp.take(&k) {
            m.insert(k, v);
        }
    }
    let resolved = resolve_all(&Value::Object(m))?;
    let mut sub = Expect::new(&resolved).map_err(anyhow::Error::msg)?;
    f(ctx, &mut sub)?;
    for msg in sub.finish() {
        exp.fail(msg);
    }
    Ok(())
}

fn packs_arg(ctx: &Ctx<'_>) -> PackSet {
    match ctx.arg_strings("packs") {
        Some(p) => PackSet::from_codes(p),
        None => PackSet::default(),
    }
}

fn match_json(ctx: &Ctx<'_>, text: &str, m: &SecretMatch) -> Value {
    let start = byte_to_utf16(text, m.span.start);
    let end = byte_to_utf16(text, m.span.end);
    json!({
        "kind": m.kind.as_str(),
        "label": ctx.render(&m.label),
        "masked": m.masked,
        "span_utf16": [start, end - start],
        "index_utf16": start,
    })
}

fn pem_mask(ctx: &Ctx<'_>) -> String {
    ctx.render(&secret::pem_body_mask_message())
}

fn find(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let text = &ctx.input;
    let found = secret::find(text, &packs_arg(ctx));
    let items: Vec<Value> = found.iter().map(|m| match_json(ctx, text, m)).collect();
    exp.list_exact("matches", &items);
    exp.list_include("matches_include", &items);
    exp.list_exclude("matches_exclude", &items);
    exp.eq("count", found.len());
    let kinds: Vec<String> = found.iter().map(|m| m.kind.as_str().to_owned()).collect();
    exp.include_all("kinds_include", &kinds);
    if let Some(v) = exp.take("kinds_exclude") {
        for k in strings(&v) {
            if kinds.contains(&k) {
                exp.fail(format!("expect.kinds_exclude: {k:?} found among {kinds:?}"));
            }
        }
    }
    let masked: Vec<String> = found.iter().map(|m| m.masked.clone()).collect();
    exp.contain_in_none("masked_not_contain", &masked);
    Ok(())
}

fn api_keys(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let text = &ctx.input;
    let packs = packs_arg(ctx);
    let all = secret::find(text, &packs);
    let keys: Vec<&SecretMatch> = all
        .iter()
        .filter(|m| m.kind == SecretKind::ApiKey)
        .collect();
    exp.eq("count", keys.len());
    let masked: Vec<String> = keys.iter().map(|m| m.masked.clone()).collect();
    exp.contain_in_none("masked_not_contain", &masked);

    if let Some(expected) = exp.take("matches") {
        let expected = expected.as_array().cloned().unwrap_or_default();
        if expected.len() != keys.len() {
            exp.fail(format!(
                "expect.matches: expected {} item(s), got {}: {:?}",
                expected.len(),
                keys.len(),
                masked
            ));
        } else {
            for (i, (e, m)) in expected.iter().zip(&keys).enumerate() {
                if let Some(why) = check_api_item(ctx, text, e, m) {
                    exp.fail(format!("expect.matches[{i}]: {why}"));
                }
            }
        }
    }

    if let Some(v) = exp.take("mask_text_not_contain_span")
        && v.as_bool() == Some(true)
    {
        let out = secret::mask_text(text, &all, &pem_mask(ctx));
        for m in &keys {
            let raw = text.get(m.span.clone()).unwrap_or_default();
            if !raw.is_empty() && out.contains(raw) {
                exp.fail("expect.mask_text_not_contain_span: masked text still contains a key");
            }
        }
    }
    Ok(())
}

fn check_api_item(ctx: &Ctx<'_>, text: &str, e: &Value, m: &SecretMatch) -> Option<String> {
    let Value::Object(e) = e else {
        return Some("expected an object".into());
    };
    let raw = text.get(m.span.clone()).unwrap_or_default();
    let mut rest = serde_json::Map::new();
    for (k, v) in e {
        match k.as_str() {
            "masked_contains" => {
                let s = v.as_str().unwrap_or_default();
                if !m.masked.contains(s) {
                    return Some(format!("masked {:?} does not contain {s:?}", m.masked));
                }
            }
            "masked_prefix" => {
                let s = v.as_str().unwrap_or_default();
                if !m.masked.starts_with(s) {
                    return Some(format!("masked {:?} does not start with {s:?}", m.masked));
                }
            }
            "span_len_min" => {
                let min = v.as_u64().unwrap_or(0) as usize;
                let len = paste_warden_core::text::utf16_len(raw);
                if len < min {
                    return Some(format!("span length {len} < {min}"));
                }
            }
            "masked_not_contain_span" => {
                if v.as_bool() == Some(true) && !raw.is_empty() && m.masked.contains(raw) {
                    return Some("masked contains the span text".into());
                }
            }
            _ => {
                rest.insert(k.clone(), v.clone());
            }
        }
    }
    partial_match(&Value::Object(rest), &match_json(ctx, text, m))
}

fn mask_value(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let ks = ctx.arg_i64("keep_start").unwrap_or(3).max(0) as usize;
    let ke = ctx.arg_i64("keep_end").unwrap_or(3).max(0) as usize;
    let out = secret::mask_value(&ctx.input, ks, ke);
    exp.eq("output", out.as_str());
    exp.text_not_contains("output_not_contain", &out);
    if let Some(v) = exp.take("star_count_min") {
        let min = v.as_u64().unwrap_or(0) as usize;
        let n = out.chars().filter(|&c| c == '*').count();
        if n < min {
            exp.fail(format!("expect.star_count_min: {n} < {min} in {out:?}"));
        }
    }
    if let Some(v) = exp.take("output_ne_input")
        && v.as_bool() == Some(true)
        && out == ctx.input
    {
        exp.fail("expect.output_ne_input: output equals input");
    }
    Ok(())
}

fn mask_text(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let text = &ctx.input;
    let found = secret::find(text, &packs_arg(ctx));
    exp.eq("output", secret::mask_text(text, &found, &pem_mask(ctx)));
    Ok(())
}

fn packs_json(p: &PackSet) -> Vec<String> {
    let mut v: Vec<String> = p.iter().map(|s| s.to_ascii_lowercase()).collect();
    v.sort();
    v
}

fn set_eq(exp: &mut Expect, key: &str, actual: Vec<String>) {
    if let Some(e) = exp.take(key) {
        let mut e = strings(&e);
        e.sort();
        e.dedup();
        if e != actual {
            exp.fail(format!("expect.{key}: expected {e:?}, got {actual:?}"));
        }
    }
}

fn packs_country_of(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let c = ctx
        .arg_str("region")
        .and_then(packs::country_of)
        .map(|c| c.to_ascii_lowercase());
    exp.eq("country", c.map_or(Value::Null, Value::from));
    Ok(())
}

fn packs_for_region(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let p = packs::for_region(
        ctx.arg_str("region"),
        ctx.arg_strings("extra").unwrap_or_default(),
        ctx.arg_strings("disabled").unwrap_or_default(),
    );
    set_eq(exp, "packs", packs_json(&p));
    Ok(())
}

fn packs_for_locales(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let p = packs::for_locales(ctx.arg_strings("locales").unwrap_or_default());
    set_eq(exp, "packs", packs_json(&p));
    Ok(())
}

fn packs_list(_ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let countries: Vec<String> = packs::countries()
        .iter()
        .map(|c| c.to_ascii_lowercase())
        .collect();
    exp.eq("countries", countries);
    set_eq(exp, "default", packs_json(&PackSet::default()));
    Ok(())
}

fn rules_load(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let files = ctx
        .arg("files")
        .and_then(Value::as_array)
        .context("args.files")?;
    let mut owned = Vec::new();
    for f in files {
        let name = f
            .get("name")
            .and_then(Value::as_str)
            .context("files[].name")?;
        let json = f
            .get("json")
            .and_then(Value::as_str)
            .context("files[].json")?;
        owned.push((name.to_owned(), json.to_owned()));
    }
    let result = secret::RuleSet::load(owned.iter().map(|(n, j)| (n.as_str(), j.as_str())));
    exp.eq("error", result.is_err());
    let msg = result
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    exp.text_contains("error_contains", &msg);
    if let Some(v) = exp.take("scan_count") {
        match &result {
            Ok(rules) => {
                let n = rules.scan_first(&ctx.input);
                if Some(n as u64) != v.as_u64() {
                    exp.fail(format!("expect.scan_count: expected {v}, got {n}"));
                }
            }
            Err(e) => exp.fail(format!("expect.scan_count: load failed: {e}")),
        }
    }
    Ok(())
}

fn checksum_validate(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let s = ctx.input.as_str();
    let valid = match ctx.arg_str("scheme").context("args.scheme")? {
        "tw_id" => checksum::is_valid_taiwan_id(s),
        "tw_ubn" => checksum::is_valid_business_id(s),
        "luhn" => checksum::is_valid_luhn(s),
        "iban" => checksum::is_valid_iban(s),
        "cn_rid" => checksum::is_valid_china_resident_id(s),
        "jp_my_number" => checksum::is_valid_my_number(s),
        "hk_id" => checksum::is_valid_hong_kong_id(s),
        "sg_nric" => checksum::is_valid_singapore_nric(s),
        "us_ssn" => checksum::is_plausible_us_ssn(s),
        "e164" => checksum::is_plausible_e164(s),
        other => bail!("unknown scheme {other}"),
    };
    exp.eq("valid", valid);
    Ok(())
}
