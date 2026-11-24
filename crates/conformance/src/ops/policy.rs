//! Adapters for the policy areas: `entry.*`, `guard.run`, `throttle.run`,
//! `paste.*`, `limits.prefix`, `registered.*`. See `corpus/ops/{entry,guard,
//! throttle,paste,limits,registered}.md`.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use paste_warden_core::policy::entry::{self, EntryWarningGate};
use paste_warden_core::policy::guard::ClipboardGuardState;
use paste_warden_core::policy::paste::{
    self, MaskKind, MaskSpan, PasteGuardSettings, PasteSecrets, PasteTarget, PendingPaste,
};
use paste_warden_core::policy::registered::{self, RegisteredSecretStore};
use paste_warden_core::policy::throttle::{Notification, NotificationLevel, NotificationThrottle};
use paste_warden_core::text::{byte_to_utf16, utf16_len, utf16_to_byte};
use paste_warden_core::{Level, Message, Verdict, limits};
use paste_warden_corpus::resolve_all;
use serde_json::{Value, json};

use crate::{Ctx, Expect};

pub fn run(op: &str, ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    match op {
        "entry.classify" => Some(entry_classify(ctx, exp)),
        "entry.decide" => Some(entry_decide(ctx, exp)),
        "entry.gate" => Some(entry_gate(ctx, exp)),
        "guard.run" => guard_run(ctx, exp),
        "throttle.run" => Some(throttle_run(ctx, exp)),
        "paste.decide" => Some(paste_decide(ctx, exp)),
        "paste.can_intercept" => Some(paste_can_intercept(ctx, exp)),
        "paste.normalize_app" => Some(paste_normalize_app(ctx, exp)),
        "paste.enter" => Some(paste_enter(ctx, exp)),
        "paste.settings_load" => Some(paste_settings_load(ctx, exp)),
        "paste.settings_save" => Some(paste_settings_save(ctx, exp)),
        "paste.mask" => paste_mask(ctx, exp),
        // TODO(phase1 merge): wire secret::find (snapshot of the detected secrets).
        "paste.snapshot" => None,
        "limits.prefix" => limits_prefix(ctx, exp),
        "registered.run" => Some(registered_run(ctx, exp)),
        "registered.validate" => Some(registered_validate(ctx, exp)),
        _ => None,
    }
}

// ---------------------------------------------------------------- cross-area hooks

/// The command analyzer used by the clipboard guard and `limits.prefix`.
fn analyze_command(text: &str) -> Option<Verdict> {
    Some(paste_warden_core::command::analyze(text))
}

/// Secret matches for `paste.mask` with `matches: "detect"`: (kind, masked, byte range).
// TODO(phase1 merge): wire secret::find (default packs).
fn detect_secrets(_text: &str) -> Option<Vec<(String, String, std::ops::Range<usize>)>> {
    None
}

// ---------------------------------------------------------------- helpers

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn level_of(name: &str) -> Result<Level> {
    Ok(match name {
        "none" => Level::None,
        "suspicious" => Level::Suspicious,
        "malicious" => Level::Malicious,
        other => bail!("unknown level {other:?}"),
    })
}

/// Expect value with any Text objects resolved.
fn take_text(exp: &mut Expect, key: &str) -> Result<Option<Value>> {
    exp.take(key).map(|v| resolve_all(&v)).transpose()
}

fn event_expect(ev: &Value) -> Result<Expect> {
    Expect::new(ev.get("expect").unwrap_or(&json!({}))).map_err(anyhow::Error::msg)
}

fn settings_of(v: Option<&Value>) -> Result<PasteGuardSettings> {
    let d = PasteGuardSettings::default();
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(d);
    };
    Ok(PasteGuardSettings {
        intercept_registered: v
            .get("intercept_registered")
            .and_then(Value::as_bool)
            .unwrap_or(d.intercept_registered),
        intercept_detected: v
            .get("intercept_detected")
            .and_then(Value::as_bool)
            .unwrap_or(d.intercept_detected),
        allowed_apps: match v.get("allowed_apps") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| x.as_str().unwrap_or_default().to_owned())
                .collect(),
            Some(_) => bail!("settings.allowed_apps must be an array"),
        },
    })
}

fn settings_json(s: &PasteGuardSettings) -> Value {
    json!({
        "intercept_registered": s.intercept_registered,
        "intercept_detected": s.intercept_detected,
        "allowed_apps": s.allowed_apps,
    })
}

// ---------------------------------------------------------------- entry

fn window_args<'a>(ctx: &'a Ctx<'_>) -> (&'a str, &'a str, &'a str) {
    (
        ctx.arg_str("class").unwrap_or_default(),
        ctx.arg_str("title").unwrap_or_default(),
        ctx.arg_str("process").unwrap_or_default(),
    )
}

fn entry_classify(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let (c, t, p) = window_args(ctx);
    exp.eq("entry", entry::classify(c, t, p).as_str());
    Ok(())
}

fn entry_decide(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let (c, t, p) = window_args(ctx);
    let level = level_of(ctx.arg_str("level").unwrap_or("none"))?;
    let quarantined = ctx.arg_bool("quarantined").unwrap_or(false);
    let w = entry::decide(c, t, p, level, quarantined);
    exp.eq("warn", w.is_some());
    match w {
        None => {
            for k in [
                "entry",
                "level",
                "title",
                "title_contain",
                "body_contain",
                "body_starts_with",
                "title_max_utf16",
                "body_max_utf16",
            ] {
                if exp.take(k).is_some() {
                    exp.fail(format!("expect.{k}: no warning was produced"));
                }
            }
        }
        Some(w) => {
            let title = ctx.render(&w.title);
            let body = w
                .body
                .iter()
                .map(|m| ctx.render(m))
                .collect::<Vec<_>>()
                .join("\n");
            exp.eq("entry", w.entry.as_str());
            exp.eq("level", w.level.as_str());
            exp.eq("title", title.as_str());
            exp.text_contains("title_contain", &title);
            exp.text_contains("body_contain", &body);
            exp.starts_with("body_starts_with", &body);
            exp.max_utf16("title_max_utf16", &title);
            exp.max_utf16("body_max_utf16", &body);
        }
    }
    Ok(())
}

fn entry_gate(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let mut gate = EntryWarningGate::new();
    for (i, ev) in ctx.events.iter().enumerate() {
        let window = ev.get("window").and_then(Value::as_u64).context("window")?;
        let generation = ev
            .get("generation")
            .and_then(Value::as_u64)
            .context("generation")?;
        let warn = gate.try_enter(window, generation);
        let mut sub = event_expect(ev)?;
        sub.eq("warn", warn);
        exp.absorb(&format!("events[{i}]"), sub);
    }
    Ok(())
}

// ---------------------------------------------------------------- guard

fn guard_run(ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    let mut state = ClipboardGuardState::new();
    for (i, ev) in ctx.events.iter().enumerate() {
        let before = state.generation();
        let mut sub = match event_expect(ev) {
            Ok(s) => s,
            Err(e) => return Some(Err(e)),
        };
        let mut read_full_called = false;
        let mut action = None;
        let mut restored = None;
        if let Some(c) = ev.get("clipboard") {
            match c {
                Value::Null => action = Some(state.on_clipboard_empty()),
                Value::String(text) => {
                    // Without the analyzer only the trusted-content path can run.
                    let mut missing = false;
                    let read_full = ev.get("read_full").and_then(Value::as_str);
                    let a = state.on_clipboard_text(
                        text,
                        |t| {
                            analyze_command(t).unwrap_or_else(|| {
                                missing = true;
                                Verdict::CLEAN
                            })
                        },
                        || {
                            read_full_called = true;
                            read_full.map(str::to_owned)
                        },
                    );
                    if missing {
                        return None;
                    }
                    action = Some(a);
                }
                _ => return Some(Err(anyhow::anyhow!("clipboard must be Text or null"))),
            }
        } else if let Some(r) = ev.get("restore").and_then(Value::as_str) {
            match r {
                "begin" => restored = Some(state.begin_restore()),
                "end_ok" => state.end_restore(true),
                "end_failed" => state.end_restore(false),
                other => return Some(Err(anyhow::anyhow!("unknown restore {other:?}"))),
            }
        } else {
            return Some(Err(anyhow::anyhow!("event {i} has no action")));
        }

        if let Some(a) = action {
            sub.eq("action", a.as_str());
        }
        if let Some(r) = restored {
            sub.eq("restored", r.map_or(Value::Null, Value::String));
        }
        sub.eq("read_full_called", read_full_called);
        sub.eq(
            "quarantined",
            state
                .quarantined()
                .map_or(Value::Null, |q| Value::String(q.to_owned())),
        );
        sub.eq("quarantine_active", state.quarantine_active());
        sub.eq("level", state.level().as_str());
        sub.eq("verdict_level", state.last_verdict().level.as_str());
        let gen_change = if state.generation() == before {
            "unchanged"
        } else {
            "increased"
        };
        sub.eq("generation", gen_change);
        exp.absorb(&format!("events[{i}]"), sub);
    }
    Some(Ok(()))
}

// ---------------------------------------------------------------- throttle

fn throttle_run(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let min = ctx
        .arg("min_interval_ms")
        .and_then(Value::as_u64)
        .unwrap_or(1000);
    let visible = ctx
        .arg("visible_for_ms")
        .and_then(Value::as_u64)
        .unwrap_or(6000);
    let mut t: NotificationThrottle<String> = NotificationThrottle::new(min, visible);
    for (i, ev) in ctx.events.iter().enumerate() {
        let now = ev.get("t_ms").and_then(Value::as_u64).context("t_ms")?;
        let mut sub = event_expect(ev)?;
        let decision = if let Some(n) = ev.get("submit") {
            let level = match s(n, "level") {
                "warning" => NotificationLevel::Warning,
                "error" => NotificationLevel::Error,
                other => bail!("unknown notification level {other:?}"),
            };
            Some(
                t.submit(
                    Notification {
                        level,
                        restorable: n
                            .get("restorable")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        payload: s(n, "title").to_owned(),
                    },
                    now,
                ),
            )
        } else if ev.get("flush").is_some() {
            Some(t.flush(now))
        } else if ev.get("clipboard_changed").is_some() {
            t.on_clipboard_changed();
            None
        } else {
            bail!("event {i} has no action");
        };
        if let Some(d) = decision {
            let shown = d.show.as_ref().map(|n| n.payload.clone());
            sub.eq("show", shown.clone().map_or(Value::Null, Value::String));
            sub.eq("shown", shown.is_some());
            sub.eq("replace_visible", d.replace_visible);
            sub.eq(
                "retry_in_ms",
                d.retry_in_ms.map_or(Value::Null, Value::from),
            );
        }
        sub.eq(
            "pending",
            t.pending()
                .map_or(Value::Null, |p| Value::String(p.payload.clone())),
        );
        exp.absorb(&format!("events[{i}]"), sub);
    }
    Ok(())
}

// ---------------------------------------------------------------- paste

fn paste_decide(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let kinds = ctx.arg_strings("kinds").unwrap_or_default();
    let target = ctx.arg("target").context("args.target")?;
    let target = PasteTarget {
        process: s(target, "process"),
        class: s(target, "class"),
        own: target.get("own").and_then(Value::as_bool).unwrap_or(false),
    };
    let settings = settings_of(ctx.arg("settings"))?;
    let d = paste::decide(
        PasteSecrets::from_kinds(kinds.iter().map(String::as_str)),
        &target,
        &settings,
    );
    exp.eq("decision", d.as_str());
    Ok(())
}

fn paste_can_intercept(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let settings = settings_of(ctx.arg("settings"))?;
    let has = ctx.arg_bool("has_registered").unwrap_or(false);
    exp.eq("can_intercept", settings.can_intercept(has));
    Ok(())
}

fn paste_normalize_app(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let name = ctx.arg_str("name").unwrap_or_default();
    exp.eq("output", paste::normalize_app_name(name));
    Ok(())
}

fn paste_enter(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let mut p = PendingPaste::new();
    for (i, ev) in ctx.events.iter().enumerate() {
        let now = ev.get("t_ms").and_then(Value::as_u64).context("t_ms")?;
        let mut sub = event_expect(ev)?;
        if let Some(x) = ev.get("intercept") {
            p.intercept(
                now,
                x.get("target_root").and_then(Value::as_u64).unwrap_or(0),
            );
        } else if ev.get("resolve").is_some() {
            p.resolve();
        } else if let Some(x) = ev.get("enter") {
            let swallow = p.should_swallow_enter(
                now,
                x.get("foreground_root")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                x.get("foreground_is_own")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            );
            sub.eq("swallow", swallow);
        } else {
            bail!("event {i} has no action");
        }
        exp.absorb(&format!("events[{i}]"), sub);
    }
    Ok(())
}

fn paste_settings_load(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let file = ctx.arg_str("file");
    let (s, err) = PasteGuardSettings::from_json(file);
    settings_expect(exp, &s, err.is_some());
    Ok(())
}

fn paste_settings_save(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let settings = settings_of(ctx.arg("settings"))?;
    let text = settings.to_json();
    let (s, err) = PasteGuardSettings::from_json(Some(&text));
    settings_expect(exp, &s, err.is_some());
    Ok(())
}

fn settings_expect(exp: &mut Expect, s: &PasteGuardSettings, error: bool) {
    exp.eq("error", error);
    exp.eq("allowed_apps_count", s.allowed_apps.len());
    if let Some(e) = exp.take("settings")
        && let Some(why) = crate::check::partial_match(&e, &settings_json(s))
    {
        exp.fail(format!("expect.settings: {why}"));
    }
}

fn mask_kind(kind: &str) -> MaskKind {
    match kind {
        "registered" => MaskKind::Registered,
        "api_key" => MaskKind::ApiKey,
        _ => MaskKind::Other,
    }
}

fn paste_mask(ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    let text = ctx.input.as_str();
    let owned: Vec<(String, String, std::ops::Range<usize>)> = match ctx.arg("matches") {
        Some(Value::String(d)) if d == "detect" => detect_secrets(text)?,
        Some(Value::Array(a)) => {
            let mut out = Vec::new();
            for m in a {
                let span = m.get("span_utf16").and_then(Value::as_array);
                let (Some(idx), Some(len)) = (
                    span.and_then(|s| s.first()).and_then(Value::as_u64),
                    span.and_then(|s| s.get(1)).and_then(Value::as_u64),
                ) else {
                    return Some(Err(anyhow::anyhow!("matches[].span_utf16")));
                };
                let (idx, len) = (idx as usize, len as usize);
                // Out-of-range spans stay out of range in bytes (the masker skips them).
                let total = utf16_len(text);
                let start = if idx > total {
                    text.len() + 1
                } else {
                    utf16_to_byte(text, idx)
                };
                let end = if idx + len > total {
                    text.len() + 1
                } else {
                    utf16_to_byte(text, idx + len)
                };
                out.push((
                    s(m, "kind").to_owned(),
                    s(m, "masked").to_owned(),
                    start..end,
                ));
            }
            out
        }
        None => Vec::new(),
        Some(_) => return Some(Err(anyhow::anyhow!("args.matches"))),
    };
    let spans: Vec<MaskSpan<'_>> = owned
        .iter()
        .map(|(k, m, r)| MaskSpan {
            range: r.clone(),
            kind: mask_kind(k),
            masked: m,
        })
        .collect();
    let pem_mask = ctx.render(&Message::new("paste-pem-body-mask"));
    let out = paste::mask_text(text, &spans, &pem_mask);
    let redetected = if exp.has("redetect_empty") {
        Some(detect_secrets(&out)?.is_empty())
    } else {
        None
    };
    Some(check_masked(exp, &out, &pem_mask, redetected))
}

fn check_masked(
    exp: &mut Expect,
    out: &str,
    pem_mask: &str,
    redetected_empty: Option<bool>,
) -> Result<()> {
    if let Some(v) = take_text(exp, "output")?
        && v.as_str() != Some(out)
    {
        exp.fail(format!("expect.output: expected {v}, got {out:?}"));
    }
    for key in ["starts_with", "ends_with"] {
        if let Some(v) = take_text(exp, key)? {
            let e = v.as_str().unwrap_or_default();
            let ok = if key == "starts_with" {
                out.starts_with(e)
            } else {
                out.ends_with(e)
            };
            if !ok {
                exp.fail(format!("expect.{key}: {out:?} vs {e:?}"));
            }
        }
    }
    if let Some(v) = take_text(exp, "contains")? {
        for e in crate::check::strings(&v) {
            if !out.contains(&e) {
                exp.fail(format!("expect.contains: {out:?} lacks {e:?}"));
            }
        }
    }
    if let Some(v) = take_text(exp, "not_contains")? {
        for e in crate::check::strings(&v) {
            if out.contains(&e) {
                exp.fail(format!("expect.not_contains: {out:?} contains {e:?}"));
            }
        }
    }
    exp.eq("contains_pem_body_mask", out.contains(pem_mask));
    if let Some(empty) = redetected_empty {
        exp.eq("redetect_empty", empty);
    }
    Ok(())
}

// ---------------------------------------------------------------- limits

fn limits_prefix(ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    let p = limits::prefix(&ctx.input);
    if exp.has("analyze_level") {
        let v = analyze_command(p)?;
        exp.eq("analyze_level", v.level.as_str());
    }
    exp.eq("length_utf16", utf16_len(p));
    exp.eq("unchanged", p.len() == ctx.input.len());
    // A Rust &str never ends with a lone surrogate.
    exp.eq("ends_with_high_surrogate", false);
    Some(Ok(()))
}

// ---------------------------------------------------------------- registered

fn key_from_hex(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        bail!("key_hex must be an even number of hex digits");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("key_hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn registered_run(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let key = key_from_hex(ctx.arg_str("key_hex").context("args.key_hex")?)?;
    let mut store =
        RegisteredSecretStore::new(&key).map_err(|_| anyhow::anyhow!("bad HMAC key length"))?;
    let mut names: HashMap<String, u64> = HashMap::new();
    let untitled = ctx.render(&Message::new("registered-untitled"));
    let display = |label: &str| {
        if label.is_empty() {
            untitled.clone()
        } else {
            label.to_owned()
        }
    };

    for (i, ev) in ctx.events.iter().enumerate() {
        let now = ev.get("t_ms").and_then(Value::as_u64).unwrap_or(0);
        let mut sub = event_expect(ev)?;
        if let Some(a) = ev.get("add") {
            let label = a.get("label").and_then(Value::as_str);
            let secret = s(a, "secret");
            match store.add(label, secret, now) {
                Ok(e) => {
                    sub.eq("ok", true);
                    sub.eq("label", display(&e.label));
                    sub.eq("length_utf16", e.length);
                    sub.eq("hmac_hex", hex(&e.hmac));
                    sub.ne("hmac_hex_not", hex(&e.hmac));
                    if let Some(name) = ev.get("as").and_then(Value::as_str) {
                        names.insert(name.to_owned(), e.id);
                    }
                    if sub.take("error").is_some() {
                        sub.fail("expect.error: add succeeded");
                    }
                }
                Err(err) => {
                    sub.eq("ok", false);
                    sub.eq("error", err.as_str());
                    for k in ["label", "length_utf16", "hmac_hex", "hmac_hex_not"] {
                        if sub.take(k).is_some() {
                            sub.fail(format!("expect.{k}: add failed ({})", err.as_str()));
                        }
                    }
                }
            }
        } else if let Some(f) = ev.get("find") {
            let text = f.as_str().unwrap_or_default();
            let found = store.find(text);
            let items: Vec<Value> = found
                .iter()
                .map(|m| {
                    let start = byte_to_utf16(text, m.start);
                    json!({
                        "kind": "registered",
                        "label": display(&m.label),
                        "span_utf16": [start, byte_to_utf16(text, m.end) - start],
                        "masked": ctx.render(&m.masked()),
                    })
                })
                .collect();
            sub.list_exact("matches", &items);
            sub.eq("count", items.len());
            if let Some(v) = sub.take("masked_not_contain") {
                let v = resolve_all(&v)?;
                for e in crate::check::strings(&v) {
                    for m in &items {
                        if s(m, "masked").contains(&e) {
                            sub.fail(format!("expect.masked_not_contain: {m} contains {e:?}"));
                        }
                    }
                }
            }
        } else if let Some(r) = ev.get("remove") {
            let id = r.as_str().and_then(|n| names.get(n).copied());
            let removed = id.is_some_and(|id| store.remove(id));
            sub.eq("removed", removed);
        } else if ev.get("reopen").is_some() {
            store = RegisteredSecretStore::with_entries(&key, store.entries().to_vec())
                .map_err(|_| anyhow::anyhow!("bad HMAC key length"))?;
        } else {
            bail!("event {i} has no action");
        }
        sub.eq("entries_count", store.entries().len());
        exp.absorb(&format!("events[{i}]"), sub);
    }
    Ok(())
}

fn registered_validate(ctx: &Ctx<'_>, exp: &mut Expect) -> Result<()> {
    let secret = ctx.arg_str("secret").unwrap_or_default();
    let confirm = ctx.arg_str("confirm").unwrap_or_default();
    match registered::validate_registration(secret, confirm) {
        Ok(()) => {
            exp.eq("ok", true);
            for k in ["field", "message", "message_contain", "message_not_contain"] {
                if exp.take(k).is_some() {
                    exp.fail(format!("expect.{k}: validation passed"));
                }
            }
        }
        Err(e) => {
            let msg = ctx.render(&e.message);
            exp.eq("ok", false);
            exp.eq("field", e.field.as_str());
            exp.eq("message", msg.as_str());
            exp.text_contains("message_contain", &msg);
            exp.text_not_contains("message_not_contain", &msg);
        }
    }
    Ok(())
}
