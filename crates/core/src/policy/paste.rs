//! Paste guard, strict mode (legacy `PasteGuard`, `PasteGuardSettings`,
//! `PasteGuardSettingsStore` sanitizing, `ClipboardSecretSnapshot`;
//! detection-rules.md §5.3): should Ctrl+V / Shift+Insert be intercepted, the
//! "paste masked" text, and the Enter-swallowing window while the user decides.
//!
//! Secret detection is not done here: callers pass the kinds / matches found by
//! the secret detector and the registered-secret store.

use std::ops::Range;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::eq_ignore_case;
use super::windows::windows_rules;

/// Maximum number of user-allowlisted apps kept (legacy `MaxAllowedApps`).
pub const MAX_ALLOWED_APPS: usize = 100;
/// Maximum length of one allowlisted app name, in chars (legacy `MaxAppNameLength`,
/// UTF-16 units there; phase-1.md §1.8).
pub const MAX_APP_NAME_LENGTH: usize = 100;
/// How long a pending interception may swallow Enter (legacy `PendingTimeout`, 60 s).
pub const PENDING_TIMEOUT_MS: u64 = 60_000;
/// Replacement for a registered secret: fixed, no label, no length leak.
pub const REGISTERED_MASK: &str = "********";

/// Paste-guard settings. Holds no secret and no clipboard content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasteGuardSettings {
    /// Intercept when the clipboard holds a registered secret. Default on.
    pub intercept_registered: bool,
    /// Also intercept detected PII / API keys. Default off (phones and tax ids are
    /// often pasted on purpose).
    pub intercept_detected: bool,
    /// User-allowlisted process names (case-insensitive, `.exe` / path optional).
    pub allowed_apps: Vec<String>,
}

impl Default for PasteGuardSettings {
    fn default() -> Self {
        PasteGuardSettings {
            intercept_registered: true,
            intercept_detected: false,
            allowed_apps: Vec::new(),
        }
    }
}

/// The settings text could not be parsed (defaults are used instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsError {
    /// Parser detail; never contains clipboard content.
    pub detail: String,
}

impl PasteGuardSettings {
    /// Whether these settings can intercept anything at all; when not, the app does
    /// not install the keyboard hook.
    pub fn can_intercept(&self, has_registered_secrets: bool) -> bool {
        self.intercept_detected || (self.intercept_registered && has_registered_secrets)
    }

    /// Normalized copy: each app [`normalize_app_name`]d, empty and over-long
    /// names dropped, case-insensitive duplicates removed (first kept), at most
    /// [`MAX_ALLOWED_APPS`].
    pub fn sanitized(&self) -> PasteGuardSettings {
        let mut apps: Vec<String> = Vec::new();
        for a in &self.allowed_apps {
            if apps.len() >= MAX_ALLOWED_APPS {
                break;
            }
            let n = normalize_app_name(a);
            let len = n.chars().count();
            if len == 0 || len > MAX_APP_NAME_LENGTH {
                continue;
            }
            if apps.iter().any(|x| eq_ignore_case(x, &n)) {
                continue;
            }
            apps.push(n);
        }
        PasteGuardSettings {
            intercept_registered: self.intercept_registered,
            intercept_detected: self.intercept_detected,
            allowed_apps: apps,
        }
    }

    /// Parses a settings file (legacy `PasteGuardSettingsStore.Load`). `None` = no
    /// file: defaults, no error. Unparsable: defaults plus an error. Missing fields
    /// take their defaults; the result is [`sanitized`](Self::sanitized).
    ///
    /// Accepts the snake_case fields written by [`to_json`](Self::to_json) and the
    /// legacy PascalCase ones (`InterceptRegistered`, `InterceptDetected`, `AllowedApps`).
    pub fn from_json(file: Option<&str>) -> (PasteGuardSettings, Option<SettingsError>) {
        let Some(text) = file else {
            return (PasteGuardSettings::default(), None);
        };
        match parse_settings(text) {
            Ok(s) => (s.sanitized(), None),
            Err(detail) => (
                PasteGuardSettings::default(),
                Some(SettingsError { detail }),
            ),
        }
    }

    /// Serializes the [`sanitized`](Self::sanitized) settings (legacy `Save`).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.sanitized()).unwrap_or_else(|_| "{}".to_owned())
    }
}

fn parse_settings(text: &str) -> Result<PasteGuardSettings, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut s = PasteGuardSettings::default();
    let obj = match v {
        Value::Null => return Ok(s),
        Value::Object(m) => m,
        _ => return Err("settings must be a JSON object".to_owned()),
    };
    let get = |snake: &str, pascal: &str| {
        obj.get(snake)
            .or_else(|| obj.get(pascal))
            .filter(|v| !v.is_null())
    };
    let get_bool = |snake: &str, pascal: &str, default: bool| match get(snake, pascal) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{snake}: expected a boolean")),
    };
    s.intercept_registered = get_bool("intercept_registered", "InterceptRegistered", true)?;
    s.intercept_detected = get_bool("intercept_detected", "InterceptDetected", false)?;
    match get("allowed_apps", "AllowedApps") {
        None => {}
        Some(Value::Array(a)) => {
            s.allowed_apps = a
                .iter()
                .map(|x| match x {
                    Value::String(s) => Ok(s.clone()),
                    Value::Null => Ok(String::new()),
                    _ => Err("allowed_apps: expected strings".to_owned()),
                })
                .collect::<Result<_, _>>()?;
        }
        Some(_) => return Err("allowed_apps: expected an array".to_owned()),
    }
    Ok(s)
}

/// Strips whitespace, a directory path (up to the last `\` or `/`) and a trailing
/// `.exe` (any case), so `Signal.exe`, `C:\…\signal.exe` and `Signal` compare equal.
pub fn normalize_app_name(name: &str) -> String {
    let n = name.trim();
    let n = match n.rfind(['\\', '/']) {
        Some(i) => &n[i + 1..],
        None => n,
    };
    let len = n.len();
    let n = if len >= 4 && n.is_char_boundary(len - 4) && n[len - 4..].eq_ignore_ascii_case(".exe")
    {
        &n[..len - 4]
    } else {
        n
    };
    n.trim().to_owned()
}

/// Where the paste goes: the foreground window's process and class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasteTarget<'a> {
    pub process: &'a str,
    pub class: &'a str,
    /// One of PasteWarden's own windows (confirmation, registration): always allowed.
    pub own: bool,
}

/// Paste decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteDecision {
    Allow,
    /// Swallow the keystroke and ask the user first.
    Intercept,
}

impl PasteDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            PasteDecision::Allow => "allow",
            PasteDecision::Intercept => "intercept",
        }
    }
}

/// What the clipboard's secret summary contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PasteSecrets {
    /// A registered secret (kind `registered`).
    pub registered: bool,
    /// Any detected secret of another kind (PII, API key…).
    pub detected: bool,
}

impl PasteSecrets {
    /// From snake_case kind names (`registered`, `credit_card`, `api_key`…).
    pub fn from_kinds<'a>(kinds: impl IntoIterator<Item = &'a str>) -> Self {
        let mut s = PasteSecrets::default();
        for k in kinds {
            if k == "registered" {
                s.registered = true;
            } else {
                s.detected = true;
            }
        }
        s
    }
}

/// Is the target allowlisted (own window, credential dialog class, built-in or
/// user-allowlisted process; exact normalized name, not a substring)?
pub fn is_allowed(target: &PasteTarget<'_>, settings: &PasteGuardSettings) -> bool {
    if target.own {
        return true;
    }
    let rules = &windows_rules().paste;
    if rules
        .allowed_window_classes
        .iter()
        .any(|c| c == target.class)
    {
        return true;
    }
    let name = normalize_app_name(target.process);
    if name.is_empty() {
        // An unknown process name is never assumed to be allowlisted.
        return false;
    }
    rules
        .allowed_apps
        .iter()
        .chain(&settings.allowed_apps)
        .any(|a| eq_ignore_case(&normalize_app_name(a), &name))
}

/// Whether to intercept a paste (legacy `PasteGuard.Decide`).
pub fn decide(
    secrets: PasteSecrets,
    target: &PasteTarget<'_>,
    settings: &PasteGuardSettings,
) -> PasteDecision {
    if !(secrets.registered || secrets.detected) || target.own {
        return PasteDecision::Allow;
    }
    let applies = (settings.intercept_registered && secrets.registered)
        || (settings.intercept_detected && secrets.detected);
    if !applies || is_allowed(target, settings) {
        PasteDecision::Allow
    } else {
        PasteDecision::Intercept
    }
}

/// One secret summary: no position, no original text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSummary<K> {
    pub kind: K,
    pub label: String,
    pub masked: String,
}

/// "This clipboard holds secrets" summary (legacy `ClipboardSecretSnapshot`):
/// kinds, labels, masks and the clipboard sequence number only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardSecretSnapshot<K> {
    /// Clipboard sequence number when the snapshot was taken (stale check).
    pub sequence: u32,
    pub secrets: Vec<SecretSummary<K>>,
}

impl<K: Clone + PartialEq> ClipboardSecretSnapshot<K> {
    pub fn new(sequence: u32, secrets: Vec<SecretSummary<K>>) -> Self {
        ClipboardSecretSnapshot { sequence, secrets }
    }

    /// Distinct kinds in first-seen order.
    pub fn kinds(&self) -> Vec<K> {
        let mut out: Vec<K> = Vec::new();
        for s in &self.secrets {
            if !out.contains(&s.kind) {
                out.push(s.kind.clone());
            }
        }
        out
    }
}

/// How a match is replaced by [`mask_text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskKind {
    /// Registered secret: replaced by [`REGISTERED_MASK`].
    Registered,
    /// API key: a PEM private-key header masks everything up to the `-----END ` line.
    ApiKey,
    /// Any other detected secret: replaced by its mask.
    Other,
}

/// One secret to mask: byte range in the text plus its mask string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskSpan<'a> {
    pub range: Range<usize>,
    pub kind: MaskKind,
    pub masked: &'a str,
}

fn is_pem_header(m: &MaskSpan<'_>) -> bool {
    m.kind == MaskKind::ApiKey
        && m.masked.starts_with("-----BEGIN ")
        && m.masked.ends_with("PRIVATE KEY-----")
}

/// Replaces every match with its mask ("paste masked"; legacy `PasteGuard.MaskText`).
///
/// Matches are applied in start order (stable); a match overlapping the previous
/// one, out of range, or not on char boundaries is skipped. A PEM private-key
/// header is followed by `\n{pem_body_mask}\n` and masks the text up to the next
/// `-----END ` (or the end). `pem_body_mask` is the localized
/// `paste-pem-body-mask` message, rendered by the caller.
pub fn mask_text(text: &str, matches: &[MaskSpan<'_>], pem_body_mask: &str) -> String {
    let mut sorted: Vec<&MaskSpan<'_>> = matches.iter().collect();
    sorted.sort_by_key(|m| m.range.start);
    let mut out = String::with_capacity(text.len());
    let mut pos = 0usize;
    for m in sorted {
        let Range { start, end } = m.range;
        if start < pos || end < start || text.get(start..end).is_none() {
            continue;
        }
        out.push_str(text.get(pos..start).unwrap_or_default());
        pos = end;
        match m.kind {
            MaskKind::Registered => out.push_str(REGISTERED_MASK),
            _ if is_pem_header(m) => {
                out.push_str(m.masked);
                out.push('\n');
                out.push_str(pem_body_mask);
                out.push('\n');
                pos = text
                    .get(pos..)
                    .and_then(|rest| rest.find("-----END "))
                    .map_or(text.len(), |i| pos + i);
            }
            _ => out.push_str(m.masked),
        }
    }
    out.push_str(text.get(pos..).unwrap_or_default());
    out
}

/// Whether to swallow Enter while an intercepted paste awaits the user's decision
/// (legacy `PasteGuard.ShouldSwallowEnter`). Only Enter sent to the paste target's
/// root window is swallowed, for at most [`PENDING_TIMEOUT_MS`].
pub fn should_swallow_enter(
    pending: bool,
    pending_for_ms: u64,
    foreground_root: u64,
    target_root: u64,
    foreground_is_own: bool,
) -> bool {
    pending
        && pending_for_ms < PENDING_TIMEOUT_MS
        && !foreground_is_own
        && target_root != 0
        && foreground_root == target_root
}

/// Tracks the pending interception for [`should_swallow_enter`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingPaste {
    /// (intercepted at, target root window).
    pending: Option<(u64, u64)>,
}

impl PendingPaste {
    pub fn new() -> Self {
        Self::default()
    }

    /// A paste to `target_root` (`0` = unknown) was intercepted at `now_ms`.
    pub fn intercept(&mut self, now_ms: u64, target_root: u64) {
        self.pending = Some((now_ms, target_root));
    }

    /// The user decided (or cancelled).
    pub fn resolve(&mut self) {
        self.pending = None;
    }

    pub fn should_swallow_enter(
        &self,
        now_ms: u64,
        foreground_root: u64,
        foreground_is_own: bool,
    ) -> bool {
        match self.pending {
            None => false,
            Some((since, target_root)) => should_swallow_enter(
                true,
                now_ms.saturating_sub(since),
                foreground_root,
                target_root,
                foreground_is_own,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_app_names() {
        assert_eq!(normalize_app_name("signal.EXE"), "signal");
        assert_eq!(normalize_app_name("C:\\x\\y\\App.exe"), "App");
        assert_eq!(normalize_app_name("/usr/bin/x"), "x");
        assert_eq!(normalize_app_name("   "), "");
        assert_eq!(normalize_app_name("中文é"), "中文é");
    }

    #[test]
    fn decides() {
        let s = PasteGuardSettings::default();
        let t = PasteTarget {
            process: "Discord",
            class: "Chrome_WidgetWin_1",
            own: false,
        };
        let reg = PasteSecrets::from_kinds(["registered"]);
        let card = PasteSecrets::from_kinds(["credit_card"]);
        assert_eq!(decide(reg, &t, &s), PasteDecision::Intercept);
        assert_eq!(decide(card, &t, &s), PasteDecision::Allow);
        let kp = PasteTarget {
            process: "KeePassXC.exe",
            ..t
        };
        assert_eq!(decide(reg, &kp, &s), PasteDecision::Allow);
        let fake = PasteTarget {
            process: "KeePassFake",
            ..t
        };
        assert_eq!(decide(reg, &fake, &s), PasteDecision::Intercept);
    }

    #[test]
    fn masks_text() {
        let text = "12345678";
        let m = [
            MaskSpan {
                range: 2..6,
                kind: MaskKind::Other,
                masked: "BBB",
            },
            MaskSpan {
                range: 0..4,
                kind: MaskKind::Other,
                masked: "AAA",
            },
            MaskSpan {
                range: 8..18,
                kind: MaskKind::Other,
                masked: "CCC",
            },
        ];
        assert_eq!(mask_text(text, &m, "x"), "AAA5678");
        // Not on a char boundary: skipped, no panic.
        let m = [MaskSpan {
            range: 1..2,
            kind: MaskKind::Registered,
            masked: "",
        }];
        assert_eq!(mask_text("中", &m, "x"), "中");
        let pem = "-----BEGIN RSA PRIVATE KEY-----";
        let text = format!("k\n{pem}\nSECRET\n-----END RSA PRIVATE KEY-----\n");
        let m = [MaskSpan {
            range: 2..2 + pem.len(),
            kind: MaskKind::ApiKey,
            masked: pem,
        }];
        let out = mask_text(&text, &m, "(masked)");
        assert!(!out.contains("SECRET"));
        assert!(out.contains("(masked)\n-----END"));
    }

    #[test]
    fn settings_round_trip() {
        let (s, e) = PasteGuardSettings::from_json(Some("{ not json"));
        assert!(e.is_some());
        assert_eq!(s, PasteGuardSettings::default());
        let (s, e) = PasteGuardSettings::from_json(Some(r#"{"InterceptDetected": true}"#));
        assert!(e.is_none() && s.intercept_detected && s.intercept_registered);
        let s = PasteGuardSettings {
            intercept_registered: false,
            intercept_detected: true,
            allowed_apps: vec!["Signal.exe".into(), "signal".into(), " ".into()],
        };
        let (back, e) = PasteGuardSettings::from_json(Some(&s.to_json()));
        assert!(e.is_none());
        assert_eq!(back.allowed_apps, vec!["Signal".to_owned()]);
        assert!(!back.intercept_registered);
    }

    #[test]
    fn enter_swallowing() {
        let mut p = PendingPaste::new();
        assert!(!p.should_swallow_enter(0, 100, false));
        p.intercept(0, 100);
        assert!(p.should_swallow_enter(59_999, 100, false));
        assert!(!p.should_swallow_enter(60_000, 100, false));
        assert!(!p.should_swallow_enter(10, 200, false));
        p.resolve();
        assert!(!p.should_swallow_enter(10, 100, false));
    }
}
