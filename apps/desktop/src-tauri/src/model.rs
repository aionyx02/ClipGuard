//! Data shared by the worker, the Tauri commands and the UI (docs/plan/phase-4.md
//! §4.3). The `*Payload` types are the JSON contract with the React frontend
//! (camelCase); change them only together with `apps/desktop/src`.
//!
//! Like core, nothing here produces human-readable text: notifications carry
//! Fluent [`Message`]s that the UI layer renders.

use std::collections::BTreeMap;

use paste_warden_core::Message;
use paste_warden_core::policy::paste::PasteGuardSettings;
use paste_warden_core::policy::throttle::NotificationLevel;
use paste_warden_platform::status::{Capability, ProtectionStatus, TrayState};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Persisted app settings (`settings.json`; paste-guard settings and registered
// secrets are stored separately, §4.3 store.rs)

/// UI language preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LocalePref {
    #[default]
    #[serde(rename = "system")]
    System,
    #[serde(rename = "zh-TW")]
    ZhTw,
    #[serde(rename = "en")]
    En,
}

impl LocalePref {
    pub fn as_str(self) -> &'static str {
        match self {
            LocalePref::System => "system",
            LocalePref::ZhTw => "zh-TW",
            LocalePref::En => "en",
        }
    }

    /// Exact match only (arguments are re-validated in Rust).
    pub fn parse(s: &str) -> Option<LocalePref> {
        match s {
            "system" => Some(LocalePref::System),
            "zh-TW" => Some(LocalePref::ZhTw),
            "en" => Some(LocalePref::En),
            _ => None,
        }
    }
}

/// Theme preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemePref {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePref {
    pub fn as_str(self) -> &'static str {
        match self {
            ThemePref::System => "system",
            ThemePref::Light => "light",
            ThemePref::Dark => "dark",
        }
    }

    pub fn parse(s: &str) -> Option<ThemePref> {
        match s {
            "system" => Some(ThemePref::System),
            "light" => Some(ThemePref::Light),
            "dark" => Some(ThemePref::Dark),
            _ => None,
        }
    }
}

/// `settings.json`. Unknown or missing fields take the defaults (strict engine
/// profile, AI off).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct AppSettings {
    pub locale: LocalePref,
    pub theme: ThemePref,
    pub onboarding_done: bool,
    /// App version of the last run (macOS re-authorization after an update,
    /// §4.9.1).
    pub last_version: Option<String>,
    pub engine: paste_warden_core::Settings,
}

/// `"windows"`, `"macos"` or `"linux"` (settings payload).
pub fn platform_id() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

// ---------------------------------------------------------------------------
// JSON contract with the frontend

/// One protection area.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityPayload {
    pub state: &'static str,
    pub reason: Option<&'static str>,
}

impl From<Capability> for CapabilityPayload {
    fn from(c: Capability) -> Self {
        CapabilityPayload {
            state: c.state_id(),
            reason: c.reason().map(|r| r.id()),
        }
    }
}

/// `get_protection_status` / event `protection-status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusPayload {
    pub watch: CapabilityPayload,
    pub write: CapabilityPayload,
    pub foreground: CapabilityPayload,
    pub intercept: CapabilityPayload,
    pub tray: &'static str,
}

pub fn tray_id(t: TrayState) -> &'static str {
    match t {
        TrayState::Normal => "normal",
        TrayState::Degraded => "degraded",
        TrayState::Failed => "failed",
    }
}

impl From<&ProtectionStatus> for StatusPayload {
    fn from(s: &ProtectionStatus) -> Self {
        StatusPayload {
            watch: s.watch.into(),
            write: s.write.into(),
            foreground: s.foreground.into(),
            intercept: s.intercept.into(),
            tray: tray_id(s.tray_state()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasteGuardPayload {
    pub registered: bool,
    pub detected: bool,
    pub allowlist: Vec<String>,
}

/// `get_settings` / event `settings-changed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPayload {
    pub locale: &'static str,
    pub theme: &'static str,
    pub paste_guard: PasteGuardPayload,
    pub onboarding_done: bool,
    pub platform: &'static str,
    pub version_changed: bool,
}

impl SettingsPayload {
    pub fn new(app: &AppSettings, paste: &PasteGuardSettings, version_changed: bool) -> Self {
        SettingsPayload {
            locale: app.locale.as_str(),
            theme: app.theme.as_str(),
            paste_guard: PasteGuardPayload {
                registered: paste.intercept_registered,
                detected: paste.intercept_detected,
                allowlist: paste.allowed_apps.clone(),
            },
            onboarding_done: app.onboarding_done,
            platform: platform_id(),
            version_changed,
        }
    }
}

/// Event `paste-confirm` (shown in the `confirm` window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmPayload {
    /// Fluent ids `ui-desktop-kind-*`, one per distinct secret kind.
    pub kinds: Vec<String>,
    /// Masked clipboard text, at most `CONFIRM_PREVIEW_MAX_CHARS` chars.
    pub masked_preview: String,
    pub target_name: Option<String>,
}

/// One row of `list_secrets` (never the secret or its HMAC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretInfo {
    pub id: String,
    pub label: String,
    pub length: usize,
    pub created_at_ms: u64,
}

/// `register_secret` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredId {
    pub id: String,
}

/// Every command error: a Fluent id, the offending field and (an addition to
/// the §4.3 contract) the message's arguments, never the input itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    pub message_id: String,
    pub field: Option<&'static str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, serde_json::Value>,
}

impl CommandError {
    pub fn new(message_id: &'static str) -> Self {
        CommandError {
            message_id: message_id.to_owned(),
            field: None,
            args: BTreeMap::new(),
        }
    }

    pub fn field(mut self, field: &'static str) -> Self {
        self.field = Some(field);
        self
    }

    /// From a core message (id + args).
    pub fn from_message(m: &Message, field: Option<&'static str>) -> Self {
        let args = m
            .args
            .iter()
            .map(|(k, v)| {
                let v = match v {
                    paste_warden_core::Arg::Str(s) => serde_json::Value::from(s.as_str()),
                    paste_warden_core::Arg::Num(n) => serde_json::Value::from(*n),
                };
                (k.to_string(), v)
            })
            .collect();
        CommandError {
            message_id: m.id.to_string(),
            field,
            args,
        }
    }
}

pub type CmdResult<T> = Result<T, CommandError>;

// ---------------------------------------------------------------------------
// Notifications

/// One line of a notification: rendered by the UI layer with Fluent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Msg(Message),
    /// A message whose arguments are themselves messages (rendered first).
    Nested(Message, Vec<(&'static str, Message)>),
    /// Already-masked text (secret masks, `U+XXXX`); never clipboard text.
    Masked(String),
}

/// A notification: severity, title and body lines (§2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub level: NotificationLevel,
    pub title: Line,
    pub body: Vec<Line>,
}

/// Where the tray menu points the settings window (event `navigate`, an
/// addition to the §4.3 contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Section {
    General,
    RegisterSecret,
    Secrets,
    Allowlist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatePayload {
    pub section: Section,
}

/// Everything `pw-work` asks the UI (main thread) to do. Implemented with
/// Tauri in `ui.rs` and recorded in tests.
pub trait UiSink: Send {
    fn status_changed(&mut self, status: &ProtectionStatus);
    fn settings_changed(&mut self, settings: &SettingsPayload);
    fn notify(&mut self, notice: &Notice);
    fn open_confirm(&mut self, payload: &ConfirmPayload);
    fn close_confirm(&mut self);
    /// The tray's "restore" item is enabled.
    fn restore_available(&mut self, available: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use paste_warden_platform::status::Reason;

    #[test]
    fn status_payload_shape() {
        let s = ProtectionStatus {
            intercept: Capability::Degraded(Reason::HookLost),
            ..Default::default()
        };
        let v = serde_json::to_value(StatusPayload::from(&s)).unwrap();
        assert_eq!(v["intercept"]["state"], "degraded");
        assert_eq!(v["intercept"]["reason"], "hook-lost");
        assert_eq!(v["watch"]["reason"], serde_json::Value::Null);
        assert_eq!(v["tray"], "degraded");
    }

    #[test]
    fn settings_payload_shape() {
        let p = SettingsPayload::new(
            &AppSettings::default(),
            &PasteGuardSettings::default(),
            true,
        );
        let v = serde_json::to_value(p).unwrap();
        assert_eq!(v["locale"], "system");
        assert_eq!(v["theme"], "system");
        assert_eq!(v["pasteGuard"]["registered"], true);
        assert_eq!(v["pasteGuard"]["allowlist"], serde_json::json!([]));
        assert_eq!(v["onboardingDone"], false);
        assert_eq!(v["versionChanged"], true);
        assert!(v["platform"].is_string());
    }

    #[test]
    fn prefs_round_trip() {
        for s in ["system", "zh-TW", "en"] {
            assert_eq!(LocalePref::parse(s).unwrap().as_str(), s);
        }
        assert!(LocalePref::parse("zh-tw").is_none());
        for s in ["system", "light", "dark"] {
            assert_eq!(ThemePref::parse(s).unwrap().as_str(), s);
        }
        let a: AppSettings = serde_json::from_str(r#"{"locale":"zh-TW"}"#).unwrap();
        assert_eq!(a.locale, LocalePref::ZhTw);
        assert!(a.engine.block_malicious_commands);
    }

    #[test]
    fn error_shape() {
        let e = CommandError::new("ui-desktop-error-x").field("secret");
        let v = serde_json::to_value(e).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"messageId":"ui-desktop-error-x","field":"secret"})
        );
    }
}
