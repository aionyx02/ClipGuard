//! LLM configuration. [`LlmConfig::Disabled`] is the default and carries
//! nothing: a [`crate::Client`] can only be built from an [`EnabledConfig`],
//! so with AI off there is no code path that opens a connection.

use std::net::{Ipv4Addr, Ipv6Addr};

use zeroize::Zeroizing;

/// Anthropic API base URL used when the config gives none.
pub const ANTHROPIC_DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Whether Tier 2 is on. The default is [`LlmConfig::Disabled`].
#[derive(Debug, Default)]
pub enum LlmConfig {
    #[default]
    Disabled,
    Enabled(EnabledConfig),
}

impl LlmConfig {
    /// The enabled config, if any. This is the only way from an [`LlmConfig`]
    /// to something a [`crate::Client`] can be built from.
    pub fn enabled(self) -> Option<EnabledConfig> {
        match self {
            LlmConfig::Disabled => None,
            LlmConfig::Enabled(c) => Some(c),
        }
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, LlmConfig::Enabled(_))
    }
}

/// Which API dialect to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// `POST {base_url}/chat/completions` (OpenAI, Ollama, LM Studio, OpenRouter, …).
    OpenAiCompatible,
    /// `POST {base_url}/v1/messages`.
    Anthropic,
}

impl ProviderKind {
    /// snake_case name used in the config file, the Report JSON and audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::OpenAiCompatible => "openai_compatible",
            ProviderKind::Anthropic => "anthropic",
        }
    }
}

/// Why a config was rejected. Never contains the API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// `base_url` is missing (required for OpenAI-compatible endpoints).
    MissingBaseUrl,
    /// `base_url` is not `http(s)://host[:port][/path]`.
    InvalidBaseUrl,
    /// `base_url` carries `user:password@`; rejected (it also hides the real host).
    UserInfoInBaseUrl,
    /// Plain `http://` to a host that is not loopback: the API key and the
    /// text would travel unencrypted.
    InsecureScheme,
    /// `model` is empty or too long.
    InvalidModel,
}

impl ConfigError {
    pub fn code(self) -> &'static str {
        match self {
            ConfigError::MissingBaseUrl => "missing_base_url",
            ConfigError::InvalidBaseUrl => "invalid_base_url",
            ConfigError::UserInfoInBaseUrl => "userinfo_in_base_url",
            ConfigError::InsecureScheme => "insecure_scheme",
            ConfigError::InvalidModel => "invalid_model",
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ConfigError {}

/// Longest accepted model name.
pub const MAX_MODEL_CHARS: usize = 200;

/// A validated, enabled configuration.
pub struct EnabledConfig {
    provider: ProviderKind,
    /// Without a trailing `/`.
    base_url: String,
    host: String,
    model: String,
    api_key: Option<Zeroizing<String>>,
    local: bool,
    only_high_risk: bool,
}

impl std::fmt::Debug for EnabledConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnabledConfig")
            .field("provider", &self.provider)
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("local", &self.local)
            .field("only_high_risk", &self.only_high_risk)
            .finish()
    }
}

/// Inputs of [`EnabledConfig::new`]. The API key comes from the caller (the
/// CLI reads the environment variable the config names); this crate reads no
/// environment variables.
#[derive(Default)]
pub struct EnabledConfigInput {
    pub provider: Option<ProviderKind>,
    pub base_url: Option<String>,
    pub model: String,
    pub api_key: Option<Zeroizing<String>>,
    /// The user says the endpoint runs on this machine. Only counts when the
    /// host really is loopback (guardrail ①).
    pub local: bool,
    /// Only ask the model when Tier 1 already found a suspicious or malicious command.
    pub only_high_risk: bool,
}

impl EnabledConfig {
    pub fn new(input: EnabledConfigInput) -> Result<EnabledConfig, ConfigError> {
        let provider = input.provider.unwrap_or(ProviderKind::OpenAiCompatible);
        let base_url = match (input.base_url, provider) {
            (Some(u), _) if !u.trim().is_empty() => u.trim().trim_end_matches('/').to_owned(),
            (_, ProviderKind::Anthropic) => ANTHROPIC_DEFAULT_BASE_URL.to_owned(),
            (_, ProviderKind::OpenAiCompatible) => return Err(ConfigError::MissingBaseUrl),
        };
        let (https, host) = parse_base_url(&base_url)?;
        if !https && !host_is_loopback(&host) {
            return Err(ConfigError::InsecureScheme);
        }
        let model = input.model.trim().to_owned();
        if model.is_empty()
            || model.chars().count() > MAX_MODEL_CHARS
            || model.chars().any(char::is_control)
        {
            return Err(ConfigError::InvalidModel);
        }
        Ok(EnabledConfig {
            provider,
            base_url,
            host,
            model,
            api_key: input.api_key.filter(|k| !k.is_empty()),
            local: input.local,
            only_high_risk: input.only_high_risk,
        })
    }

    pub fn provider(&self) -> ProviderKind {
        self.provider
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn only_high_risk(&self) -> bool {
        self.only_high_risk
    }

    pub(crate) fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref().map(String::as_str)
    }

    /// Guardrail ①: the endpoint counts as local only when the user said so
    /// **and** the host is loopback (127.0.0.0/8, ::1, `localhost`).
    pub fn is_local(&self) -> bool {
        self.local && host_is_loopback(&self.host)
    }
}

/// Splits `scheme://authority/path`; returns (is https, lowercase host).
fn parse_base_url(url: &str) -> Result<(bool, String), ConfigError> {
    let (https, rest) = if let Some(r) = strip_prefix_ci(url, "https://") {
        (true, r)
    } else if let Some(r) = strip_prefix_ci(url, "http://") {
        (false, r)
    } else {
        return Err(ConfigError::InvalidBaseUrl);
    };
    if url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return Err(ConfigError::InvalidBaseUrl);
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if rest[end..].starts_with(['?', '#']) {
        return Err(ConfigError::InvalidBaseUrl);
    }
    let authority = &rest[..end];
    if authority.contains('@') {
        return Err(ConfigError::UserInfoInBaseUrl);
    }
    let host = if let Some(v6) = authority.strip_prefix('[') {
        let close = v6.find(']').ok_or(ConfigError::InvalidBaseUrl)?;
        let after = &v6[close + 1..];
        if !(after.is_empty() || is_port(after)) {
            return Err(ConfigError::InvalidBaseUrl);
        }
        let h = &v6[..close];
        h.parse::<Ipv6Addr>()
            .map_err(|_| ConfigError::InvalidBaseUrl)?;
        h
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if is_port(&format!(":{p}")) => h,
            Some(_) => return Err(ConfigError::InvalidBaseUrl),
            None => authority,
        }
    };
    if host.is_empty() {
        return Err(ConfigError::InvalidBaseUrl);
    }
    Ok((https, host.to_ascii_lowercase()))
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// `:<1–5 digits>`.
fn is_port(s: &str) -> bool {
    s.strip_prefix(':')
        .is_some_and(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// 127.0.0.0/8, ::1 (also `[::1]`), `localhost`.
pub fn host_is_loopback(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = h.parse::<Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = h.parse::<Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str, local: bool) -> Result<EnabledConfig, ConfigError> {
        EnabledConfig::new(EnabledConfigInput {
            base_url: Some(url.into()),
            model: "m".into(),
            local,
            ..Default::default()
        })
    }

    #[test]
    fn disabled_is_the_default_and_yields_no_config() {
        assert!(!LlmConfig::default().is_enabled());
        assert!(LlmConfig::default().enabled().is_none());
    }

    #[test]
    fn local_needs_the_flag_and_a_loopback_host() {
        for url in [
            "http://127.0.0.1:11434/v1",
            "http://127.9.8.7/v1",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://[::1]:11434/v1",
        ] {
            assert!(cfg(url, true).unwrap().is_local(), "{url}");
            assert!(!cfg(url, false).unwrap().is_local(), "{url}");
        }
        for url in [
            "https://api.example.invalid/v1",
            "https://127.0.0.1.example.invalid/v1",
            "https://localhost.example.invalid",
            "https://10.0.0.1/v1",
            "https://[::2]/v1",
        ] {
            assert!(!cfg(url, true).unwrap().is_local(), "{url}");
        }
    }

    #[test]
    fn bad_urls_are_rejected() {
        assert_eq!(
            cfg("http://127.0.0.1@evil.example.invalid/v1", true).unwrap_err(),
            ConfigError::UserInfoInBaseUrl
        );
        assert_eq!(
            cfg("http://api.example.invalid/v1", false).unwrap_err(),
            ConfigError::InsecureScheme
        );
        for url in [
            "ftp://x",
            "127.0.0.1",
            "http://",
            "http://a b",
            "http://[::1",
            "http://h:99999999",
            "http://h?x",
        ] {
            assert!(cfg(url, true).is_err(), "{url}");
        }
        assert_eq!(
            EnabledConfig::new(EnabledConfigInput {
                model: "m".into(),
                ..Default::default()
            })
            .unwrap_err(),
            ConfigError::MissingBaseUrl
        );
        let anthropic = EnabledConfig::new(EnabledConfigInput {
            provider: Some(ProviderKind::Anthropic),
            model: "m".into(),
            local: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(anthropic.base_url(), ANTHROPIC_DEFAULT_BASE_URL);
        assert!(!anthropic.is_local());
    }

    #[test]
    fn debug_never_shows_the_key() {
        let c = EnabledConfig::new(EnabledConfigInput {
            base_url: Some("http://127.0.0.1".into()),
            model: "m".into(),
            api_key: Some(Zeroizing::new("sk-very-secret-value".into())),
            ..Default::default()
        })
        .unwrap();
        assert!(!format!("{c:?}").contains("very-secret"));
    }
}
