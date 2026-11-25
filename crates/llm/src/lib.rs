//! Optional Tier 2: LLM explanations (OpenAI-compatible, Anthropic) with the
//! five CLAUDE.md guardrails enforced in code (docs/plan/phase-5.md §5.6).
//!
//! Off by default: [`LlmConfig::Disabled`] carries nothing and a [`Client`]
//! can only be built from an [`EnabledConfig`], so with AI off no code path
//! can open a connection. The HTTP client lives behind the `net` feature;
//! this crate reads no environment variables (the caller passes the API key).
//!
//! | Guardrail | Where |
//! |---|---|
//! | ① no secrets to the cloud | [`Client::explain`] refuses before building a request; [`Tier1Input`] only holds masked text |
//! | ② untrusted content wrapped | [`prompt::wrap_untrusted`] (`&`, `<`, `>` escaped) |
//! | ③ output validated | [`output::parse_output`] (strict serde + limits), schema from `schemars` |
//! | ④ only raise | [`merge`], [`merge_action`] |
//! | ⑤ no tools, timeout | no `tools`/`tool_choice` in requests; tool calls in responses → [`LlmError::ToolCalls`]; [`LLM_TIMEOUT_MS`], [`LLM_MAX_OUTPUT_TOKENS`], [`LLM_MAX_RESPONSE_BYTES`] |
//!
//! Audit: every call records one [`AuditRecord`] (provider, model,
//! guardrail decision, duration, result code) and never any content.
#![forbid(unsafe_code)]

pub mod audit;
mod client;
pub mod config;
mod merge;
pub mod output;
pub mod prompt;
pub mod transport;

pub use audit::{AuditRecord, AuditSink, GuardrailDecision, MemoryAudit, NoAudit};
pub use client::{Client, Explanation, LlmError};
pub use config::{ConfigError, EnabledConfig, EnabledConfigInput, LlmConfig, ProviderKind};
pub use merge::{merge, merge_action};
pub use output::{LlmLevel, LlmOutput, OutputError, Technique};
pub use prompt::Tier1Input;
#[cfg(feature = "net")]
pub use transport::UreqTransport;
pub use transport::{HttpRequest, HttpResponse, Transport, TransportError};

/// Connect + read timeout of one request (phase-5.md §5.9).
pub const LLM_TIMEOUT_MS: u64 = 20_000;
/// `max_tokens` of every request (§5.9).
pub const LLM_MAX_OUTPUT_TOKENS: u32 = 512;
/// Longest accepted `explanation`, in chars (§5.9).
pub const LLM_MAX_EXPLANATION_CHARS: usize = 600;
/// Most `techniques` entries accepted.
pub const LLM_MAX_TECHNIQUES: usize = 8;
/// Largest response body read; anything larger is discarded.
pub const LLM_MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Longest masked text sent, in chars (the rest is cut and the model is told).
pub const LLM_MAX_PAYLOAD_CHARS: usize = 8_000;
/// `anthropic-version` header.
pub const ANTHROPIC_VERSION: &str = "2026-10-21";
