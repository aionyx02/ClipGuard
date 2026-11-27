//! Audit records: one per [`crate::Client`] call. They hold provider, model,
//! the guardrail decision, the duration and a result code — **never** the
//! prompt, the text or the model's answer.

use std::time::Duration;

use crate::ProviderKind;

/// What guardrail ① (and `only_high_risk`) decided before any request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardrailDecision {
    /// A request was sent.
    Sent,
    /// Tier 1 found secrets and the endpoint is not local: nothing was sent.
    RefusedSecretsPresent,
    /// `only_high_risk` and Tier 1 found no suspicious command: nothing was sent.
    SkippedNotHighRisk,
}

impl GuardrailDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            GuardrailDecision::Sent => "sent",
            GuardrailDecision::RefusedSecretsPresent => "refused_secrets_present",
            GuardrailDecision::SkippedNotHighRisk => "skipped_not_high_risk",
        }
    }
}

/// One audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub provider: ProviderKind,
    pub model: String,
    pub guardrail: GuardrailDecision,
    pub duration: Duration,
    /// `ok` or an [`crate::LlmError::code`].
    pub result: &'static str,
}

/// Receives audit records.
pub trait AuditSink {
    fn record(&mut self, record: &AuditRecord);
}

/// Drops every record.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAudit;

impl AuditSink for NoAudit {
    fn record(&mut self, _: &AuditRecord) {}
}

/// Keeps records in memory (tests, the desktop app's session view).
#[derive(Debug, Default, Clone)]
pub struct MemoryAudit(pub Vec<AuditRecord>);

impl AuditSink for MemoryAudit {
    fn record(&mut self, record: &AuditRecord) {
        self.0.push(record.clone());
    }
}
