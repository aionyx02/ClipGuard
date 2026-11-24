//! PII and API-key detection, masking, packs and checksums (legacy `SecretDetector`,
//! `SecretRules`, `SecretTextNormalizer`, `Checksums`, `SecretMasker`, `SecretPacks`,
//! `PiiFormats`). Behavior spec: docs/spec/detection-rules.md §5.
//!
//! Entry points:
//! - [`find`]: secrets in a text with the built-in rules and the given [`PackSet`].
//! - [`mask_text`]: "paste masked" version of a text.
//! - [`mask_value`]: `A12****789` masking of a single value.
//! - [`checksum`]: check-digit validators; [`packs`]: pack selection.
//!
//! Spans are UTF-8 byte ranges into the original (un-normalized) text. Lengths and
//! masking count chars (legacy counted UTF-16 code units; phase-1 §1.8).

pub mod checksum;
pub mod engine;
pub mod mask;
pub mod normalize;
pub mod packs;
pub mod pii;

use std::ops::Range;

use paste_warden_rules::secret::RuleKind;

use crate::Message;

pub use engine::{MAX_SCAN_LENGTH, RULE_LABEL_ID, RuleSet, rule_label};
pub use mask::{
    MAX_STARS, MIN_HIDDEN, PEM_BODY_MASK_ID, mask_text, mask_value, pem_body_mask_message,
};
pub use packs::PackSet;

/// What kind of secret a match is (legacy `SecretKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    NationalId,
    ResidentCertificate,
    BusinessId,
    CreditCard,
    MobilePhone,
    ApiKey,
    /// A secret the user registered (HMAC match; see `policy`).
    Registered,
    /// International phone number.
    PhoneNumber,
    /// Bank account (IBAN).
    BankAccount,
}

impl SecretKind {
    /// snake_case name used by the corpus and settings.
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::NationalId => "national_id",
            SecretKind::ResidentCertificate => "resident_certificate",
            SecretKind::BusinessId => "business_id",
            SecretKind::CreditCard => "credit_card",
            SecretKind::MobilePhone => "mobile_phone",
            SecretKind::ApiKey => "api_key",
            SecretKind::Registered => "registered",
            SecretKind::PhoneNumber => "phone_number",
            SecretKind::BankAccount => "bank_account",
        }
    }
}

impl From<RuleKind> for SecretKind {
    fn from(k: RuleKind) -> Self {
        match k {
            RuleKind::ApiKey => SecretKind::ApiKey,
            RuleKind::NationalId => SecretKind::NationalId,
            RuleKind::ResidentCertificate => SecretKind::ResidentCertificate,
            RuleKind::BusinessId => SecretKind::BusinessId,
            RuleKind::CreditCard => SecretKind::CreditCard,
            RuleKind::MobilePhone => SecretKind::MobilePhone,
            RuleKind::PhoneNumber => SecretKind::PhoneNumber,
            RuleKind::BankAccount => SecretKind::BankAccount,
        }
    }
}

/// One detected secret (legacy `SecretMatch`). Deliberately holds no plaintext: only
/// the mask and the position, so a result cannot be displayed or logged by mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    pub kind: SecretKind,
    /// Rule id (`tw-national-id`, `gitleaks.…`); empty for registered secrets.
    pub rule_id: String,
    /// Display label (render with Fluent; see [`RULE_LABEL_ID`]).
    pub label: Message,
    /// Masked value (`A12****789`); a PEM header is shown as is.
    pub masked: String,
    /// UTF-8 byte range in the original text (includes zero-width chars removed by
    /// normalization).
    pub span: Range<usize>,
}

/// Finds secrets in `text` with the built-in rules of `packs` (universal always on).
pub fn find(text: &str, packs: &PackSet) -> Vec<SecretMatch> {
    engine::builtin().find(text, packs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_regexes(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m.iter_mut() {
                    if k == "regex" {
                        *x = serde_json::Value::String(String::new());
                    } else {
                        blank_regexes(x);
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(blank_regexes),
            _ => {}
        }
    }

    /// Rule files must not carry anything that looks like a real key (legacy
    /// `SecretRulesTests` property).
    #[test]
    fn rule_files_contain_no_keys() {
        for (name, json) in paste_warden_rules::secret::EMBEDDED {
            let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
            blank_regexes(&mut v);
            let text = serde_json::to_string_pretty(&v).unwrap();
            let found = find(&text, &PackSet::default());
            assert!(found.is_empty(), "{name}: {found:?}");
        }
    }

    #[test]
    fn spans_are_original_byte_ranges() {
        let text = "身分證 Ａ１２３４５６７８９ ok";
        let m = find(text, &PackSet::default());
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, SecretKind::NationalId);
        assert_eq!(m[0].masked, "A12****789");
        assert_eq!(&text[m[0].span.clone()], "Ａ１２３４５６７８９");
    }

    #[test]
    fn odd_inputs_do_not_panic() {
        for t in [
            "",
            "\u{200B}",
            "🔑",
            "eyJ",
            "-----BEGIN PRIVATE KEY-----",
            "\r\n\r\n",
        ] {
            let m = find(t, &PackSet::all());
            let _ = mask_text(t, &m, "x");
        }
    }
}
