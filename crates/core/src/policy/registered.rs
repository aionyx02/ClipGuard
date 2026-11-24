//! User-registered secrets (legacy `RegisteredSecretStore` matching and
//! `SecretRegistration`; detection-rules.md §5.1).
//!
//! Only the label, the length and **HMAC-SHA256(key, UTF-8(secret))** are kept —
//! never the secret, and never a plain SHA-256 (short secrets such as ID or phone
//! numbers could be brute-forced from an unkeyed hash). The 32-byte key and the
//! persistence of [`RegisteredSecret`] entries belong to the platform layer
//! (Phase 4); this module only does the keyed matching.
//!
//! Lengths are counted in **chars** (the legacy store used UTF-16 code units;
//! phase-1.md §1.8).

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::Message;

/// Minimum secret length in chars.
pub const MIN_LENGTH: usize = 6;
/// Maximum secret length in chars.
pub const MAX_LENGTH: usize = 256;
/// Labels are shown in notifications; longer ones are cut (chars).
pub const MAX_LABEL_LENGTH: usize = 40;
/// Only the first this-many chars of a text are scanned (sliding window × distinct
/// lengths would otherwise slow the UI).
pub const MAX_SCAN_LENGTH: usize = 20_000;
/// HMAC key length in bytes.
pub const KEY_LENGTH: usize = 32;
/// HMAC-SHA256 output length in bytes.
pub const HMAC_LENGTH: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// One registered secret. No secret material besides the keyed MAC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredSecret {
    /// Store-assigned id (unique within the store).
    pub id: u64,
    /// Trimmed label; empty = untitled (rendered with `registered-untitled`).
    pub label: String,
    /// Secret length in chars.
    pub length: usize,
    /// HMAC-SHA256(key, UTF-8(secret)).
    pub hmac: [u8; HMAC_LENGTH],
    /// Caller-supplied creation time (ms since the Unix epoch).
    pub created_at_ms: u64,
}

impl RegisteredSecret {
    /// The label as a message argument: the label itself, or `None` when untitled.
    pub fn label(&self) -> Option<&str> {
        (!self.label.is_empty()).then_some(self.label.as_str())
    }
}

/// The key is not [`KEY_LENGTH`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyError;

/// Why [`RegisteredSecretStore::add`] refused a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddError {
    /// Not in `MIN_LENGTH..=MAX_LENGTH` chars.
    LengthOutOfRange,
    /// The same secret is already registered.
    AlreadyRegistered,
}

impl AddError {
    pub fn as_str(self) -> &'static str {
        match self {
            AddError::LengthOutOfRange => "length_out_of_range",
            AddError::AlreadyRegistered => "already_registered",
        }
    }

    /// Localizable explanation.
    pub fn message(self) -> Message {
        match self {
            AddError::LengthOutOfRange => Message::new("registered-length-out-of-range")
                .arg("min", MIN_LENGTH)
                .arg("max", MAX_LENGTH),
            AddError::AlreadyRegistered => Message::new("registered-already-registered"),
        }
    }
}

/// A registered secret found in a text. Carries no character of the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredMatch {
    pub entry_id: u64,
    /// Entry label; empty = untitled.
    pub label: String,
    /// UTF-8 byte range in the scanned text.
    pub start: usize,
    pub end: usize,
}

impl RegisteredMatch {
    /// The mask shown instead of the secret: `registered-mask` with the label, or
    /// `registered-mask-untitled`.
    pub fn masked(&self) -> Message {
        if self.label.is_empty() {
            Message::new("registered-mask-untitled")
        } else {
            Message::new("registered-mask").arg("label", self.label.as_str())
        }
    }
}

/// Registered secrets keyed by an HMAC key (see the module docs).
pub struct RegisteredSecretStore {
    mac: HmacSha256,
    entries: Vec<RegisteredSecret>,
}

impl std::fmt::Debug for RegisteredSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredSecretStore")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Constant-time equality of two MACs.
fn ct_eq(a: &[u8; HMAC_LENGTH], b: &[u8; HMAC_LENGTH]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl RegisteredSecretStore {
    /// An empty store.
    pub fn new(key: &[u8]) -> Result<Self, KeyError> {
        Self::with_entries(key, Vec::new())
    }

    /// A store with previously saved entries (same key).
    pub fn with_entries(key: &[u8], entries: Vec<RegisteredSecret>) -> Result<Self, KeyError> {
        if key.len() != KEY_LENGTH {
            return Err(KeyError);
        }
        let mac = HmacSha256::new_from_slice(key).map_err(|_| KeyError)?;
        Ok(RegisteredSecretStore { mac, entries })
    }

    pub fn entries(&self) -> &[RegisteredSecret] {
        &self.entries
    }

    /// HMAC-SHA256(key, UTF-8(value)).
    pub fn hmac(&self, value: &str) -> [u8; HMAC_LENGTH] {
        let mut m = self.mac.clone();
        m.update(value.as_bytes());
        let tag = m.finalize().into_bytes();
        let mut out = [0u8; HMAC_LENGTH];
        for (o, t) in out.iter_mut().zip(tag.iter()) {
            *o = *t;
        }
        out
    }

    /// Registers `secret` with `label` (trimmed, cut to [`MAX_LABEL_LENGTH`] chars;
    /// blank = untitled).
    pub fn add(
        &mut self,
        label: Option<&str>,
        secret: &str,
        now_ms: u64,
    ) -> Result<&RegisteredSecret, AddError> {
        let length = secret.chars().count();
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
            return Err(AddError::LengthOutOfRange);
        }
        let hmac = self.hmac(secret);
        // Check every entry (no early exit) so timing does not depend on the match.
        let duplicate = self.entries.iter().fold(false, |acc, e| {
            acc | (e.length == length && ct_eq(&e.hmac, &hmac))
        });
        if duplicate {
            return Err(AddError::AlreadyRegistered);
        }
        let label: String = label
            .map(str::trim)
            .unwrap_or_default()
            .chars()
            .take(MAX_LABEL_LENGTH)
            .collect();
        let id = self
            .entries
            .iter()
            .map(|e| e.id)
            .max()
            .map_or(1, |m| m.saturating_add(1));
        self.entries.push(RegisteredSecret {
            id,
            label,
            length,
            hmac,
            created_at_ms: now_ms,
        });
        self.entries.last().ok_or(AddError::LengthOutOfRange)
    }

    /// Removes an entry; `false` when there is no such id.
    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() != before
    }

    /// Finds registered secrets in `text` (first [`MAX_SCAN_LENGTH`] chars). For each
    /// registered length L, every L-char window is MACed and compared in constant
    /// time. Each entry is reported at most once (first occurrence); results are
    /// sorted by position.
    pub fn find(&self, text: &str) -> Vec<RegisteredMatch> {
        if text.is_empty() || self.entries.is_empty() {
            return Vec::new();
        }
        // Char boundaries of the scanned prefix, plus its end.
        let bounds: Vec<usize> = text
            .char_indices()
            .map(|(i, _)| i)
            .take(MAX_SCAN_LENGTH)
            .chain(std::iter::once(
                text.char_indices()
                    .nth(MAX_SCAN_LENGTH)
                    .map_or(text.len(), |(i, _)| i),
            ))
            .collect();
        let chars = bounds.len().saturating_sub(1);

        let mut lengths: Vec<usize> = self.entries.iter().map(|e| e.length).collect();
        lengths.sort_unstable();
        lengths.dedup();

        let mut results = Vec::new();
        for len in lengths {
            if len == 0 || len > chars {
                continue;
            }
            let mut candidates: Vec<&RegisteredSecret> =
                self.entries.iter().filter(|e| e.length == len).collect();
            let mut i = 0;
            while i + len <= chars && !candidates.is_empty() {
                let (Some(&start), Some(&end)) = (bounds.get(i), bounds.get(i + len)) else {
                    break;
                };
                let mac = self.hmac(text.get(start..end).unwrap_or_default());
                candidates.retain(|e| {
                    if ct_eq(&e.hmac, &mac) {
                        results.push(RegisteredMatch {
                            entry_id: e.id,
                            label: e.label.clone(),
                            start,
                            end,
                        });
                        false
                    } else {
                        true
                    }
                });
                i += 1;
            }
        }
        results.sort_by_key(|m| m.start);
        results
    }
}

/// Field of the registration dialog that has a problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationField {
    Secret,
    Confirm,
}

impl RegistrationField {
    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationField::Secret => "secret",
            RegistrationField::Confirm => "confirm",
        }
    }
}

/// A registration input problem. The message never contains the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationError {
    pub field: RegistrationField,
    pub message: Message,
}

/// Checks the "register a secret" dialog input (legacy `SecretRegistration.Validate`).
/// The label may be blank; duplicates are detected by [`RegisteredSecretStore::add`].
pub fn validate_registration(secret: &str, confirm: &str) -> Result<(), RegistrationError> {
    let err = |field, message| Err(RegistrationError { field, message });
    if secret.is_empty() {
        return err(
            RegistrationField::Secret,
            Message::new("registered-secret-empty"),
        );
    }
    let length = secret.chars().count();
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return err(
            RegistrationField::Secret,
            Message::new("registered-secret-length")
                .arg("min", MIN_LENGTH)
                .arg("max", MAX_LENGTH)
                .arg("length", length),
        );
    }
    if confirm.is_empty() {
        return err(
            RegistrationField::Confirm,
            Message::new("registered-confirm-empty"),
        );
    }
    if secret != confirm {
        return err(
            RegistrationField::Confirm,
            Message::new("registered-mismatch"),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn hmac_is_keyed() {
        let key: Vec<u8> = (0u8..32).collect();
        let s = RegisteredSecretStore::new(&key).unwrap();
        let hex: String = s
            .hmac("MyS3cretValue!")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "7a3fd1e6953be552cb63020cef6a8ee2e5ba8e35ca0048a849e7439a6773130a"
        );
        assert!(RegisteredSecretStore::new(&key[..16]).is_err());
    }

    #[test]
    fn add_find_remove() {
        let mut s = RegisteredSecretStore::new(&KEY).unwrap();
        let id = s.add(Some("  pin "), "246813579", 0).unwrap().id;
        assert_eq!(s.entries()[0].label, "pin");
        assert_eq!(
            s.add(None, "246813579", 0),
            Err(AddError::AlreadyRegistered)
        );
        assert_eq!(s.add(None, "short", 0), Err(AddError::LengthOutOfRange));
        let m = s.find("x 246813579 246813579");
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].start, m[0].end), (2, 11));
        assert!(s.find("24681357").is_empty());
        assert!(s.remove(id));
        assert!(!s.remove(id));
        assert!(s.find("246813579").is_empty());
    }

    #[test]
    fn multibyte_windows_and_scan_limit() {
        let mut s = RegisteredSecretStore::new(&KEY).unwrap();
        s.add(Some("中文"), "我的祕密密碼🔑", 0).unwrap();
        let m = s.find("前綴我的祕密密碼🔑後綴");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].start, "前綴".len());
        s.add(None, "scan-limit-secret", 0).unwrap();
        let inside = format!("{}scan-limit-secret", "a".repeat(MAX_SCAN_LENGTH - 17));
        assert_eq!(s.find(&inside).len(), 1);
        let outside = format!("{}scan-limit-secret", "a".repeat(MAX_SCAN_LENGTH - 16));
        assert!(s.find(&outside).is_empty());
    }

    #[test]
    fn validation() {
        assert!(validate_registration("abcdef", "abcdef").is_ok());
        assert_eq!(
            validate_registration("", "").unwrap_err().field,
            RegistrationField::Secret
        );
        assert_eq!(
            validate_registration("abcdef", "abcdeg").unwrap_err().field,
            RegistrationField::Confirm
        );
    }
}
