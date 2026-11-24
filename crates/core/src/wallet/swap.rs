//! Clipper detection: malware that watches the clipboard and replaces a copied
//! wallet address with the attacker's (often only the address inside a sentence).

use sha2::{Digest, Sha256};

use super::{Cryptocurrency, find_all};

/// Address-only content replaced within this many ms is a swap: nobody selects
/// and copies two different addresses within one second.
pub const FAST_WINDOW_MS: u64 = 1_000;

/// How long the last address is remembered; with surrounding text or the
/// "no user input" signal, a replacement within this window is a swap.
pub const WINDOW_MS: u64 = 3_000;

/// Input within this many ms after copying (releasing Ctrl, C) still belongs to
/// copying the first address, not to something the user did afterwards.
pub const COPY_INPUT_GRACE_MS: u64 = 500;

/// Why a replacement was judged a swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSwapSignal {
    /// Replaced faster than a person could copy twice (≤ [`FAST_WINDOW_MS`]).
    FastReplacement,
    /// Identical surrounding text, only the address changed.
    SameSurroundingText,
    /// No keyboard or mouse input since the address was copied.
    NoUserInput,
}

impl WalletSwapSignal {
    /// snake_case name used by the corpus.
    pub fn as_str(self) -> &'static str {
        match self {
            WalletSwapSignal::FastReplacement => "fast_replacement",
            WalletSwapSignal::SameSurroundingText => "same_surrounding_text",
            WalletSwapSignal::NoUserInput => "no_user_input",
        }
    }
}

/// A copied address was replaced by another. `original` / `replacement` are for
/// tests and debugging only; notifications never show them (P4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSwap {
    pub currency: Cryptocurrency,
    pub replacement_currency: Cryptocurrency,
    pub original: String,
    pub replacement: String,
    pub elapsed_ms: u64,
    pub signal: WalletSwapSignal,
}

#[derive(Debug, Clone)]
struct Address {
    normalized: String,
    currency: Cryptocurrency,
    raw: String,
}

/// What is remembered about the last content with addresses. The surrounding
/// text is kept only as a SHA-256 hash, never as text.
#[derive(Debug, Clone)]
struct Snapshot {
    addresses: Vec<Address>,
    template_hash: [u8; 32],
    has_context: bool,
    at: u64,
}

/// Stateful swap detector (legacy `WalletSwapDetector`). Time is injected.
///
/// The surrounding text (addresses replaced by a placeholder, trimmed) must be
/// identical and only an address may differ:
/// - with surrounding text: warn within [`WINDOW_MS`];
/// - addresses only: warn within [`FAST_WINDOW_MS`], or within [`WINDOW_MS`] when
///   the user has had no input since the copy.
///
/// Content without addresses does not reset the memory (A → "x" → B compares A, B).
#[derive(Debug, Clone, Default)]
pub struct SwapDetector {
    last: Option<Snapshot>,
}

impl SwapDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Call on every clipboard change (`""` for non-text content).
    ///
    /// `now_ms` is the time of the change; `user_idle_ms` is how long ago the
    /// user's last keyboard or mouse input was (`None` = unknown, then
    /// address-only content uses only [`FAST_WINDOW_MS`]).
    pub fn observe(
        &mut self,
        text: &str,
        now_ms: u64,
        user_idle_ms: Option<u64>,
    ) -> Option<WalletSwap> {
        let found = find_all(text);
        if found.is_empty() {
            return None;
        }

        let current = capture(text, &found, now_ms);
        let last = self.last.replace(current);
        let last = last?;
        let current = self.last.as_ref()?;

        let elapsed = i128::from(now_ms) - i128::from(last.at);
        if elapsed < 0 || elapsed > i128::from(WINDOW_MS) {
            return None;
        }
        let elapsed = u64::try_from(elapsed).ok()?;

        // A clipper substitutes in place: the surrounding text does not change.
        if last.template_hash != current.template_hash
            || last.addresses.len() != current.addresses.len()
        {
            return None;
        }
        let (old, new) = last
            .addresses
            .iter()
            .zip(&current.addresses)
            .find(|(a, b)| a.normalized != b.normalized)?;

        let signal = if current.has_context {
            WalletSwapSignal::SameSurroundingText
        } else if elapsed <= FAST_WINDOW_MS {
            WalletSwapSignal::FastReplacement
        } else if user_idle_ms.is_some_and(|idle| {
            i128::from(now_ms) - i128::from(idle)
                <= i128::from(last.at) + i128::from(COPY_INPUT_GRACE_MS)
        }) {
            WalletSwapSignal::NoUserInput
        } else {
            return None;
        };

        Some(WalletSwap {
            currency: old.currency,
            replacement_currency: new.currency,
            original: old.raw.clone(),
            replacement: new.raw.clone(),
            elapsed_ms: elapsed,
            signal,
        })
    }
}

fn capture(text: &str, found: &[super::WalletAddressMatch], at: u64) -> Snapshot {
    let mut template = String::with_capacity(text.len());
    let mut pos = 0;
    let mut addresses = Vec::with_capacity(found.len());
    for m in found {
        template.push_str(text.get(pos..m.start).unwrap_or_default());
        template.push('\u{FFFC}');
        addresses.push(Address {
            normalized: m.normalized.clone(),
            currency: m.currency,
            raw: text.get(m.range()).unwrap_or_default().to_owned(),
        });
        pos = m.start + m.len;
    }
    template.push_str(text.get(pos..).unwrap_or_default());
    let trimmed = template.trim();
    let has_context = trimmed
        .chars()
        .any(|c| c != '\u{FFFC}' && !c.is_whitespace());
    let template_hash = Sha256::digest(trimmed.as_bytes()).into();
    Snapshot {
        addresses,
        template_hash,
        has_context,
        at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
    const B: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

    #[test]
    fn signals_and_windows() {
        let mut d = SwapDetector::new();
        assert!(d.observe(A, 0, None).is_none());
        let s = d.observe(B, 1_000, None).unwrap();
        assert_eq!(s.signal, WalletSwapSignal::FastReplacement);

        let mut d = SwapDetector::new();
        d.observe(A, 2_000, None);
        assert!(d.observe(B, 4_000, Some(1_499)).is_none());
        let mut d = SwapDetector::new();
        d.observe(A, 0, None);
        let s = d.observe(B, 2_000, Some(1_500)).unwrap();
        assert_eq!(s.signal, WalletSwapSignal::NoUserInput);

        let mut d = SwapDetector::new();
        d.observe(&format!("pay {A} now"), 0, None);
        let s = d.observe(&format!("pay {B} now"), 3_000, Some(0)).unwrap();
        assert_eq!(s.signal, WalletSwapSignal::SameSurroundingText);
        assert!(d.observe(&format!("pay {A} now"), 6_001, None).is_none());
    }

    #[test]
    fn clock_backwards_and_idle_overflow() {
        let mut d = SwapDetector::new();
        d.observe(A, 100, None);
        assert!(d.observe(B, 90, None).is_none());
        let mut d = SwapDetector::new();
        d.observe(A, 0, None);
        assert!(d.observe(B, 2_000, Some(u64::MAX)).is_some());
    }
}
