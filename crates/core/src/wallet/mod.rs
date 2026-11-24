//! Wallet addresses and clipper (address swap) detection (legacy `WalletAddress`,
//! `WalletSwapDetector`; docs/spec/detection-rules.md §6.2).

mod swap;

pub use swap::{
    COPY_INPUT_GRACE_MS, FAST_WINDOW_MS, SwapDetector, WINDOW_MS, WalletSwap, WalletSwapSignal,
};

use sha2::{Digest, Sha256};

/// Only candidates starting within this many chars are considered (same as
/// secret detection); the rest of the text is not analyzed. Legacy counts UTF-16
/// code units; addresses are ASCII, so only text before them can differ.
pub const MAX_SCAN_LENGTH: usize = 100_000;

/// At most this many candidates (alphanumeric runs of a plausible length) are
/// validated per text; each costs a SHA-256 or bech32 checksum.
pub const MAX_CANDIDATES: usize = 256;

/// Shortest plausible address.
pub const MIN_ADDRESS_LEN: usize = 26;
/// Longest plausible address.
pub const MAX_ADDRESS_LEN: usize = 90;

/// Cryptocurrency of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cryptocurrency {
    Bitcoin,
    /// Ethereum and other EVM chains (BSC, Polygon…) sharing `0x` addresses.
    Ethereum,
    Tron,
}

impl Cryptocurrency {
    /// snake_case name used by the corpus.
    pub fn as_str(self) -> &'static str {
        match self {
            Cryptocurrency::Bitcoin => "bitcoin",
            Cryptocurrency::Ethereum => "ethereum",
            Cryptocurrency::Tron => "tron",
        }
    }
}

/// An address found in a text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAddressMatch {
    /// UTF-8 byte offset of the address.
    pub start: usize,
    /// Length in bytes (addresses are ASCII, so also chars and UTF-16 units).
    pub len: usize,
    pub currency: Cryptocurrency,
    /// Normalized form for "same address?" comparisons (ETH and bech32 lowercased).
    pub normalized: String,
}

impl WalletAddressMatch {
    /// Byte range of the address in the searched text.
    pub fn range(&self) -> std::ops::Range<usize> {
        self.start..self.start + self.len
    }
}

/// Every valid address in `text`, in order (legacy `WalletAddress.FindAll`).
///
/// An address must be a whole run of ASCII letters and digits, so longer runs
/// (hashes, Base64) are never cut to produce a false match.
pub fn find_all(text: &str) -> Vec<WalletAddressMatch> {
    let bytes = text.as_bytes();
    let end = text
        .char_indices()
        .nth(MAX_SCAN_LENGTH)
        .map_or(text.len(), |(i, _)| i);
    let mut found = Vec::new();
    let mut candidates = 0;
    let mut i = 0;
    while i < end && candidates < MAX_CANDIDATES {
        if !bytes.get(i).is_some_and(u8::is_ascii_alphanumeric) {
            i += 1;
            continue;
        }
        let start = i;
        while bytes.get(i).is_some_and(u8::is_ascii_alphanumeric) {
            i += 1;
        }
        let len = i - start;
        if !(MIN_ADDRESS_LEN..=MAX_ADDRESS_LEN).contains(&len) {
            continue;
        }
        candidates += 1;
        if let Some((currency, normalized)) = text.get(start..i).and_then(parse) {
            found.push(WalletAddressMatch {
                start,
                len,
                currency,
                normalized,
            });
        }
    }
    found
}

/// Is the whole of `text` (trimmed) one valid address? Returns its currency and
/// normalized form (legacy `WalletAddress.TryParse`).
pub fn parse(text: &str) -> Option<(Cryptocurrency, String)> {
    let s = text.trim();
    if !s.is_ascii() || !(MIN_ADDRESS_LEN..=MAX_ADDRESS_LEN).contains(&s.len()) {
        return None;
    }
    if is_ethereum(s) {
        return Some((Cryptocurrency::Ethereum, s.to_ascii_lowercase()));
    }
    if is_bech32_bitcoin(s) {
        return Some((Cryptocurrency::Bitcoin, s.to_ascii_lowercase()));
    }
    match s.as_bytes().first() {
        Some(b'1') if is_base58check(s, 0x00) => Some((Cryptocurrency::Bitcoin, s.to_owned())),
        Some(b'3') if is_base58check(s, 0x05) => Some((Cryptocurrency::Bitcoin, s.to_owned())),
        Some(b'T') if is_base58check(s, 0x41) => Some((Cryptocurrency::Tron, s.to_owned())),
        _ => None,
    }
}

/// `0x` / `0X` + 40 hex digits. EIP-55 (Keccak) is not checked.
fn is_ethereum(s: &str) -> bool {
    s.len() == 42
        && (s.starts_with("0x") || s.starts_with("0X"))
        && s.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
}

/// Base58Check: 1 version byte + 20-byte hash + 4-byte checksum.
fn is_base58check(s: &str, version: u8) -> bool {
    if !(26..=35).contains(&s.len()) {
        return false;
    }
    let Ok(bytes) = bs58::decode(s).into_vec() else {
        return false;
    };
    let (Some(body), Some(check)) = (bytes.get(..21), bytes.get(21..)) else {
        return false;
    };
    if bytes.len() != 25 || bytes.first() != Some(&version) {
        return false;
    }
    let hash = Sha256::digest(Sha256::digest(body));
    hash.get(..4) == Some(check)
}

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// BTC bech32 (BIP-173, witness v0) / bech32m (BIP-350, v1) with HRP `bc`.
fn is_bech32_bitcoin(s: &str) -> bool {
    if !s.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("bc1")) {
        return false;
    }
    // Mixed case is invalid bech32.
    if s.bytes().any(|b| b.is_ascii_uppercase()) && s.bytes().any(|b| b.is_ascii_lowercase()) {
        return false;
    }
    let mut data = Vec::with_capacity(s.len().saturating_sub(3));
    for b in s.bytes().skip(3) {
        let lower = b.to_ascii_lowercase();
        match BECH32_CHARSET.iter().position(|&c| c == lower) {
            Some(v) => data.push(v as u32),
            None => return false,
        }
    }
    if data.len() < 7 {
        return false;
    }
    let program_chars = data.len() - 1 - 6;
    // v0: 20 bytes (32 chars) or 32 bytes (52 chars); v1 (taproot): 32 bytes.
    let expected = match data.first() {
        Some(0) if program_chars == 32 || program_chars == 52 => BECH32_CONST,
        Some(1) if program_chars == 52 => BECH32M_CONST,
        _ => return false,
    };
    let hrp = [
        u32::from(b'b' >> 5),
        u32::from(b'c' >> 5),
        0,
        u32::from(b'b' & 31),
        u32::from(b'c' & 31),
    ];
    polymod(hrp.iter().chain(&data).copied()) == expected
}

fn polymod(values: impl Iterator<Item = u32>) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_kind() {
        let cases = [
            (
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                Some(Cryptocurrency::Bitcoin),
            ),
            (
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                Some(Cryptocurrency::Bitcoin),
            ),
            (
                "BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ",
                Some(Cryptocurrency::Bitcoin),
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                Some(Cryptocurrency::Bitcoin),
            ),
            (
                "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                Some(Cryptocurrency::Tron),
            ),
            (
                "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
                Some(Cryptocurrency::Ethereum),
            ),
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", None),
            ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwF5mdq", None),
            ("é1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None),
        ];
        for (s, want) in cases {
            assert_eq!(parse(s).map(|p| p.0), want, "{s}");
        }
    }

    #[test]
    fn finds_in_sentence_with_byte_offsets() {
        let text = "送到TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t謝謝";
        let m = find_all(text);
        assert_eq!(m.len(), 1);
        assert_eq!(&text[m[0].range()], "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
    }
}
