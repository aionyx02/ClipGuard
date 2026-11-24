//! Wallet addresses and clipper (address swap) detection (legacy `WalletAddress`,
//! `WalletSwapDetector`; docs/spec/detection-rules.md §6.2).

mod keccak;
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

/// Solana addresses: Base58 of a 32-byte public key.
pub const SOLANA_MIN_LEN: usize = 32;
pub const SOLANA_MAX_LEN: usize = 44;
pub const SOLANA_KEY_BYTES: usize = 32;

/// Longest Base58Check address (BTC, TRON, XRP `r…` in the Ripple alphabet). XRP
/// allows 25 characters, but [`MIN_ADDRESS_LEN`] still applies (a 25-character
/// address needs a hash with ~60 leading zero bits).
pub const BASE58CHECK_MAX_LEN: usize = 35;

/// Cryptocurrency of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cryptocurrency {
    Bitcoin,
    /// Ethereum and other EVM chains (BSC, Polygon…) sharing `0x` addresses.
    Ethereum,
    Tron,
    /// Solana (Base58 32-byte public key; no checksum).
    Solana,
    /// XRP Ledger classic address.
    Xrp,
}

impl Cryptocurrency {
    /// snake_case name used by the corpus.
    pub fn as_str(self) -> &'static str {
        match self {
            Cryptocurrency::Bitcoin => "bitcoin",
            Cryptocurrency::Ethereum => "ethereum",
            Cryptocurrency::Tron => "tron",
            Cryptocurrency::Solana => "solana",
            Cryptocurrency::Xrp => "xrp",
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
        let parsed = text.get(start..i).and_then(parse).filter(|(currency, _)| {
            *currency != Cryptocurrency::Solana || !looks_like_base64_part(bytes, start, i)
        });
        if let Some((currency, normalized)) = parsed {
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

/// A Solana address has no checksum, so a run that is visibly part of a Base64
/// string (`+` on either side, `/` or `=` right after it) is not taken as one.
/// `/` before it is allowed: explorer URLs end in `/account/<address>`.
fn looks_like_base64_part(bytes: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).and_then(|b| bytes.get(b));
    let after = bytes.get(end);
    before == Some(&b'+') || matches!(after, Some(b'+' | b'/' | b'='))
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
    let bitcoin = bs58::Alphabet::BITCOIN;
    let found = match s.as_bytes().first() {
        Some(b'1') if is_base58check(s, 0x00, bitcoin) => Some(Cryptocurrency::Bitcoin),
        Some(b'3') if is_base58check(s, 0x05, bitcoin) => Some(Cryptocurrency::Bitcoin),
        Some(b'T') if is_base58check(s, 0x41, bitcoin) => Some(Cryptocurrency::Tron),
        Some(b'r') if is_base58check(s, 0x00, bs58::Alphabet::RIPPLE) => Some(Cryptocurrency::Xrp),
        _ => None,
    };
    let found = found.or_else(|| is_solana(s).then_some(Cryptocurrency::Solana));
    found.map(|c| (c, s.to_owned()))
}

/// `0x` / `0X` + 40 hex digits. Mixed-case hex must carry a valid EIP-55 checksum;
/// all-lowercase and all-uppercase hex have none and stay valid.
fn is_ethereum(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) else {
        return false;
    };
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let has_upper = hex.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = hex.bytes().any(|b| b.is_ascii_lowercase());
    !(has_upper && has_lower) || is_eip55(hex)
}

/// EIP-55: hex letter `i` is uppercase iff nibble `i` of
/// `keccak256(lowercase hex as ASCII)` is ≥ 8.
fn is_eip55(hex: &str) -> bool {
    let lower = hex.to_ascii_lowercase();
    let hash = keccak::keccak256(lower.as_bytes());
    hex.bytes().enumerate().all(|(i, b)| {
        if !b.is_ascii_alphabetic() {
            return true;
        }
        let byte = hash.get(i / 2).copied().unwrap_or(0);
        let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
        b.is_ascii_uppercase() == (nibble >= 8)
    })
}

/// Solana: Base58 (Bitcoin alphabet) of exactly 32 bytes, 32–44 characters.
/// There is no checksum, so only the length and alphabet are checked; a string
/// made only of hex digits (a hash) is never taken as one.
fn is_solana(s: &str) -> bool {
    if !(SOLANA_MIN_LEN..=SOLANA_MAX_LEN).contains(&s.len())
        || s.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return false;
    }
    let mut key = [0u8; SOLANA_KEY_BYTES];
    matches!(bs58::decode(s).onto(&mut key[..]), Ok(SOLANA_KEY_BYTES))
}

/// Base58Check: 1 version byte + 20-byte hash + 4-byte checksum.
fn is_base58check(s: &str, version: u8, alphabet: &bs58::Alphabet) -> bool {
    if !(MIN_ADDRESS_LEN..=BASE58CHECK_MAX_LEN).contains(&s.len()) {
        return false;
    }
    let Ok(bytes) = bs58::decode(s).with_alphabet(alphabet).into_vec() else {
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
    fn eip55() {
        // EIP-55 test vectors.
        for a in [
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            "0xde709f2102306220921060314715629080e2fb77",
            "0x27b1fdb04752bbc536007a920d24acb045561c26",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED",
            "0X5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
        ] {
            assert_eq!(parse(a).map(|p| p.0), Some(Cryptocurrency::Ethereum), "{a}");
        }
        for a in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",
            "0x5aaeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        ] {
            assert_eq!(parse(a), None, "{a}");
        }
    }

    #[test]
    fn solana_and_xrp() {
        for a in [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "So11111111111111111111111111111111111111112",
        ] {
            assert_eq!(parse(a).map(|p| p.0), Some(Cryptocurrency::Solana), "{a}");
        }
        for a in [
            "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
            "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
        ] {
            assert_eq!(parse(a).map(|p| p.0), Some(Cryptocurrency::Xrp), "{a}");
        }
        for a in [
            "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi",
            // Git SHA-1 / SHA-256 (hex only).
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
            "1111111111111111111111111111111111111111111",
            // The system program id: only hex digits, so taken as a hash.
            "11111111111111111111111111111111",
            // 44 chars decoding to 33 bytes.
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            // Base58 of 33 bytes / too long.
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DAx",
        ] {
            assert_eq!(parse(a), None, "{a}");
        }
        let b64 = "key=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v=";
        assert!(find_all(b64).is_empty());
        let b64 = "x+EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        assert!(find_all(b64).is_empty());
        let url =
            "https://explorer.invalid/address/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v?x=1";
        assert_eq!(find_all(url).len(), 1);
    }

    #[test]
    fn finds_in_sentence_with_byte_offsets() {
        let text = "送到TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t謝謝";
        let m = find_all(text);
        assert_eq!(m.len(), 1);
        assert_eq!(&text[m[0].range()], "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
    }
}
