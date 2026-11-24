//! BIP-39 recovery phrases (phase 1b, spec §5.7): the `bip39` finder.
//!
//! A candidate is a maximal run of words from the English BIP-39 list, joined by
//! "gaps" (whitespace, one comma, list numbering such as `2.` / `2)` / `(2)`). A run
//! counts only when it has exactly 12, 15, 18, 21 or 24 words and the BIP-39 checksum
//! (first `words / 3` bits of SHA-256 of the entropy) is right, so ordinary English
//! made of list words almost never matches (a 12-word run passes by chance 1 time in
//! 16, a 24-word run 1 in 256, and twelve list words in a row are rare in prose).
//! Runs of other lengths are not searched for windows: a 13-word run is not a phrase.

use std::sync::OnceLock;

use paste_warden_rules::secret::{BIP39_ENGLISH, parse_bip39_words};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Word counts BIP-39 defines (128–256 bits of entropy).
pub const VALID_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// Longest phrase in words; a longer run is a word list, not a phrase.
pub const MAX_WORDS: usize = 24;

/// Longest gap between two words, in chars (`\n\n 12.  ` fits). Keeps a whole
/// phrase far below the segment overlap and lets a run that started before a
/// segment be recognized as such within the 64-char look-back.
pub const MAX_GAP: usize = 16;

/// Longest list-number in a gap (`24.`).
const MAX_NUMBER_DIGITS: usize = 2;

fn words() -> &'static [&'static str] {
    static W: OnceLock<Vec<&'static str>> = OnceLock::new();
    W.get_or_init(|| parse_bip39_words(BIP39_ENGLISH).unwrap_or_default())
}

/// Index of an ASCII-letter token in the word list (case-insensitive).
fn word_index(token: &[u8]) -> Option<u16> {
    if !(3..=8).contains(&token.len()) {
        return None;
    }
    let mut buf = [0u8; 8];
    for (b, t) in buf.iter_mut().zip(token) {
        *b = t.to_ascii_lowercase();
    }
    let key = &buf[..token.len()];
    let i = words().binary_search_by(|w| w.as_bytes().cmp(key)).ok()?;
    u16::try_from(i).ok()
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c')
}

/// Is `g` (the text between two words) a valid separator? Grammar:
/// `ws* [',' ws*] [number ws*]` with at least one char, where `number` is 1–2 digits
/// followed by `.`, `)` or `:` (then optional ws), or by ws, or `(n)`.
fn valid_gap(g: &[u8]) -> bool {
    if g.is_empty() || g.len() > MAX_GAP {
        return false;
    }
    let mut i = 0;
    let skip_ws = |i: &mut usize| {
        while *i < g.len() && is_ws(g[*i]) {
            *i += 1;
        }
    };
    skip_ws(&mut i);
    if g.get(i) == Some(&b',') {
        i += 1;
        skip_ws(&mut i);
    }
    if i == g.len() {
        return true;
    }
    let paren = g[i] == b'(';
    if paren {
        i += 1;
    }
    let d0 = i;
    while i < g.len() && g[i].is_ascii_digit() && i - d0 < MAX_NUMBER_DIGITS {
        i += 1;
    }
    if i == d0 {
        return false;
    }
    if paren {
        if g.get(i) != Some(&b')') {
            return false;
        }
        i += 1;
    } else if matches!(g.get(i), Some(b'.' | b')' | b':')) {
        i += 1;
    } else if !g.get(i).copied().is_some_and(is_ws) {
        return false;
    }
    skip_ws(&mut i);
    i == g.len()
}

/// Checks the BIP-39 checksum of word indices (`idx.len()` must be valid).
pub fn checksum_ok(idx: &[u16]) -> bool {
    let n = idx.len();
    if !VALID_WORD_COUNTS.contains(&n) {
        return false;
    }
    let total_bits = n * 11;
    let cs_bits = n / 3;
    let ent_bytes = (total_bits - cs_bits) / 8;
    // Pack the 11-bit indices big-endian into a bit string.
    let mut bits = Zeroizing::new(vec![0u8; total_bits.div_ceil(8)]);
    for (w, &v) in idx.iter().enumerate() {
        for k in 0..11 {
            if v >> (10 - k) & 1 == 1 {
                let pos = w * 11 + k;
                bits[pos / 8] |= 0x80 >> (pos % 8);
            }
        }
    }
    let hash = Sha256::digest(&bits[..ent_bytes]);
    // Checksum bits follow the entropy; cs_bits ≤ 8 so they sit in one byte.
    let expected = hash[0] >> (8 - cs_bits);
    let got = bits[ent_bytes] >> (8 - cs_bits);
    expected == got
}

/// Candidates in the ASCII view: `(start, len)` from the first word's first char to
/// the last word's last char, for runs of a valid length with a valid checksum.
pub fn candidates(ascii: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    // Current run: word indices (at most MAX_WORDS + 1 kept) and its bounds.
    let mut idx: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(MAX_WORDS + 1));
    let mut run_start = 0usize;
    let mut run_end = 0usize;
    let mut run_len = 0usize;

    let finish = |idx: &mut Vec<u16>, run_len: &mut usize, s: usize, e: usize, out: &mut Vec<_>| {
        if *run_len <= MAX_WORDS && checksum_ok(idx) {
            out.push((s, e - s));
        }
        idx.clear();
        *run_len = 0;
    };

    let n = ascii.len();
    let mut i = 0;
    while i < n {
        if !ascii[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && ascii[i].is_ascii_alphabetic() {
            i += 1;
        }
        let end = i;
        let glued = (start > 0 && is_glue(ascii[start - 1])) || (end < n && is_glue(ascii[end]));
        let w = if glued {
            None
        } else {
            word_index(&ascii[start..end])
        };
        let Some(w) = w else {
            if run_len > 0 {
                finish(&mut idx, &mut run_len, run_start, run_end, &mut out);
            }
            continue;
        };
        if run_len > 0 && !valid_gap(&ascii[run_end..start]) {
            finish(&mut idx, &mut run_len, run_start, run_end, &mut out);
        }
        if run_len == 0 {
            run_start = start;
        }
        run_len += 1;
        if idx.len() <= MAX_WORDS {
            idx.push(w);
        }
        run_end = end;
    }
    if run_len > 0 {
        finish(&mut idx, &mut run_len, run_start, run_end, &mut out);
    }
    out
}

/// A word glued to a digit or `_` (`abandon1`, `x_ability`) is part of an identifier.
fn is_glue(b: u8) -> bool {
    b.is_ascii_digit() || b == b'_'
}

/// Number of words in a matched phrase (ASCII letter runs).
pub fn word_count(s: &str) -> usize {
    let mut n = 0;
    let mut prev = false;
    for c in s.chars() {
        let a = c.is_ascii_alphabetic();
        if a && !prev {
            n += 1;
        }
        prev = a;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mnemonic for `entropy` (test helper; the reverse of `checksum_ok`).
    fn mnemonic(entropy: &[u8]) -> String {
        let ent_bits = entropy.len() * 8;
        let cs_bits = ent_bits / 32;
        let hash = Sha256::digest(entropy);
        let mut bits: Vec<bool> = entropy
            .iter()
            .flat_map(|b| (0..8).map(move |k| b >> (7 - k) & 1 == 1))
            .collect();
        bits.extend((0..cs_bits).map(|k| hash[0] >> (7 - k) & 1 == 1));
        bits.chunks(11)
            .map(|c| {
                let v = c.iter().fold(0usize, |a, &b| a << 1 | usize::from(b));
                words()[v]
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn found(t: &str) -> Vec<(usize, usize)> {
        candidates(t.as_bytes())
    }

    #[test]
    fn official_vectors() {
        // BIP-39 test vectors (trezor/python-mnemonic vectors.json).
        assert_eq!(
            mnemonic(&[0u8; 16]),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(
            mnemonic(&[0xffu8; 32]),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
        );
        for len in [16, 20, 24, 28, 32] {
            let e: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let m = mnemonic(&e);
            assert_eq!(found(&m), vec![(0, m.len())], "{m}");
            assert_eq!(word_count(&m), len * 3 / 4);
        }
    }

    #[test]
    fn checksum_and_length() {
        let good = mnemonic(&[7u8; 16]);
        let words: Vec<&str> = good.split(' ').collect();
        // Bad checksum: swap the last word for another.
        let last = if words[11] == "zoo" { "abandon" } else { "zoo" };
        let bad = format!("{} {last}", words[..11].join(" "));
        assert!(found(&bad).is_empty());
        assert!(found(&words[..11].join(" ")).is_empty());
        assert!(found(&format!("{good} ability")).is_empty());
        assert!(found(&format!("ability {good}")).is_empty());
        // Non-list words and punctuation end a run.
        assert_eq!(found(&format!("Phrase: {good}. The end")).len(), 1);
        assert_eq!(found(&format!("Seed: {good}")).len(), 1);
    }

    #[test]
    fn separators() {
        let good = mnemonic(&[42u8; 16]);
        let w: Vec<&str> = good.split(' ').collect();
        let numbered: String = w
            .iter()
            .enumerate()
            .map(|(i, x)| format!("{}. {x}\n", i + 1))
            .collect();
        assert_eq!(found(&numbered).len(), 1);
        let parens: String = w
            .iter()
            .enumerate()
            .map(|(i, x)| format!("({}) {x}  ", i + 1))
            .collect();
        assert_eq!(found(&parens).len(), 1);
        assert_eq!(found(&w.join(", ")).len(), 1);
        assert_eq!(found(&w.join("\r\n")).len(), 1);
        assert_eq!(found(&good.to_uppercase()).len(), 1);
        assert!(found(&w.join("-")).is_empty());
        assert!(found(&w.join(" . ")).is_empty());
        assert!(found(&w.join(&" ".repeat(MAX_GAP + 1))).is_empty());
        assert!(found(&format!("{good}1")).is_empty());
    }

    #[test]
    fn gaps() {
        for g in [
            " ", "\n", ", ", ",", " 2. ", "\n12.", " 3) ", " (4) ", " 5 ", "\n6:",
        ] {
            assert!(valid_gap(g.as_bytes()), "{g:?}");
        }
        for g in [
            "", "-", ". ", " 123. ", " 2.. ", " (2 ", " a ", ",,", " 2x ",
        ] {
            assert!(!valid_gap(g.as_bytes()), "{g:?}");
        }
    }

    #[test]
    fn long_runs_are_linear_and_ignored() {
        let t = "abandon ".repeat(200_000);
        assert!(found(&t).is_empty());
    }
}
