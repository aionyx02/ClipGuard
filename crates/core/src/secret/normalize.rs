//! Normalization before secret matching (legacy `SecretTextNormalizer`, spec §5.0).
//!
//! - NFKC per char: full-width letters, digits, punctuation and spaces become
//!   half-width (`Ａ１２３` → `A123`).
//! - Dash variants (U+2010–2015, U+2212, U+FE58) become `-`.
//! - Zero-width chars (U+200B–200D, U+2060, U+FEFF) and the soft hyphen U+00AD are
//!   dropped, so numbers with those inside still match.
//!
//! Normalizing char by char (not the whole string) lets every output char remember
//! where it came from in the original, so results map back to original spans.

use unicode_normalization::UnicodeNormalization;

/// Where one normalized char came from in the original text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Origin {
    /// Original UTF-8 byte range.
    pub byte_start: usize,
    pub byte_end: usize,
    /// Original char-index range.
    pub char_start: usize,
    pub char_end: usize,
}

/// Normalized text plus, per normalized char, its origin in the original.
#[derive(Debug, Clone, Default)]
pub struct Normalized {
    pub chars: Vec<char>,
    pub origins: Vec<Origin>,
}

impl Drop for Normalized {
    /// The normalized text is clipboard plaintext: wipe it.
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.chars.zeroize();
    }
}

impl Normalized {
    /// Original range of normalized chars `[index, index + len)` (`len ≥ 1`), including
    /// any zero-width chars dropped in between. `None` if out of range.
    pub fn to_original(&self, index: usize, len: usize) -> Option<Origin> {
        let first = self.origins.get(index)?;
        let last = self.origins.get((index + len).checked_sub(1)?)?;
        Some(Origin {
            byte_start: first.byte_start,
            byte_end: last.byte_end,
            char_start: first.char_start,
            char_end: last.char_end,
        })
    }
}

fn is_dropped(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}'
    )
}

fn is_dash(c: char) -> bool {
    matches!(c, '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{FE58}')
}

/// Normalizes `text` (a slice of a larger text starting at byte `base_byte`, char
/// `base_char`), recording absolute original positions.
pub fn normalize(text: &str, base_byte: usize, base_char: usize) -> Normalized {
    let mut out = Normalized {
        chars: Vec::with_capacity(text.len()),
        origins: Vec::with_capacity(text.len()),
    };
    for (ci, (bi, c)) in text.char_indices().enumerate() {
        let origin = Origin {
            byte_start: base_byte + bi,
            byte_end: base_byte + bi + c.len_utf8(),
            char_start: base_char + ci,
            char_end: base_char + ci + 1,
        };
        let mut push = |ch: char| {
            out.chars.push(ch);
            out.origins.push(origin);
        };
        // Common chars map to themselves: ASCII, CJK unified ideographs, Hangul syllables.
        if c.is_ascii()
            || ('\u{3400}'..='\u{9FFF}').contains(&c)
            || ('\u{AC00}'..='\u{D7A3}').contains(&c)
        {
            push(c);
        } else if is_dropped(c) {
        } else if is_dash(c) {
            push('-');
        } else {
            for m in std::iter::once(c).nfkc() {
                push(m);
            }
        }
    }
    out
}

/// Normalizes a whole string (convenience for tests and callers that only need text).
pub fn normalize_str(text: &str) -> String {
    normalize(text, 0, 0).chars.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_width_dashes_and_zero_width() {
        assert_eq!(normalize_str("Ａ１２３"), "A123");
        assert_eq!(normalize_str("A123–456"), "A123-456");
        assert_eq!(normalize_str("A1\u{200B}2"), "A12");
    }

    #[test]
    fn origins_cover_dropped_chars() {
        let n = normalize("a\u{200B}b", 0, 0);
        let o = n.to_original(0, 2).unwrap();
        assert_eq!((o.byte_start, o.byte_end), (0, 5));
        assert_eq!((o.char_start, o.char_end), (0, 3));
        assert!(n.to_original(1, 5).is_none());
        assert!(n.to_original(0, 0).is_none());
    }

    #[test]
    fn idempotent() {
        let s = "Ａ１２３ ﹘ x\u{FEFF}y ㎏ 中文";
        let once = normalize_str(s);
        assert_eq!(normalize_str(&once), once);
    }
}
