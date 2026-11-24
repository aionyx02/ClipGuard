//! Clipboard read limit (legacy `ClipboardLimits`; detection-rules.md §2.2).
//!
//! The app reads only the first [`MAX_ANALYZED_CHARS`] chars of the clipboard for
//! analysis. 1 Mi is several times every detector's own limit, so truncation does
//! not weaken detection; quarantined commands are read in full separately.
//!
//! Counted in chars, not UTF-16 code units (phase-1.md §1.8): a cut can never
//! split a surrogate pair, so the legacy "drop a dangling high surrogate" rule is
//! implied.

/// Maximum number of chars read for analysis (`1 << 20`). Do not raise a
/// detector's own length limit above this: the rest is never read.
pub const MAX_ANALYZED_CHARS: usize = 1 << 20;

/// Byte length of the prefix of `text` that is analyzed.
pub fn cut_len(text: &str) -> usize {
    // Fast path: fewer bytes than the limit means fewer chars too.
    if text.len() <= MAX_ANALYZED_CHARS {
        return text.len();
    }
    text.char_indices()
        .nth(MAX_ANALYZED_CHARS)
        .map_or(text.len(), |(i, _)| i)
}

/// The prefix of `text` the app analyzes (legacy `ClipboardLimits.Prefix`).
pub fn prefix(text: &str) -> &str {
    text.get(..cut_len(text)).unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuts_at_char_limit() {
        let s = "a".repeat(MAX_ANALYZED_CHARS);
        assert_eq!(prefix(&s).len(), MAX_ANALYZED_CHARS);
        let s = format!("{}😀tail", "a".repeat(MAX_ANALYZED_CHARS - 1));
        assert!(prefix(&s).ends_with('😀'));
        assert_eq!(prefix(&s).chars().count(), MAX_ANALYZED_CHARS);
        let s = "中".repeat(MAX_ANALYZED_CHARS + 3);
        assert_eq!(prefix(&s).chars().count(), MAX_ANALYZED_CHARS);
    }
}
