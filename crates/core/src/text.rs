//! Text helpers shared by all modules.
//!
//! Positions inside the engine are UTF-8 byte offsets. Legacy behavior and the
//! corpus use UTF-16 code units; convert only at the boundaries.

/// Length of `s` in UTF-16 code units.
pub fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// Converts a UTF-8 byte offset (must be on a char boundary) to a UTF-16 offset.
pub fn byte_to_utf16(s: &str, byte: usize) -> usize {
    utf16_len(&s[..byte.min(s.len())])
}

/// Converts a UTF-16 offset to the UTF-8 byte offset of the char that starts there
/// (or the end of the string). An offset in the middle of a surrogate pair rounds
/// down to the start of that char.
pub fn utf16_to_byte(s: &str, utf16: usize) -> usize {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        let next = units + c.len_utf16();
        if next > utf16 {
            return i;
        }
        units = next;
    }
    s.len()
}

/// Test helper: a performance budget in milliseconds, multiplied by the
/// `PW_PERF_SLACK` environment variable (default 1). CI sets it to 2 so only
/// regressions beyond twice the budget fail (phase-1.md §1.6), since shared
/// runners are slower than developer machines.
#[cfg(test)]
pub(crate) fn perf_budget_ms(base: u128) -> u128 {
    let slack = std::env::var("PW_PERF_SLACK")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|s| *s >= 1.0)
        .unwrap_or(1.0);
    (base as f64 * slack) as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_conversions_round_trip() {
        let s = "a🔑中b";
        assert_eq!(utf16_len(s), 5);
        assert_eq!(byte_to_utf16(s, 1), 1);
        assert_eq!(byte_to_utf16(s, 5), 3);
        assert_eq!(utf16_to_byte(s, 3), 5);
        assert_eq!(utf16_to_byte(s, 2), 1); // inside the surrogate pair
        assert_eq!(utf16_to_byte(s, 99), s.len());
    }
}
