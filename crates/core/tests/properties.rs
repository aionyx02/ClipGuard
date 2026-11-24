//! Property tests for engine invariants (phase-1.md §1.6). Fuzzing (fuzz/) checks
//! "never panics"; these check semantic invariants on generated inputs.

use paste_warden_core::secret::{self, PackSet, checksum};
use paste_warden_core::{command, hidden, limits};
use proptest::prelude::*;

/// Taiwan national IDs that pass the checksum: letter + [12] + 7 digits + check digit.
fn tw_id() -> impl Strategy<Value = String> {
    (
        b'A'..=b'Z',
        prop_oneof![Just('1'), Just('2')],
        proptest::collection::vec(0u8..10, 7),
    )
        .prop_filter_map("valid checksum", |(letter, sex, digits)| {
            let body: String = digits.iter().map(|d| char::from(b'0' + d)).collect();
            (0..10u8)
                .map(|c| format!("{}{}{}{}", letter as char, sex, body, c))
                .find(|id| checksum::is_valid_taiwan_id(id))
        })
}

/// Visa-like 16-digit card numbers that pass Luhn.
fn luhn_card() -> impl Strategy<Value = String> {
    proptest::collection::vec(0u8..10, 14).prop_filter_map("luhn", |digits| {
        let body: String = std::iter::once('4')
            .chain(digits.iter().map(|d| char::from(b'0' + d)))
            .collect();
        (0..10u8)
            .map(|c| format!("{body}{c}"))
            .find(|n| checksum::is_valid_luhn(n))
    })
}

/// Filler text that is unlikely to contain secrets itself.
fn filler() -> impl Strategy<Value = String> {
    "[a-zA-Z一-鿿 ,.。，\\n]{0,40}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A detected secret's full text never survives masking (P4).
    #[test]
    fn masking_removes_detected_secrets(
        before in filler(),
        id in tw_id(),
        card in luhn_card(),
        after in filler(),
    ) {
        let text = format!("{before} 身分證 {id} 卡號 {card} {after}");
        let matches = secret::find(&text, &PackSet::default());
        prop_assert!(!matches.is_empty(), "no secret found in {text:?}");
        let masked = secret::mask_text(&text, &matches, "[masked]");
        for m in &matches {
            let original = &text[m.span.clone()];
            if original.chars().count() >= 8 {
                prop_assert!(!masked.contains(original), "{original:?} survived masking: {masked:?}");
            }
            prop_assert!(!m.masked.contains(original), "mask string {:?} reveals {original:?}", m.masked);
        }
    }

    /// Spans always lie on char boundaries of the original text.
    #[test]
    fn secret_spans_are_char_boundaries(text in "\\PC{0,200}") {
        for packs in [PackSet::default(), PackSet::all()] {
            for m in secret::find(&text, &packs) {
                prop_assert!(m.span.end <= text.len());
                prop_assert!(text.is_char_boundary(m.span.start) && text.is_char_boundary(m.span.end));
            }
        }
    }

    /// Analysis is deterministic.
    #[test]
    fn command_analysis_is_deterministic(text in "\\PC{0,200}") {
        prop_assert_eq!(command::analyze(&text), command::analyze(&text));
        prop_assert_eq!(command::normalize(&text), command::normalize(&text));
        prop_assert_eq!(hidden::analyze(&text), hidden::analyze(&text));
    }

    /// `limits::prefix` returns a prefix of at most MAX_ANALYZED_CHARS chars.
    #[test]
    fn prefix_is_a_bounded_prefix(text in "\\PC{0,64}", repeat in 0usize..3) {
        let long = text.repeat(1 + repeat * 1000);
        let p = limits::prefix(&long);
        prop_assert!(long.starts_with(p));
        prop_assert!(p.chars().count() <= limits::MAX_ANALYZED_CHARS);
    }
}
