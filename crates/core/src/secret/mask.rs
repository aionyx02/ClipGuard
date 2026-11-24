//! Masking (legacy `SecretMasker` and `PasteGuard.MaskText`).

use super::{SecretKind, SecretMatch};
use crate::Message;
use crate::policy::paste::{self, MaskKind, MaskSpan};

/// At most this many `*` are shown: long keys do not need dozens of stars, and the
/// exact length stays hidden (legacy `SecretMasker.MaxStars`).
pub const MAX_STARS: usize = 8;

/// At least this many chars are always hidden (legacy `SecretMasker.MinHidden`).
pub const MIN_HIDDEN: usize = 4;

/// Fluent id of the text that replaces a PEM private-key body in "paste masked"
/// (shared with `policy::paste`).
pub const PEM_BODY_MASK_ID: &str = "paste-pem-body-mask";

/// The message that replaces a PEM private-key body (render it and pass it to [`mask_text`]).
pub fn pem_body_mask_message() -> Message {
    Message::new(PEM_BODY_MASK_ID)
}

/// Masks a value as `A12****789`: keeps `keep_start` leading and `keep_end` trailing
/// chars, replacing the middle with at most [`MAX_STARS`] stars. The kept counts
/// shrink (the larger one first, the end on ties) until at least [`MIN_HIDDEN`]
/// chars are hidden; very short values are fully hidden. Counts are in chars.
pub fn mask_value(value: &str, keep_start: usize, keep_end: usize) -> String {
    if value.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    let max_keep = len.saturating_sub(MIN_HIDDEN);
    let (mut ks, mut ke) = (keep_start, keep_end);
    while ks + ke > max_keep && (ks > 0 || ke > 0) {
        if ke >= ks && ke > 0 {
            ke -= 1;
        } else {
            ks -= 1;
        }
    }
    let hidden = len - ks - ke;
    let mut out = String::with_capacity(value.len());
    out.extend(&chars[..ks]);
    out.extend(std::iter::repeat_n('*', hidden.min(MAX_STARS)));
    out.extend(&chars[len - ke..]);
    out
}

/// "Paste masked" (legacy `PasteGuard.MaskText`): replaces every match in `text` with
/// its mask, in position order; overlapping or out-of-range matches are skipped.
/// Registered secrets become `policy::paste::REGISTERED_MASK`; a PEM private-key
/// header is kept and everything after it up to the next `-----END ` (or the end) is
/// replaced by `pem_body_mask` (the rendered [`pem_body_mask_message`]) on its own
/// line. `matches` must come from the same `text`. Delegates to
/// [`crate::policy::paste::mask_text`] (phase-1 §1.8: one implementation).
pub fn mask_text(text: &str, matches: &[SecretMatch], pem_body_mask: &str) -> String {
    let spans: Vec<MaskSpan<'_>> = matches
        .iter()
        .map(|m| MaskSpan {
            range: m.span.clone(),
            kind: match m.kind {
                SecretKind::Registered => MaskKind::Registered,
                SecretKind::ApiKey => MaskKind::ApiKey,
                _ => MaskKind::Other,
            },
            masked: &m.masked,
        })
        .collect();
    paste::mask_text(text, &spans, pem_body_mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_value_shapes() {
        assert_eq!(mask_value("A123456789", 3, 3), "A12****789");
        assert_eq!(mask_value("", 3, 3), "");
        assert_eq!(mask_value("abcd", 3, 3), "****");
        assert_eq!(mask_value("abcdef", 3, 3), "a****f");
        assert_eq!(mask_value(&"x".repeat(40), 0, 3), "********xxx");
    }

    #[test]
    fn mask_text_skips_overlaps_and_bad_spans() {
        let m = |s: usize, e: usize| SecretMatch {
            kind: SecretKind::ApiKey,
            rule_id: "t".into(),
            label: Message::new("x"),
            masked: "M".into(),
            span: s..e,
        };
        assert_eq!(
            mask_text("abcdef", &[m(1, 3), m(2, 4), m(5, 99)], "P"),
            "aMdef"
        );
        assert_eq!(mask_text("中文", &[m(1, 3)], "P"), "中文");
    }
}
