//! The secret-rule engine (legacy `SecretRules` + `SecretDetector`).
//!
//! Flow per segment: normalize (§5.0) → ASCII view (non-ASCII chars become U+001A, one
//! byte per normalized char, so byte offsets in the view are char indices in the
//! normalized text) → for each active rule in priority order: keyword prefilter,
//! context prefilter, regex or finder candidates, acceptance checks → mask → map the
//! span back to the original text. Results of each rule are merged in priority order;
//! later rules lose overlaps.

use std::ops::Range;
use std::sync::OnceLock;

use paste_warden_rules::secret::{
    self as rules, ContextDef, EntropySpec, ExclusionTarget, MaskSpec, Matcher, RuleDef,
    RuleLoadError,
};
use regex::bytes::Regex;
use zeroize::Zeroizing;

use super::normalize::{Normalized, normalize};
use super::{PackSet, SecretKind, SecretMatch, mask, mnemonic, pii};
use crate::Message;

/// Longest text analyzed in full, in chars. Longer texts are analyzed at the head and
/// the tail (half each); secrets tend to sit at either end (`.env`, last log lines).
/// Equals the clipboard read limit (legacy `SecretDetector.MaxScanLength`).
pub const MAX_SCAN_LENGTH: usize = 1 << 20;

/// Segment step in chars (legacy `SecretDetector.SegmentStep`).
pub const SEGMENT_STEP: usize = 64 * 1024;

/// Each segment looks this many chars past its end, so any secret shorter than this
/// lies entirely in the segment where it starts (legacy `SecretDetector.Overlap`).
pub const OVERLAP: usize = 8 * 1024;

/// Each segment looks this many chars before its start, for `notPrecededBy` and
/// context keywords (window 32 + keyword 24; legacy `SecretDetector.Context`).
pub const CONTEXT: usize = 64;

/// `notFollowedBy` sees at most this many chars after a match.
pub const NOT_FOLLOWED_BY_WINDOW: usize = 64;

/// Key names (`exclude` target `key`) extend back at most this many chars.
pub const MAX_KEY_EXTENSION: usize = 40;

/// Fluent id of a rule's display label. Arguments: `id` (rule id) and `label` (the
/// rule file's label, used when the locale has no translation for `id`).
pub const RULE_LABEL_ID: &str = "secret-rule-label";

/// Mask of a `word-count` rule (BIP-39 phrase): stars plus the word count, e.g.
/// `******** (12)`. Nothing of the words is kept; the label carries the count too
/// (argument `words`).
pub const WORD_COUNT_MASK_STARS: &str = "********";

/// Byte that replaces every non-ASCII char in the ASCII view.
const SUBSTITUTE: u8 = 0x1A;

/// A compiled rule: the definition plus lazily compiled regexes.
pub struct Rule {
    pub def: RuleDef,
    kind: SecretKind,
    regex: OnceLock<Option<Regex>>,
    not_preceded_by: OnceLock<Option<Regex>>,
    not_followed_by: OnceLock<Option<Regex>>,
    exclusions: OnceLock<Vec<Option<Regex>>>,
    context: Option<Context>,
}

struct Context {
    keywords: Vec<Vec<char>>,
    keyword_strs: Vec<String>,
    before: usize,
    after: usize,
}

impl Context {
    fn new(def: &ContextDef) -> Context {
        Context {
            keywords: def.keywords.iter().map(|k| k.chars().collect()).collect(),
            keyword_strs: def.keywords.clone(),
            before: def.before,
            after: def.after,
        }
    }

    /// Is a keyword within the window around normalized chars `[index, index + len)`?
    fn present(&self, lower: &[char], index: usize, len: usize) -> bool {
        let end = index + len;
        for k in &self.keywords {
            let kl = k.len();
            if kl == 0 {
                continue;
            }
            if self.before > 0 {
                // The keyword lies wholly before the secret and ends in [index - before, index].
                let from = index.saturating_sub(self.before + kl);
                let mut p = from;
                while p + kl <= index {
                    if lower.get(p..p + kl) == Some(k.as_slice()) && is_word(lower, p, kl) {
                        return true;
                    }
                    p += 1;
                }
            }
            if self.after > 0 && end < lower.len() {
                // The keyword starts in [end, end + after].
                let limit = lower.len().min(end + self.after + kl);
                let mut p = end;
                while p + kl <= limit {
                    if lower.get(p..p + kl) == Some(k.as_slice()) && is_word(lower, p, kl) {
                        return true;
                    }
                    p += 1;
                }
            }
        }
        false
    }
}

/// A keyword that starts or ends with an ASCII letter may not touch another ASCII
/// letter on that side (`vat` does not match inside `private`).
fn is_word(s: &[char], start: usize, len: usize) -> bool {
    let end = start + len;
    if s[start].is_ascii_lowercase() && start > 0 && s[start - 1].is_ascii_alphabetic() {
        return false;
    }
    if s[end - 1].is_ascii_lowercase() && end < s.len() && s[end].is_ascii_alphabetic() {
        return false;
    }
    true
}

/// A match on the ASCII view, with the group the secret came from.
struct Hit {
    start: usize,
    end: usize,
    /// Group 1's span when the regex has groups (for `key` exclusions).
    group1: Option<Option<(usize, usize)>>,
}

impl Rule {
    fn new(def: RuleDef) -> Rule {
        Rule {
            kind: SecretKind::from(def.kind),
            context: def.context.as_ref().map(Context::new),
            def,
            regex: OnceLock::new(),
            not_preceded_by: OnceLock::new(),
            not_followed_by: OnceLock::new(),
            exclusions: OnceLock::new(),
        }
    }

    pub fn kind(&self) -> SecretKind {
        self.kind
    }

    /// The localizable display label (see [`RULE_LABEL_ID`]).
    pub fn label(&self) -> Message {
        rule_label(&self.def.id, &self.def.label)
    }

    fn regex(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| match &self.def.matcher {
                Matcher::Regex {
                    pattern,
                    ignore_case,
                } => rules::compile(pattern, *ignore_case).ok(),
                Matcher::Finder(_) => None,
            })
            .as_ref()
    }

    fn not_preceded_by(&self) -> Option<&Regex> {
        self.not_preceded_by
            .get_or_init(|| {
                self.def
                    .not_preceded_by
                    .as_deref()
                    .and_then(|p| rules::compile_not_preceded_by(p).ok())
            })
            .as_ref()
    }

    fn not_followed_by(&self) -> Option<&Regex> {
        self.not_followed_by
            .get_or_init(|| {
                self.def
                    .not_followed_by
                    .as_deref()
                    .and_then(|p| rules::compile_not_followed_by(p).ok())
            })
            .as_ref()
    }

    fn exclusions(&self) -> &[Option<Regex>] {
        self.exclusions.get_or_init(|| {
            self.def
                .exclusions
                .iter()
                .map(|e| rules::compile(&e.pattern, false).ok())
                .collect()
        })
    }

    fn keywords_present(&self, lower: &str) -> bool {
        self.def.keywords.is_empty() || self.def.keywords.iter().any(|k| lower.contains(k.as_str()))
    }

    /// The localizable display label of one match: [`Rule::label`], plus the
    /// argument `words` for `word-count` rules.
    fn match_label(&self, words: Option<usize>) -> Message {
        match words {
            Some(n) => self.label().arg("words", n),
            None => self.label(),
        }
    }

    /// Word count of `secret` when this rule masks by word count.
    fn words_of(&self, secret: &str) -> Option<usize> {
        matches!(self.def.mask, MaskSpec::WordCount).then(|| mnemonic::word_count(secret))
    }

    /// The mask shown for `secret` (PEM headers are shown as is).
    pub fn mask(&self, secret: &str) -> String {
        match &self.def.mask {
            MaskSpec::PemBlock => secret.to_owned(),
            MaskSpec::WordCount => {
                format!("{WORD_COUNT_MASK_STARS} ({})", mnemonic::word_count(secret))
            }
            MaskSpec::Keep {
                keep_start,
                keep_end,
                canonical,
            } => match canonical {
                Some(c) => {
                    let canon = Zeroizing::new(pii::canonical(*c, secret));
                    mask::mask_value(&canon, *keep_start, *keep_end)
                }
                None => mask::mask_value(secret, *keep_start, *keep_end),
            },
        }
    }

    /// Finds this rule's secrets in `ascii` (the ASCII view of `chars`). Returns
    /// `(index, len, secret)` in normalized-char positions. `ctx_lower` is the
    /// ASCII-lower-cased normalized text (needed when the rule has a context).
    fn scan(
        &self,
        ascii: &[u8],
        chars: &[char],
        ctx_lower: Option<&[char]>,
    ) -> Vec<(usize, usize, Zeroizing<String>)> {
        let mut out = Vec::new();
        let secret_of = |i: usize, len: usize| -> Zeroizing<String> {
            Zeroizing::new(chars.get(i..i + len).unwrap_or_default().iter().collect())
        };
        match &self.def.matcher {
            Matcher::Finder(finder) => {
                let candidates = match finder {
                    rules::FinderKind::CardGroups => pii::card_candidates(ascii),
                    rules::FinderKind::Bip39 => mnemonic::candidates(ascii),
                };
                for (index, len) in candidates {
                    if len < self.def.min_length || len > self.def.max_length {
                        continue;
                    }
                    let secret = secret_of(index, len);
                    if self.accept(&secret, None, index, len, ascii, ctx_lower) {
                        out.push((index, len, secret));
                    }
                }
            }
            Matcher::Regex { .. } => {
                let Some(re) = self.regex() else {
                    return out;
                };
                let npb = self.not_preceded_by();
                let nfb = self.not_followed_by();
                let has_groups = re.captures_len() > 1;
                let mut handle = |start: usize,
                                  end: usize,
                                  group: Option<(usize, usize)>,
                                  group1| {
                    if let Some(r) = npb
                        && start > 0
                        && r.is_match(&ascii[start - 1..start])
                    {
                        return;
                    }
                    if let Some(r) = nfb
                        && end < ascii.len()
                        && r.is_match(&ascii[end..ascii.len().min(end + NOT_FOLLOWED_BY_WINDOW)])
                    {
                        return;
                    }
                    let Some((gs, ge)) = group else {
                        return;
                    };
                    let len = ge - gs;
                    if len < self.def.min_length || len > self.def.max_length {
                        return;
                    }
                    let secret = secret_of(gs, len);
                    let hit = Hit { start, end, group1 };
                    if self.accept(&secret, Some(&hit), gs, len, ascii, ctx_lower) {
                        out.push((gs, len, secret));
                    }
                };
                if has_groups {
                    for caps in re.captures_iter(ascii) {
                        let Some(m) = caps.get(0) else {
                            continue;
                        };
                        let span = |g: regex::bytes::Match<'_>| (g.start(), g.end());
                        let group = match self.def.secret_group {
                            Some(n) => caps.get(n).map(span),
                            None => (1..caps.len())
                                .filter_map(|k| caps.get(k))
                                .find(|g| !g.is_empty())
                                .map(span)
                                .or(Some(span(m))),
                        };
                        let group1 = Some(caps.get(1).map(span));
                        handle(m.start(), m.end(), group, group1);
                    }
                } else {
                    for m in re.find_iter(ascii) {
                        let group = match self.def.secret_group {
                            Some(n) if n > 0 => None,
                            _ => Some((m.start(), m.end())),
                        };
                        handle(m.start(), m.end(), group, None);
                    }
                }
            }
        }
        out
    }

    fn accept(
        &self,
        secret: &str,
        hit: Option<&Hit>,
        index: usize,
        len: usize,
        ascii: &[u8],
        ctx_lower: Option<&[char]>,
    ) -> bool {
        let d = &self.def;
        if let Some(e) = &d.entropy
            && entropy(secret) <= threshold(e, secret)
        {
            return false;
        }
        if d.digit_required_below > 0
            && secret.chars().count() < d.digit_required_below
            && !secret.chars().any(|c| c.is_ascii_digit())
        {
            return false;
        }
        if d.reject_sequential && is_sequential(secret) {
            return false;
        }
        if !d.stopwords.is_empty() {
            let lower = Zeroizing::new(secret.to_lowercase());
            if d.stopwords.iter().any(|w| lower.contains(w.as_str())) {
                return false;
            }
        }
        for (e, re) in d.exclusions.iter().zip(self.exclusions()) {
            let Some(re) = re else {
                continue;
            };
            let target: Zeroizing<Vec<u8>> = Zeroizing::new(match (e.target, hit) {
                (ExclusionTarget::Match, Some(h)) => ascii[h.start..h.end].to_vec(),
                (ExclusionTarget::Line, Some(h)) => line_of(ascii, h.start, h.end).to_vec(),
                (ExclusionTarget::Line, None) => line_of(ascii, index, index + len).to_vec(),
                (ExclusionTarget::Key, Some(h)) => key_of(ascii, h).to_vec(),
                _ => secret.as_bytes().to_vec(),
            });
            let target = if e.ignore_case {
                match std::str::from_utf8(&target) {
                    Ok(s) => Zeroizing::new(s.to_lowercase().into_bytes()),
                    Err(_) => Zeroizing::new(target.to_ascii_lowercase()),
                }
            } else {
                target
            };
            if re.is_match(&target) {
                return false;
            }
        }
        if let Some(v) = d.validate
            && !pii::validate(v, secret)
        {
            return false;
        }
        match (&self.context, ctx_lower) {
            (None, _) => true,
            (Some(c), Some(lower)) => c.present(lower, index, len),
            (Some(_), None) => false,
        }
    }
}

fn line_of(s: &[u8], start: usize, end: usize) -> &[u8] {
    let a = s[..start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);
    let b = s[end.min(s.len())..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(s.len(), |p| end + p);
    &s[a..b]
}

/// Key name: group 1 (or the whole match) extended back over the identifier, at most
/// [`MAX_KEY_EXTENSION`] chars (`MY_SECRET`, not just `SECRET`).
fn key_of<'a>(s: &'a [u8], hit: &Hit) -> &'a [u8] {
    let (gs, ge) = match hit.group1 {
        Some(Some(g)) => g,
        Some(None) => (0, 0),
        None => (hit.start, hit.end),
    };
    let limit = gs.saturating_sub(MAX_KEY_EXTENSION);
    let mut start = gs;
    while start > limit && is_key_char(s[start - 1]) {
        start -= 1;
    }
    &s[start..ge]
}

fn is_key_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')
}

/// Shannon entropy in bits per char (same as gitleaks).
pub fn entropy(s: &str) -> f64 {
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    counts
        .values()
        .map(|&k| {
            let p = k as f64 / n;
            -p * p.log2()
        })
        .sum()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charset {
    Hex,
    Base36,
    Base64,
}

fn charset(s: &str) -> Charset {
    // Hex with dashes (UUID) counts as hex.
    if s.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        Charset::Hex
    } else if s
        .chars()
        .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
        || s.chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
    {
        Charset::Base36
    } else {
        Charset::Base64
    }
}

fn threshold(e: &EntropySpec, secret: &str) -> f64 {
    match e {
        EntropySpec::Fixed(f) => *f,
        EntropySpec::ByCharset {
            hex,
            base36,
            base64,
        } => {
            let [a, b, cap] = match charset(secret) {
                Charset::Hex => *hex,
                Charset::Base36 => *base36,
                Charset::Base64 => *base64,
            };
            cap.min(a + b * (secret.chars().count() as f64).log2())
        }
    }
}

/// At least half of the adjacent pairs are equal or consecutive (`aaaa`,
/// `0123456789abcdef`): not a random key.
pub fn is_sequential(s: &str) -> bool {
    let cs: Vec<u32> = s.chars().map(u32::from).collect();
    if cs.len() < 2 {
        return true;
    }
    let close = cs.windows(2).filter(|w| w[0].abs_diff(w[1]) <= 1).count();
    close * 2 >= cs.len() - 1
}

/// Display label of a rule (see [`RULE_LABEL_ID`]).
pub fn rule_label(id: &str, label: &str) -> Message {
    Message::new(RULE_LABEL_ID)
        .arg("id", id)
        .arg("label", label)
}

/// A set of compiled rules, in priority order.
pub struct RuleSet {
    rules: Vec<Rule>,
}

/// The built-in rules (`rules/*.json`), parsed once. Regexes compile lazily.
pub fn builtin() -> &'static RuleSet {
    static B: OnceLock<RuleSet> = OnceLock::new();
    B.get_or_init(|| RuleSet::from_defs(rules::load_embedded().unwrap_or_default()))
}

/// One accepted match before merging.
struct Found {
    rule: usize,
    masked: String,
    /// Word count (`word-count` rules), for the label.
    words: Option<usize>,
    bytes: Range<usize>,
    chars: Range<usize>,
}

impl RuleSet {
    pub fn from_defs(defs: Vec<RuleDef>) -> RuleSet {
        RuleSet {
            rules: defs.into_iter().map(Rule::new).collect(),
        }
    }

    /// Loads only `files` (legacy `SecretRules.Load`), validating and compiling them.
    pub fn load<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<RuleSet, RuleLoadError> {
        Ok(RuleSet::from_defs(rules::load(files)?))
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Scans `text` with the first rule only, on its ASCII view, without normalizing,
    /// segmenting or merging (legacy `rules[0].Scan(text, text)`); returns the count.
    pub fn scan_first(&self, text: &str) -> usize {
        let Some(rule) = self.rules.first() else {
            return 0;
        };
        let chars: Zeroizing<Vec<char>> = Zeroizing::new(text.chars().collect());
        let ascii = ascii_view(&chars);
        let lower = rule.context.as_ref().map(|_| ascii_lower(&chars));
        rule.scan(&ascii, &chars, lower.as_deref().map(|v| v.as_slice()))
            .len()
    }

    /// Finds secrets in `text` with the rules of `packs` (legacy `SecretDetector.Find`).
    pub fn find(&self, text: &str, packs: &PackSet) -> Vec<SecretMatch> {
        if text.is_empty() {
            return Vec::new();
        }
        let active: Vec<bool> = self
            .rules
            .iter()
            .map(|r| packs.contains(&r.def.pack))
            .collect();
        let mut by_rank: Vec<Vec<Found>> = (0..self.rules.len()).map(|_| Vec::new()).collect();

        let n = text.chars().count();
        let ranges: Vec<(usize, usize)> = if n <= MAX_SCAN_LENGTH {
            vec![(0, n)]
        } else {
            vec![(0, MAX_SCAN_LENGTH / 2), (n - MAX_SCAN_LENGTH / 2, n)]
        };
        let mut start_cur = CharCursor::default();
        let mut end_cur = CharCursor::default();
        for (from, to) in ranges {
            let mut s = from;
            while s < to {
                let owned_end = (s + SEGMENT_STEP).min(to);
                let seg_start = s.saturating_sub(CONTEXT);
                let seg_end = (owned_end + OVERLAP).min(n);
                let b0 = start_cur.advance(text, seg_start);
                let b1 = end_cur.advance(text, seg_end);
                let norm = normalize(text.get(b0..b1).unwrap_or_default(), b0, seg_start);
                self.find_in_segment(&norm, &active, &mut |rank, f: Found| {
                    // Keep only results starting in this segment's own range; results
                    // touching the segment end may be cut and belong to the next one.
                    if f.chars.start < s || f.chars.start >= owned_end {
                        return;
                    }
                    if seg_end < n && f.chars.end >= seg_end {
                        return;
                    }
                    if let Some(list) = by_rank.get_mut(rank) {
                        list.push(f);
                    }
                });
                s += SEGMENT_STEP;
            }
        }

        let mut kept: Vec<Found> = Vec::new();
        for list in by_rank {
            kept = merge(kept, list);
        }
        kept.into_iter()
            .filter_map(|f| {
                let rule = self.rules.get(f.rule)?;
                Some(SecretMatch {
                    kind: rule.kind,
                    rule_id: rule.def.id.clone(),
                    label: rule.match_label(f.words),
                    masked: f.masked,
                    span: f.bytes,
                })
            })
            .collect()
    }

    fn find_in_segment(
        &self,
        norm: &Normalized,
        active: &[bool],
        add: &mut dyn FnMut(usize, Found),
    ) {
        let chars = &norm.chars;
        let ascii = ascii_view(chars);
        let lower_ascii: Zeroizing<Vec<u8>> = Zeroizing::new(ascii.to_ascii_lowercase());
        let lower_str = std::str::from_utf8(&lower_ascii).unwrap_or_default();
        let mut ctx_lower: Option<(Zeroizing<Vec<char>>, Zeroizing<String>)> = None;
        for (k, rule) in self.rules.iter().enumerate() {
            if !active.get(k).copied().unwrap_or(false) || !rule.keywords_present(lower_str) {
                continue;
            }
            if let Some(c) = &rule.context {
                let (_, s) = ctx_lower.get_or_insert_with(|| {
                    let v = ascii_lower(chars);
                    let s = Zeroizing::new(v.iter().collect::<String>());
                    (v, s)
                });
                if !c.keyword_strs.iter().any(|kw| s.contains(kw.as_str())) {
                    continue;
                }
            }
            let lower = ctx_lower.as_ref().map(|(v, _)| v.as_slice());
            for (index, len, secret) in rule.scan(&ascii, chars, lower) {
                let Some(o) = norm.to_original(index, len) else {
                    continue;
                };
                add(
                    k,
                    Found {
                        rule: k,
                        masked: rule.mask(&secret),
                        words: rule.words_of(&secret),
                        bytes: o.byte_start..o.byte_end,
                        chars: o.char_start..o.char_end,
                    },
                );
            }
        }
    }
}

/// Merges the next priority's results into the kept list. Both lists are sorted and
/// non-overlapping; candidates overlapping a kept result are dropped. Linear time.
fn merge(kept: Vec<Found>, next: Vec<Found>) -> Vec<Found> {
    if next.is_empty() {
        return kept;
    }
    let mut result: Vec<Found> = Vec::with_capacity(kept.len() + next.len());
    let mut kept = kept.into_iter().peekable();
    for m in next {
        while let Some(k) = kept.peek() {
            if k.bytes.end <= m.bytes.start {
                if let Some(k) = kept.next() {
                    result.push(k);
                }
            } else {
                break;
            }
        }
        if kept.peek().is_some_and(|k| k.bytes.start < m.bytes.end) {
            continue;
        }
        if result.last().is_some_and(|r| r.bytes.end > m.bytes.start) {
            continue;
        }
        result.push(m);
    }
    result.extend(kept);
    result
}

/// ASCII view: one byte per char; non-ASCII chars become U+001A.
fn ascii_view(chars: &[char]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        chars
            .iter()
            .map(|&c| if c.is_ascii() { c as u8 } else { SUBSTITUTE })
            .collect(),
    )
}

/// Lower-cases A–Z only (length-preserving).
fn ascii_lower(chars: &[char]) -> Zeroizing<Vec<char>> {
    Zeroizing::new(chars.iter().map(char::to_ascii_lowercase).collect())
}

/// Maps increasing char indices to byte offsets in one forward pass.
#[derive(Default)]
struct CharCursor {
    chars: usize,
    bytes: usize,
}

impl CharCursor {
    fn advance(&mut self, text: &str, target: usize) -> usize {
        if target < self.chars {
            // Not expected (targets increase); restart from the beginning.
            *self = CharCursor::default();
        }
        let rest = text.get(self.bytes..).unwrap_or_default();
        for c in rest.chars() {
            if self.chars >= target {
                break;
            }
            self.chars += 1;
            self.bytes += c.len_utf8();
        }
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_and_entropy() {
        assert!(is_sequential("aaaa"));
        assert!(is_sequential("0123456789abcdef"));
        assert!(!is_sequential("a8Kq2Zp0"));
        assert_eq!(entropy(""), 0.0);
        assert!((entropy("ab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn cursor_maps_chars_to_bytes() {
        let t = "a中b🔑c";
        let mut c = CharCursor::default();
        assert_eq!(c.advance(t, 1), 1);
        assert_eq!(c.advance(t, 3), 5);
        assert_eq!(c.advance(t, 99), t.len());
        assert_eq!(c.advance(t, 2), 4);
    }

    #[test]
    fn line_and_key() {
        let s = b"a\nMY_SECRET=x\nb";
        assert_eq!(line_of(s, 5, 7), b"MY_SECRET=x");
        let hit = Hit {
            start: 5,
            end: 13,
            group1: Some(Some((5, 11))),
        };
        assert_eq!(key_of(s, &hit), b"MY_SECRET");
    }
}

/// Legacy performance properties (corpus/legacy-properties/secret-*.jsonl). Ignored by
/// default; run with `cargo test --release -p paste-warden-core -- --ignored --nocapture`.
#[cfg(test)]
mod perf {
    use super::*;
    use std::time::{Duration, Instant};

    fn fill(unit: &str, len: usize) -> String {
        unit.chars().cycle().take(len).collect()
    }

    fn time<T>(f: impl FnOnce() -> T) -> Duration {
        let t = Instant::now();
        std::hint::black_box(f());
        t.elapsed()
    }

    /// Phase 1b pathological units (each repeated to 1 Mi chars).
    const PATHOLOGICAL_1B: &[&str] = &[
        "abandon ",
        "1. abandon\n",
        "abandon, ",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote\n",
        "curl ",
        "curl\n",
        "curl -H \"Authorization: ",
        "curl -H 'X-Key: aaaaaaaa ",
        "curl -u a",
        "curl -u aaa:",
        "postgres://",
        "postgres://a:",
        "postgres://a:b",
        "redis://:a@",
        "Server=a;",
        "Server=a;b=c;",
        "Server=a;Password=",
        "密碼：",
        "密碼：a",
        "金鑰 = \"aB3",
    ];

    fn scan_rule(rule: &Rule, text: &str) -> usize {
        let chars: Vec<char> = text.chars().collect();
        let ascii = ascii_view(&chars);
        let lower = ascii_lower(&chars);
        rule.scan(&ascii, &chars, Some(&lower)).len()
    }

    #[test]
    #[ignore]
    fn each_rule_is_linear_on_1mi_inputs() {
        const N: usize = 1 << 20;
        let set = builtin();
        let mut worst = (Duration::ZERO, String::new());
        for rule in set.rules() {
            let kw = rule
                .def
                .keywords
                .first()
                .cloned()
                .unwrap_or_else(|| "key".into());
            let mut inputs = vec![
                fill(&format!("{kw} "), N),
                fill(&format!("{kw}="), N),
                fill(&format!("{kw} = \""), N),
                fill(&format!("{kw}{} ", "a".repeat(40)), N),
                format!("{kw}{}", "a".repeat(N.saturating_sub(kw.len()))),
            ];
            // Phase 1b: BIP-39 runs, curl headers / credentials over many lines,
            // connection strings, CJK key names.
            for u in PATHOLOGICAL_1B {
                inputs.push(fill(u, N));
            }
            if rule.kind != SecretKind::ApiKey {
                for u in [
                    "1",
                    "1 ",
                    "+1 ",
                    "+123456789012345 ",
                    "A1",
                    "DE89 ",
                    "DE8937040044",
                    "A123456(",
                    "SSN 078-05-1120 ",
                    "マイナンバー 1234 5678 9018 ",
                    "주민등록번호 900101-1234567 ",
                    "統編 12345675 ",
                    "ssn マイナンバー 주민번호 hkid 統編 ",
                    "A123456789 ",
                ] {
                    inputs.push(fill(u, N));
                }
            }
            for input in &inputs {
                let d = time(|| scan_rule(rule, input));
                if d > worst.0 {
                    worst = (d, rule.def.id.clone());
                }
            }
        }
        println!("slowest rule: {} {:?}", worst.1, worst.0);
        assert!(worst.0 < Duration::from_millis(2000));
    }

    #[test]
    #[ignore]
    fn find_on_1mi_inputs() {
        const N: usize = MAX_SCAN_LENGTH;
        let set = builtin();
        let mut kws: Vec<String> = set
            .rules()
            .iter()
            .flat_map(|r| r.def.keywords.clone())
            .collect();
        kws.sort();
        kws.dedup();
        let key40 = "aZ3kQ9xW2mP7vB1nR8tY4uI6oL0sD5fG3hJ2kL9z";
        let all_kw = format!("{} = \"{key40}\"\n", kws.join(" = \""));
        let inputs = [
            fill(&all_kw, N),
            fill("API_TOKEN=aZ3kQ9xW2mP7vB1nR8tY4uI6oL0sD5fG\n", N),
            fill("Authorization: Bearer ", N),
            fill("var token=e.token,secret=t.secret||\"\",apiKey=null;", N),
            fill("A123456789 ", N),
            fill("統編 12345675 ", N),
            fill("マイナンバー 1234 5678 9018 ", N),
            fill("abandon ", N),
            fill("1. abandon\n", N),
            fill("curl -u aaa:", N),
            fill("curl\n", N),
            fill("curl -H \"Authorization: ", N),
            fill("Server=a;b=c;", N),
            fill("postgres://a:b", N),
            fill("密碼：aB3", N),
        ];
        let all = PackSet::all();
        for (i, input) in inputs.iter().enumerate() {
            let d = time(|| set.find(input, &PackSet::default()).len());
            let a = time(|| set.find(input, &all).len());
            println!("find input {i}: default {d:?}, all packs {a:?}");
            assert!(d < Duration::from_millis(3000) && a < Duration::from_millis(3000));
        }
        for (unit, count) in [
            (" ", 4_000_000),
            ("１", 4_000_000),
            ("4111 ", 800_000),
            ("\u{200B}", 4_000_000),
            ("今天天氣很好，（星期三）。", 300_000),
            ("x", 20_000_000),
        ] {
            let input = unit.repeat(count);
            let d = time(|| set.find(&input, &PackSet::default()).len());
            println!("find {unit:?} x {count}: {d:?}");
            assert!(d < Duration::from_secs(5));
        }
    }
}
