//! Secret rules in `rules/*.json` (format 1, docs/spec/detection-rules.md §5.4).
//!
//! This module parses and validates rule files into [`RuleDef`]s (plain data) and
//! knows how to turn a rule-file regex into a Rust [`regex::bytes::Regex`]. The
//! matching engine itself lives in `paste-warden-core` (`secret::engine`).
//!
//! Regex dialect: rule regexes are matched against an "ASCII view" of the text
//! (every non-ASCII char replaced by U+001A, one byte per char), so they are
//! compiled with `unicode(false)`: `\b`, `\w`, `\d`, `\s` and case-insensitivity
//! only know ASCII, exactly like the legacy .NET / JS engines on that view. `$`
//! means "end of text" (Rust's default without multi-line mode, which is what the
//! legacy engine achieved by rewriting `$` to `\z`).

use std::fmt;

use regex::bytes::{Regex, RegexBuilder};
use serde_json::{Map, Value};

/// Pack name of the always-on pack (legacy `SecretPacks.Universal`).
pub const UNIVERSAL: &str = "universal";

/// Default number of trailing characters kept when masking (legacy `SecretRules.DefaultKeepEnd`).
pub const DEFAULT_KEEP_END: usize = 3;

/// Context windows may not exceed this many chars (legacy `ContextSpec.MaxWindow`); the
/// detector looks back 64 chars before each segment, which must cover window + keyword.
pub const MAX_CONTEXT_WINDOW: usize = 32;

/// Longest allowed context keyword in chars (legacy `ContextSpec.MaxKeywordLength`).
pub const MAX_CONTEXT_KEYWORD: usize = 24;

/// Compiled-program size limit per rule regex. Generous: counted repetitions such as
/// `[A-Za-z0-9_-]{2,6144}` (JWT) expand into many NFA states.
pub const REGEX_SIZE_LIMIT: usize = 64 << 20;

/// The built-in rule files, embedded at compile time: `(file name, JSON)`, sorted by name.
pub const EMBEDDED: &[(&str, &str)] = &[
    (
        "api-keys.json",
        include_str!("../../../rules/api-keys.json"),
    ),
    (
        "connection-strings.json",
        include_str!("../../../rules/connection-strings.json"),
    ),
    ("context.json", include_str!("../../../rules/context.json")),
    (
        "gitleaks-late.json",
        include_str!("../../../rules/gitleaks-late.json"),
    ),
    (
        "gitleaks.json",
        include_str!("../../../rules/gitleaks.json"),
    ),
    (
        "mnemonic.json",
        include_str!("../../../rules/mnemonic.json"),
    ),
    ("pii-cn.json", include_str!("../../../rules/pii-cn.json")),
    ("pii-hk.json", include_str!("../../../rules/pii-hk.json")),
    ("pii-jp.json", include_str!("../../../rules/pii-jp.json")),
    ("pii-kr.json", include_str!("../../../rules/pii-kr.json")),
    ("pii-sg.json", include_str!("../../../rules/pii-sg.json")),
    ("pii-tw.json", include_str!("../../../rules/pii-tw.json")),
    (
        "pii-universal.json",
        include_str!("../../../rules/pii-universal.json"),
    ),
    ("pii-us.json", include_str!("../../../rules/pii-us.json")),
];

/// The official BIP-39 English word list (`rules/secret/bip39-english.txt`, MIT, from
/// bitcoin/bips; see THIRD_PARTY_NOTICES.md): 2048 lines, sorted, so a word's index
/// is its 11-bit value.
pub const BIP39_ENGLISH: &str = include_str!("../../../rules/secret/bip39-english.txt");

/// Number of words in a BIP-39 word list.
pub const BIP39_WORD_COUNT: usize = 2048;

/// Parses and validates a BIP-39 word list: exactly [`BIP39_WORD_COUNT`] lines of
/// 3–8 lower-case ASCII letters, strictly ascending (so binary search gives the
/// index), with a trailing newline at most.
pub fn parse_bip39_words(text: &str) -> Result<Vec<&str>, String> {
    let words: Vec<&str> = text
        .strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .collect();
    if words.len() != BIP39_WORD_COUNT {
        return Err(format!(
            "BIP-39 word list must have {BIP39_WORD_COUNT} words, has {}",
            words.len()
        ));
    }
    for (i, w) in words.iter().enumerate() {
        if !(3..=8).contains(&w.len()) || !w.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(format!(
                "BIP-39 word {i} is not 3–8 lower-case letters: {w:?}"
            ));
        }
        if i > 0 && words[i - 1] >= *w {
            return Err(format!("BIP-39 word list is not sorted at {i}: {w:?}"));
        }
    }
    Ok(words)
}

/// What a rule detects (rule-file `kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleKind {
    ApiKey,
    NationalId,
    ResidentCertificate,
    BusinessId,
    CreditCard,
    MobilePhone,
    PhoneNumber,
    BankAccount,
    /// BIP-39 recovery phrase (phase 1b).
    Mnemonic,
}

impl RuleKind {
    fn parse(s: &str) -> Option<RuleKind> {
        Some(match s {
            "api-key" => RuleKind::ApiKey,
            "national-id" => RuleKind::NationalId,
            "resident-certificate" => RuleKind::ResidentCertificate,
            "business-id" => RuleKind::BusinessId,
            "credit-card" => RuleKind::CreditCard,
            "mobile-phone" => RuleKind::MobilePhone,
            "phone-number" => RuleKind::PhoneNumber,
            "bank-account" => RuleKind::BankAccount,
            "mnemonic" => RuleKind::Mnemonic,
            _ => return None,
        })
    }
}

/// Programmatic candidate generators (`finder`), for formats a regex cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinderKind {
    /// Credit-card digit groups (legacy `PiiFormats.CardCandidates`).
    CardGroups,
    /// Runs of 12/15/18/21/24 BIP-39 words with a valid checksum (phase 1b; word
    /// list [`BIP39_ENGLISH`]).
    Bip39,
}

/// Extra validation (`validate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorKind {
    JwtHeader,
    TwId,
    TwUbn,
    Iban,
    E164,
    CnId,
    JpMyNumber,
    HkId,
    SgNric,
    UsSsn,
}

impl ValidatorKind {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "jwt-header" => Self::JwtHeader,
            "tw-id" => Self::TwId,
            "tw-ubn" => Self::TwUbn,
            "iban" => Self::Iban,
            "e164" => Self::E164,
            "cn-id" => Self::CnId,
            "jp-my-number" => Self::JpMyNumber,
            "hk-id" => Self::HkId,
            "sg-nric" => Self::SgNric,
            "us-ssn" => Self::UsSsn,
            _ => return None,
        })
    }
}

/// Canonical form applied before masking (`mask.canonical`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalKind {
    AlnumUpper,
    Digits,
    TwMobile,
    E164,
}

impl CanonicalKind {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "alnum-upper" => Self::AlnumUpper,
            "digits" => Self::Digits,
            "tw-mobile" => Self::TwMobile,
            "e164" => Self::E164,
            _ => return None,
        })
    }
}

/// How a match is masked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskSpec {
    /// Keep `keep_start` / `keep_end` chars of the (canonicalized) value.
    Keep {
        keep_start: usize,
        keep_end: usize,
        canonical: Option<CanonicalKind>,
    },
    /// PEM header: shown as is; "paste masked" masks up to the END line.
    PemBlock,
    /// Nothing of the value is kept, only its word count (BIP-39 phrases).
    WordCount,
}

/// How candidates are found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    Regex { pattern: String, ignore_case: bool },
    Finder(FinderKind),
}

/// What an `exclude` regex is matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExclusionTarget {
    /// The secret itself (default).
    Secret,
    /// The whole regex match.
    Match,
    /// The line containing the match.
    Line,
    /// Group 1 extended back over the whole identifier (key name).
    Key,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusionDef {
    pub pattern: String,
    /// Lower-case the target before matching (the regex is written in lower case).
    pub ignore_case: bool,
    pub target: ExclusionTarget,
}

/// Entropy threshold: fixed (gitleaks) or `min(cap, a + b·log2(len))` per charset class.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EntropySpec {
    Fixed(f64),
    ByCharset {
        hex: [f64; 3],
        base36: [f64; 3],
        base64: [f64; 3],
    },
}

/// Context keywords (`context`): one must end within `before` chars before the secret
/// or start within `after` chars after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextDef {
    pub keywords: Vec<String>,
    pub before: usize,
    pub after: usize,
}

/// One parsed, validated rule.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleDef {
    pub id: String,
    /// `universal` or a two-letter upper-case country code.
    pub pack: String,
    pub kind: RuleKind,
    pub label: String,
    pub matcher: Matcher,
    pub context: Option<ContextDef>,
    pub secret_group: Option<usize>,
    /// Lower-case; at least one must occur in the lower-cased text (empty = always run).
    pub keywords: Vec<String>,
    pub not_preceded_by: Option<String>,
    pub not_followed_by: Option<String>,
    pub min_length: usize,
    pub max_length: usize,
    pub entropy: Option<EntropySpec>,
    pub digit_required_below: usize,
    pub reject_sequential: bool,
    /// Rule exclusions followed by file-level ones.
    pub exclusions: Vec<ExclusionDef>,
    /// Rule stopwords followed by file-level ones.
    pub stopwords: Vec<String>,
    pub validate: Option<ValidatorKind>,
    pub mask: MaskSpec,
}

/// A rule file could not be loaded (legacy `InvalidDataException`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLoadError {
    pub file: String,
    pub message: String,
}

impl fmt::Display for RuleLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.message)
    }
}

impl std::error::Error for RuleLoadError {}

/// Parses and validates rule files, returning every rule ordered by file `priority`,
/// then file name, then position in the file (earlier rules win overlaps).
/// Rule regexes (and their exclusion / lookaround replacements) are compiled once to
/// validate them; the engine compiles them again lazily.
pub fn load<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<RuleDef>, RuleLoadError> {
    load_impl(files, true)
}

/// Loads the embedded `rules/*.json`. Regexes are not compiled here (the engine
/// compiles each rule lazily); the unit tests compile every embedded rule.
pub fn load_embedded() -> Result<Vec<RuleDef>, RuleLoadError> {
    load_impl(EMBEDDED.iter().copied(), false)
}

fn load_impl<'a>(
    files: impl IntoIterator<Item = (&'a str, &'a str)>,
    compile_check: bool,
) -> Result<Vec<RuleDef>, RuleLoadError> {
    let mut parsed: Vec<(i64, String, Vec<RuleDef>)> = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for (name, json) in files {
        let err = |m: String| RuleLoadError {
            file: name.to_owned(),
            message: m,
        };
        let root: Value =
            serde_json::from_str(json).map_err(|e| err(format!("invalid JSON: {e}")))?;
        let root = root
            .as_object()
            .ok_or_else(|| err("root must be an object".into()))?;
        if get_i64(root, "format").map_err(&err)? != 1 {
            return Err(err("unsupported format".into()));
        }
        let priority = get_i64(root, "priority").map_err(&err)?;
        let pack = match root.get("pack") {
            None => UNIVERSAL.to_owned(),
            Some(v) => v
                .as_str()
                .ok_or_else(|| err("pack must be a string".into()))?
                .to_owned(),
        };
        if pack != UNIVERSAL && !(pack.len() == 2 && pack.bytes().all(|b| b.is_ascii_uppercase())) {
            return Err(err(format!(
                "pack must be `universal` or a two-letter upper-case country code: {pack}"
            )));
        }
        let file_exclude = read_exclusions(root).map_err(&err)?;
        let file_stopwords = read_strings(root, "stopwords").map_err(&err)?;
        let rules_v = root
            .get("rules")
            .and_then(Value::as_array)
            .ok_or_else(|| err("missing `rules` array".into()))?;
        let mut rules = Vec::with_capacity(rules_v.len());
        for r in rules_v {
            let r = r
                .as_object()
                .ok_or_else(|| err("rule must be an object".into()))?;
            let id = get_str(r, "id").map_err(&err)?.to_owned();
            if !ids.insert(id.clone()) {
                return Err(err(format!("duplicate rule id: {id}")));
            }
            let rule = read_rule(r, &id, &pack, &file_exclude, &file_stopwords)
                .map_err(|m| err(format!("rule {id} is invalid: {m}")))?;
            if compile_check {
                check_compiles(&rule).map_err(|m| err(format!("rule {id} is invalid: {m}")))?;
            }
            rules.push(rule);
        }
        parsed.push((priority, name.to_owned(), rules));
    }
    parsed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(parsed.into_iter().flat_map(|p| p.2).collect())
}

fn get_i64(o: &Map<String, Value>, k: &str) -> Result<i64, String> {
    o.get(k)
        .ok_or_else(|| format!("missing `{k}`"))?
        .as_i64()
        .ok_or_else(|| format!("`{k}` must be an integer"))
}

fn get_str<'a>(o: &'a Map<String, Value>, k: &str) -> Result<&'a str, String> {
    o.get(k)
        .ok_or_else(|| format!("missing `{k}`"))?
        .as_str()
        .ok_or_else(|| format!("`{k}` must be a string"))
}

fn opt_str<'a>(o: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, String> {
    match o.get(k) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("`{k}` must be a string")),
    }
}

fn opt_bool(o: &Map<String, Value>, k: &str) -> Result<bool, String> {
    match o.get(k) {
        None => Ok(false),
        Some(v) => v
            .as_bool()
            .ok_or_else(|| format!("`{k}` must be a boolean")),
    }
}

fn opt_usize(o: &Map<String, Value>, k: &str, default: usize) -> Result<usize, String> {
    match o.get(k) {
        None => Ok(default),
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| format!("`{k}` must be a non-negative integer")),
    }
}

fn read_strings(o: &Map<String, Value>, k: &str) -> Result<Vec<String>, String> {
    match o.get(k) {
        None => Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| format!("`{k}` must be an array"))?
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("`{k}` must contain strings"))
            })
            .collect(),
    }
}

fn read_exclusions(o: &Map<String, Value>) -> Result<Vec<ExclusionDef>, String> {
    let Some(v) = o.get("exclude") else {
        return Ok(Vec::new());
    };
    let arr = v.as_array().ok_or("`exclude` must be an array")?;
    arr.iter()
        .map(|x| {
            let x = x.as_object().ok_or("exclude entries must be objects")?;
            let target = match opt_str(x, "target")? {
                None | Some("secret") => ExclusionTarget::Secret,
                Some("match") => ExclusionTarget::Match,
                Some("line") => ExclusionTarget::Line,
                Some("key") => ExclusionTarget::Key,
                Some(t) => return Err(format!("unknown exclude target: {t}")),
            };
            Ok(ExclusionDef {
                pattern: get_str(x, "regex")?.to_owned(),
                ignore_case: opt_bool(x, "ignoreCase")?,
                target,
            })
        })
        .collect()
}

fn read_rule(
    r: &Map<String, Value>,
    id: &str,
    pack: &str,
    file_exclude: &[ExclusionDef],
    file_stopwords: &[String],
) -> Result<RuleDef, String> {
    let ignore_case = opt_bool(r, "ignoreCase")?;
    let mask = match r.get("mask") {
        None => MaskSpec::Keep {
            keep_start: 0,
            keep_end: DEFAULT_KEEP_END,
            canonical: None,
        },
        Some(Value::String(s)) if s == "pem-block" => MaskSpec::PemBlock,
        Some(Value::String(s)) if s == "word-count" => MaskSpec::WordCount,
        Some(Value::String(s)) => return Err(format!("unknown mask: {s}")),
        Some(Value::Object(m)) => MaskSpec::Keep {
            keep_start: opt_usize(m, "keepStart", 0)?,
            keep_end: opt_usize(m, "keepEnd", DEFAULT_KEEP_END)?,
            canonical: match opt_str(m, "canonical")? {
                None => None,
                Some(c) => Some(
                    CanonicalKind::parse(c)
                        .ok_or_else(|| format!("unknown mask.canonical: {c}"))?,
                ),
            },
        },
        Some(_) => return Err("mask must be a string or an object".into()),
    };

    let regex = opt_str(r, "regex")?;
    let finder = opt_str(r, "finder")?;
    let matcher = match (regex, finder) {
        (Some(p), None) => Matcher::Regex {
            pattern: p.to_owned(),
            ignore_case,
        },
        (None, Some(f)) => match f {
            "card-groups" => Matcher::Finder(FinderKind::CardGroups),
            "bip39" => Matcher::Finder(FinderKind::Bip39),
            _ => return Err(format!("unknown finder: {f}")),
        },
        _ => return Err("needs exactly one of `regex` or `finder`".into()),
    };

    let kind_s = get_str(r, "kind")?;
    let kind = RuleKind::parse(kind_s).ok_or_else(|| format!("unknown kind: {kind_s}"))?;
    let label = get_str(r, "label")?.to_owned();

    let context = match r.get("context") {
        None => None,
        Some(c) => Some(read_context(c)?),
    };
    let secret_group = match r.get("secretGroup") {
        None => None,
        Some(v) => Some(
            v.as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("`secretGroup` must be a non-negative integer")?,
        ),
    };
    let entropy = match r.get("entropy") {
        None => None,
        Some(Value::Number(n)) => Some(EntropySpec::Fixed(n.as_f64().ok_or("bad entropy")?)),
        Some(Value::Object(o)) => {
            let abc = |k: &str| -> Result<[f64; 3], String> {
                let a = o
                    .get(k)
                    .and_then(Value::as_array)
                    .ok_or_else(|| format!("entropy.{k} must be [a, b, cap]"))?;
                let f = |i: usize| a.get(i).and_then(Value::as_f64);
                match (f(0), f(1), f(2)) {
                    (Some(x), Some(y), Some(z)) => Ok([x, y, z]),
                    _ => Err(format!("entropy.{k} must be [a, b, cap]")),
                }
            };
            Some(EntropySpec::ByCharset {
                hex: abc("hex")?,
                base36: abc("base36")?,
                base64: abc("base64")?,
            })
        }
        Some(_) => return Err("entropy must be a number or an object".into()),
    };
    let digit_required_below = match r.get("digitRequiredBelow") {
        None => 0,
        Some(v) => {
            let f = v.as_f64().ok_or("`digitRequiredBelow` must be a number")?;
            if f <= 0.0 {
                0
            } else {
                f.min(i32::MAX as f64) as usize
            }
        }
    };
    let validate = match opt_str(r, "validate")? {
        None => None,
        Some(v) => Some(ValidatorKind::parse(v).ok_or_else(|| format!("unknown validate: {v}"))?),
    };

    let mut exclusions = read_exclusions(r)?;
    exclusions.extend(file_exclude.iter().cloned());
    let mut stopwords = read_strings(r, "stopwords")?;
    stopwords.extend(file_stopwords.iter().cloned());

    let min_length = match r.get("minLength") {
        None => 1,
        Some(v) => v
            .as_i64()
            .ok_or("`minLength` must be an integer")?
            .max(0)
            .try_into()
            .unwrap_or(usize::MAX),
    };
    let max_length = match r.get("maxLength") {
        None => usize::MAX,
        Some(v) => {
            let n = v.as_i64().ok_or("`maxLength` must be an integer")?;
            usize::try_from(n).unwrap_or(0)
        }
    };

    Ok(RuleDef {
        id: id.to_owned(),
        pack: pack.to_owned(),
        kind,
        label,
        matcher,
        context,
        secret_group,
        keywords: read_strings(r, "keywords")?,
        not_preceded_by: opt_str(r, "notPrecededBy")?.map(str::to_owned),
        not_followed_by: opt_str(r, "notFollowedBy")?.map(str::to_owned),
        min_length,
        max_length,
        entropy,
        digit_required_below,
        reject_sequential: opt_bool(r, "rejectSequential")?,
        exclusions,
        stopwords,
        validate,
        mask,
    })
}

fn read_context(c: &Value) -> Result<ContextDef, String> {
    let o = c.as_object().ok_or("context must be an object")?;
    let keywords = read_strings(o, "keywords")?;
    let before = opt_usize(o, "before", 0)?;
    let after = opt_usize(o, "after", 0)?;
    if keywords.is_empty()
        || keywords.iter().any(|k| {
            let n = k.chars().count();
            n == 0 || n > MAX_CONTEXT_KEYWORD || k.chars().any(|c| c.is_ascii_uppercase())
        })
    {
        return Err(format!(
            "context.keywords must be 1–{MAX_CONTEXT_KEYWORD} chars, lower-case"
        ));
    }
    if before > MAX_CONTEXT_WINDOW || after > MAX_CONTEXT_WINDOW || before + after == 0 {
        return Err(format!(
            "context.before / after must be 0–{MAX_CONTEXT_WINDOW} and not both 0"
        ));
    }
    Ok(ContextDef {
        keywords,
        before,
        after,
    })
}

/// Compiles every pattern of `rule` once, reporting the first error.
pub fn check_compiles(rule: &RuleDef) -> Result<(), String> {
    if let Matcher::Regex {
        pattern,
        ignore_case,
    } = &rule.matcher
    {
        compile(pattern, *ignore_case).map_err(|e| format!("regex: {e}"))?;
    }
    if let Some(p) = &rule.not_preceded_by {
        compile_not_preceded_by(p).map_err(|e| format!("notPrecededBy: {e}"))?;
    }
    if let Some(p) = &rule.not_followed_by {
        compile_not_followed_by(p).map_err(|e| format!("notFollowedBy: {e}"))?;
    }
    for e in &rule.exclusions {
        compile(&e.pattern, false).map_err(|err| format!("exclude: {err}"))?;
    }
    Ok(())
}

/// Compiles a rule-file regex for matching the ASCII view.
pub fn compile(pattern: &str, ignore_case: bool) -> Result<Regex, regex::Error> {
    RegexBuilder::new(&to_rust_syntax(pattern))
        .unicode(false)
        .case_insensitive(ignore_case)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// `notPrecededBy`: must match the single preceding char exactly.
pub fn compile_not_preceded_by(pattern: &str) -> Result<Regex, regex::Error> {
    compile(&format!("^(?:{pattern})$"), false)
}

/// `notFollowedBy`: must match at the start of the text after the match.
pub fn compile_not_followed_by(pattern: &str) -> Result<Regex, regex::Error> {
    compile(&format!("^(?:{pattern})"), false)
}

/// Rewrites the shared rule dialect (.NET / JS subset) into Rust `regex` syntax.
/// Only character classes differ: inside `[...]`, Rust treats `[` as a nested class
/// and `&&`, `--`, `~~` as set operations, while the rule dialect treats them as
/// literals. Those are escaped; everything else is passed through.
pub fn to_rust_syntax(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut in_class = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            out.push(c);
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }
        if in_class {
            match c {
                ']' => {
                    in_class = false;
                    out.push(c);
                }
                '[' | '&' | '~' => {
                    out.push('\\');
                    out.push(c);
                }
                '-' if chars.get(i + 1) == Some(&'-')
                    || chars.get(i.wrapping_sub(1)) == Some(&'-') =>
                {
                    out.push_str("\\-");
                }
                _ => out.push(c),
            }
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
        if c == '[' {
            in_class = true;
            // `]` right after `[` or `[^` is a literal.
            if chars.get(i) == Some(&'^') {
                out.push('^');
                i += 1;
            }
            if chars.get(i) == Some(&']') {
                out.push_str("\\]");
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_load_and_compile() {
        let rules = load(EMBEDDED.iter().copied()).expect("embedded rules load and compile");
        assert!(rules.len() > 200);
        assert_eq!(rules[0].id, "jwt");
        assert_eq!(rules.last().map(|r| r.pack.as_str()), Some(UNIVERSAL));
        let pos = |id: &str| rules.iter().position(|r| r.id == id);
        assert!(pos("tw-mobile") < pos("e164-phone"));
        for r in &rules {
            assert!(
                r.keywords.iter().all(|k| k.to_lowercase() == *k),
                "{}",
                r.id
            );
        }
    }

    #[test]
    fn bip39_list_is_valid() {
        let w = parse_bip39_words(BIP39_ENGLISH).expect("valid list");
        assert_eq!(w[0], "abandon");
        assert_eq!(w[2047], "zoo");
        assert!(parse_bip39_words("abc\nabd\n").is_err());
    }

    #[test]
    fn class_rewrites() {
        assert_eq!(to_rust_syntax("[a[b]"), "[a\\[b]");
        assert_eq!(to_rust_syntax("[]a]"), "[\\]a]");
        assert_eq!(to_rust_syntax("[^]a]"), "[^\\]a]");
        assert_eq!(to_rust_syntax("[a&&b~~c]"), "[a\\&\\&b\\~\\~c]");
        assert_eq!(to_rust_syntax("[a--b]x--"), "[a\\-\\-b]x--");
        assert_eq!(to_rust_syntax("a\\[b[\\]]"), "a\\[b[\\]]");
    }

    #[test]
    fn dollar_is_end_of_text() {
        let r = compile("ab$", false).unwrap();
        assert!(r.is_match(b"ab"));
        assert!(!r.is_match(b"ab\n"));
    }

    #[test]
    fn errors_name_the_file() {
        let e = load([(
            "bad.json",
            r#"{"format":1,"priority":1,"rules":[{"id":"x","kind":"api-key","label":"x","regex":"(?<=a)b"}]}"#,
        )])
        .unwrap_err();
        assert!(e.to_string().contains("bad.json"));
    }
}
