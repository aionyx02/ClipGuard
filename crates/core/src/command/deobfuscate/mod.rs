//! Deobfuscation with an onion trace (phase-1.md §1.5 "解混淆", "洋蔥 trace";
//! docs/spec/detection-rules.md §3.5).
//!
//! The text is peeled in layers. Layer 0 is the legacy normalization
//! ([`super::normalize`], §3.0) plus removal of markdown code markers; every
//! later layer applies the 1b transforms once (PowerShell string building,
//! escapes, encodings, cmd substrings, full-width letters) and then normalizes
//! again, until nothing changes or [`MAX_LAYERS`] is reached. Every transform that
//! changed the text is recorded as a [`DeobfuscationStep`].
//!
//! Literal analysis only: nothing is run, fetched or read from the environment.
//! Bounded: at most [`MAX_LAYERS`] layers, the text never grows beyond
//! [`MAX_GROWTH`] × the input (and never beyond [`MAX_OUTPUT_CHARS`]); a step that
//! would exceed the cap is dropped and peeling stops.

mod cmd;
mod encoding;
mod powershell;

use crate::Message;
use crate::secret::{self, PackSet};

use super::{markdown, normalize};

/// At most this many deobfuscation layers after normalization.
pub const MAX_LAYERS: usize = 5;
/// The text never grows beyond this many times the input length (chars).
pub const MAX_GROWTH: usize = 4;
/// The text never grows beyond this many chars (1 Mi), whatever the input.
pub const MAX_OUTPUT_CHARS: usize = 1 << 20;
/// At most this many steps are recorded per text (transforms keep running).
pub const MAX_STEPS: usize = 64;
/// Chars of the text shown in a step preview.
pub const MAX_PREVIEW_CHARS: usize = 120;
/// Passes of string concatenation per layer (`'a'+'b'+'c'+'d'` needs two).
pub const MAX_CONCAT_PASSES: usize = 16;
/// Items of a literal list (`-join`, `-f`, `[char[]]`) that are evaluated.
pub const MAX_LIST_ITEMS: usize = 4096;
/// `-replace` operations with a regex pattern evaluated per layer.
pub const MAX_REGEX_REPLACES: usize = 32;
/// Longest `-replace` pattern evaluated (chars).
pub const MAX_PATTERN_LENGTH: usize = 256;

/// What a deobfuscation step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StepKind {
    // ---- layer 0: normalization (§3.0) ----
    /// Invisible characters removed (soft hyphen, zero-width, TAG block…).
    Invisible,
    /// Dash variants → `-`.
    Dash,
    /// cmd `^` escapes removed.
    Caret,
    /// cmd `%x%` / `!x!` substituted (one level).
    Variable,
    /// Quotes inside words merged (`"m"sh"ta"`).
    Quote,
    /// Full paths of known programs shortened.
    ProgramPath,
    /// Markdown fences and inline code markers removed.
    Markdown,
    // ---- layers 1–5 ----
    /// Full-width Latin letters and digits → ASCII.
    FullWidth,
    /// PowerShell backtick escapes removed.
    Backtick,
    /// `%xx` URL escapes decoded.
    UrlDecode,
    /// `\xHH` escapes or hex strings decoded.
    HexDecode,
    /// `[char]NN` / `[char[]](…)` evaluated.
    CharCode,
    /// String literals concatenated (`'ms'+'hta'`).
    Concat,
    /// `-join` evaluated.
    Join,
    /// `-f` format operator evaluated.
    Format,
    /// `-replace` / `.Replace()` evaluated.
    Replace,
    /// `[string]::Concat` / `Join` / `Format` evaluated.
    StringMethod,
    /// PowerShell string variables substituted (`$a='ms'` … `$a`).
    PsVariable,
    /// A literal run as a command unwrapped (`& ('mshta')`, `iex 'iwr …'`).
    Unwrap,
    /// Base64 decoded (`FromBase64String`, `base64 -d`, `b64decode`).
    Base64,
    /// PowerShell `-EncodedCommand` decoded (UTF-16LE).
    EncodedCommand,
    /// cmd substring / replace expansion (`%x:~0,3%`, `%x:a=b%`).
    CmdSubstring,
    /// cmd variables substituted again (a value contained another variable).
    NestedVariable,
}

impl StepKind {
    /// snake_case name used by the corpus.
    pub fn as_str(self) -> &'static str {
        match self {
            StepKind::Invisible => "invisible",
            StepKind::Dash => "dash",
            StepKind::Caret => "caret",
            StepKind::Variable => "variable",
            StepKind::Quote => "quote",
            StepKind::ProgramPath => "program_path",
            StepKind::Markdown => "markdown",
            StepKind::FullWidth => "full_width",
            StepKind::Backtick => "backtick",
            StepKind::UrlDecode => "url_decode",
            StepKind::HexDecode => "hex_decode",
            StepKind::CharCode => "char_code",
            StepKind::Concat => "concat",
            StepKind::Join => "join",
            StepKind::Format => "format",
            StepKind::Replace => "replace",
            StepKind::StringMethod => "string_method",
            StepKind::PsVariable => "ps_variable",
            StepKind::Unwrap => "unwrap",
            StepKind::Base64 => "base64",
            StepKind::EncodedCommand => "encoded_command",
            StepKind::CmdSubstring => "cmd_substring",
            StepKind::NestedVariable => "nested_variable",
        }
    }

    /// Fluent message id describing the step (argument `count`).
    pub fn message_id(self) -> &'static str {
        match self {
            StepKind::Invisible => "cmd-deob-invisible",
            StepKind::Dash => "cmd-deob-dash",
            StepKind::Caret => "cmd-deob-caret",
            StepKind::Variable => "cmd-deob-variable",
            StepKind::Quote => "cmd-deob-quote",
            StepKind::ProgramPath => "cmd-deob-program-path",
            StepKind::Markdown => "cmd-deob-markdown",
            StepKind::FullWidth => "cmd-deob-full-width",
            StepKind::Backtick => "cmd-deob-backtick",
            StepKind::UrlDecode => "cmd-deob-url-decode",
            StepKind::HexDecode => "cmd-deob-hex-decode",
            StepKind::CharCode => "cmd-deob-char-code",
            StepKind::Concat => "cmd-deob-concat",
            StepKind::Join => "cmd-deob-join",
            StepKind::Format => "cmd-deob-format",
            StepKind::Replace => "cmd-deob-replace",
            StepKind::StringMethod => "cmd-deob-string-method",
            StepKind::PsVariable => "cmd-deob-ps-variable",
            StepKind::Unwrap => "cmd-deob-unwrap",
            StepKind::Base64 => "cmd-deob-base64",
            StepKind::EncodedCommand => "cmd-deob-encoded-command",
            StepKind::CmdSubstring => "cmd-deob-cmd-substring",
            StepKind::NestedVariable => "cmd-deob-nested-variable",
        }
    }

    /// Steps that build text from pieces: a URL that went through one of them
    /// never qualifies for the official installer lists (§3.2), and an execution
    /// signal they reveal counts as hidden (`cmd-reason-obfuscated`).
    pub fn is_built(self) -> bool {
        matches!(
            self,
            StepKind::Backtick
                | StepKind::UrlDecode
                | StepKind::HexDecode
                | StepKind::CharCode
                | StepKind::Concat
                | StepKind::Join
                | StepKind::Format
                | StepKind::Replace
                | StepKind::StringMethod
                | StepKind::Base64
                | StepKind::EncodedCommand
                | StepKind::CmdSubstring
                | StepKind::NestedVariable
        )
    }

    /// Steps that only exist to hide what a command does (built steps plus
    /// full-width letters).
    pub fn is_obfuscation(self) -> bool {
        self.is_built() || self == StepKind::FullWidth
    }

    /// Every kind, in pipeline order.
    pub const ALL: [StepKind; 23] = [
        StepKind::Invisible,
        StepKind::Dash,
        StepKind::Caret,
        StepKind::Variable,
        StepKind::Quote,
        StepKind::ProgramPath,
        StepKind::Markdown,
        StepKind::FullWidth,
        StepKind::Backtick,
        StepKind::UrlDecode,
        StepKind::HexDecode,
        StepKind::CharCode,
        StepKind::Concat,
        StepKind::Join,
        StepKind::Format,
        StepKind::Replace,
        StepKind::StringMethod,
        StepKind::PsVariable,
        StepKind::Unwrap,
        StepKind::Base64,
        StepKind::EncodedCommand,
        StepKind::CmdSubstring,
        StepKind::NestedVariable,
    ];
}

/// One peeled layer of the onion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeobfuscationStep {
    pub kind: StepKind,
    /// 0 = normalization, 1..=[`MAX_LAYERS`] = deobfuscation layers.
    pub layer: u8,
    /// What the step did ([`StepKind::message_id`], argument `count`).
    pub message: Message,
    /// The text after the step, around the first change: at most
    /// [`MAX_PREVIEW_CHARS`] chars, whitespace runs collapsed, `…` where cut,
    /// secrets masked. Untrusted: the UI must escape it.
    pub preview: String,
}

/// Result of [`deobfuscate`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Deobfuscated {
    /// Steps in the order they were applied (at most [`MAX_STEPS`]).
    pub layers: Vec<DeobfuscationStep>,
    /// The fully peeled text (normalized).
    pub output: String,
    /// A cap ([`MAX_GROWTH`], [`MAX_OUTPUT_CHARS`], [`MAX_STEPS`]) stopped
    /// peeling or recording early.
    pub capped: bool,
}

/// Peels `text` (layers, steps and output; see the module docs).
pub fn deobfuscate(text: &str) -> Deobfuscated {
    let head = text
        .char_indices()
        .nth(MAX_OUTPUT_CHARS)
        .map_or(text, |(i, _)| &text[..i]);
    let run = run(head);
    Deobfuscated {
        layers: run.steps.iter().map(RawStep::to_public).collect(),
        output: run.output,
        capped: run.capped || head.len() < text.len(),
    }
}

/// A step before its preview is masked (masking is only done for steps shown).
#[derive(Debug, Clone)]
pub(crate) struct RawStep {
    pub kind: StepKind,
    pub layer: u8,
    pub count: usize,
    pub preview: String,
}

impl RawStep {
    pub(crate) fn to_public(&self) -> DeobfuscationStep {
        DeobfuscationStep {
            kind: self.kind,
            layer: self.layer,
            message: Message::new(self.kind.message_id()).arg("count", self.count),
            preview: mask_secrets(&self.preview),
        }
    }
}

/// Masks secrets (PII, API keys) in a preview (phase-1.md §1.5: secrets in the
/// trace are masked).
fn mask_secrets(preview: &str) -> String {
    let found = secret::find(preview, &PackSet::default());
    if found.is_empty() {
        preview.to_owned()
    } else {
        secret::mask_text(preview, &found, "…")
    }
}

/// Internal result used by the analysis.
#[derive(Debug, Clone, Default)]
pub(crate) struct Run {
    pub steps: Vec<RawStep>,
    /// After the normalization steps of layer 0: equal to
    /// [`normalize::normalize`] of the input (`None` if a cap stopped it).
    pub normalized: Option<String>,
    /// After layer 0 (normalization + markdown markers).
    pub plain: String,
    /// After every layer.
    pub output: String,
    /// A built step ([`StepKind::is_built`]) changed the text.
    pub built: bool,
    /// An obfuscation step ([`StepKind::is_obfuscation`]) changed the text.
    pub obfuscated: bool,
    pub capped: bool,
}

/// A transform: returns the new text and how many places changed, or `None`.
type Transform = fn(&str) -> Option<(String, usize)>;
/// A legacy normalization step and its kind.
type NormalizeStep = (StepKind, fn(&str) -> String);

struct Peeler {
    run: Run,
    limit: usize,
    layer: u8,
}

impl Peeler {
    /// Applies `f` to `text` as a step of `kind`. Returns false (and stops) when the
    /// result exceeds the size cap.
    fn apply(
        &mut self,
        kind: StepKind,
        text: &mut String,
        f: impl FnOnce(&str) -> Option<(String, usize)>,
    ) -> bool {
        let Some((next, count)) = f(text) else {
            return true;
        };
        if next == *text {
            return true;
        }
        if next.len() > self.limit * 4 || next.chars().count() > self.limit {
            self.run.capped = true;
            return false;
        }
        self.run.built |= kind.is_built();
        self.run.obfuscated |= kind.is_obfuscation();
        if self.run.steps.len() < MAX_STEPS {
            self.run.steps.push(RawStep {
                kind,
                layer: self.layer,
                count: count.max(1),
                preview: preview(text, &next),
            });
        } else {
            self.run.capped = true;
        }
        *text = next;
        true
    }

    /// The legacy normalization steps, in [`normalize`] order.
    fn normalize(&mut self, text: &mut String, variable: StepKind) -> bool {
        let steps: [NormalizeStep; 6] = [
            (StepKind::Invisible, normalize::strip_invisible),
            (StepKind::Dash, normalize::normalize_dashes),
            (StepKind::Caret, normalize::unescape_carets),
            (variable, normalize::expand_variables),
            (StepKind::Quote, |s| {
                normalize::collapse_split_quotes(s.to_owned())
            }),
            (StepKind::ProgramPath, normalize::shorten_program_paths),
        ];
        for (kind, f) in steps {
            if !self.apply(kind, text, |s| Some((f(s), 1))) {
                return false;
            }
        }
        true
    }
}

/// The transforms of one layer, in order.
const LAYER: [(StepKind, Transform); 15] = [
    (StepKind::FullWidth, encoding::full_width),
    (StepKind::Backtick, powershell::backticks),
    (StepKind::UrlDecode, encoding::url_decode),
    (StepKind::HexDecode, encoding::hex_decode),
    (StepKind::EncodedCommand, encoding::encoded_command),
    (StepKind::Base64, encoding::base64),
    (StepKind::CharCode, powershell::char_codes),
    (StepKind::PsVariable, powershell::variables),
    (StepKind::CmdSubstring, cmd::substrings),
    (StepKind::StringMethod, powershell::string_methods),
    (StepKind::Concat, powershell::concat),
    (StepKind::Join, powershell::join),
    (StepKind::Format, powershell::format),
    (StepKind::Replace, powershell::replace),
    (StepKind::Unwrap, powershell::unwrap),
];

/// Runs the pipeline on `text`.
pub(crate) fn run(text: &str) -> Run {
    let input_chars = text.chars().count();
    let mut p = Peeler {
        run: Run::default(),
        limit: input_chars
            .saturating_mul(MAX_GROWTH)
            .clamp(1, MAX_OUTPUT_CHARS),
        layer: 0,
    };
    let mut s = text.to_owned();
    let mut ok = p.normalize(&mut s, StepKind::Variable);
    if ok {
        p.run.normalized = Some(s.clone());
    }
    ok = ok
        && p.apply(
            StepKind::Markdown,
            &mut s,
            |t| match markdown::strip_code_markers(t) {
                std::borrow::Cow::Owned(o) => Some((o, 1)),
                std::borrow::Cow::Borrowed(_) => None,
            },
        );
    p.run.plain = s.clone();
    for layer in 1..=MAX_LAYERS {
        if !ok {
            break;
        }
        p.layer = u8::try_from(layer).unwrap_or(u8::MAX);
        let before = s.clone();
        for (kind, f) in LAYER {
            ok = p.apply(kind, &mut s, f);
            if !ok {
                break;
            }
        }
        ok = ok && p.normalize(&mut s, StepKind::NestedVariable);
        if s == before {
            break;
        }
    }
    p.run.output = s;
    p.run
}

/// Collapses whitespace runs to one space.
fn one_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(4 * MAX_PREVIEW_CHARS));
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            space = true;
            continue;
        }
        if space && !out.is_empty() {
            out.push(' ');
        }
        space = false;
        out.push(c);
    }
    out
}

/// Chars of context kept before the first change in a preview.
const PREVIEW_CONTEXT: usize = 24;

/// Chars scanned on each side of a preview window for secrets that cross its
/// edges (a card number or key cut in half would not be detected, and its
/// visible half would leak).
const PREVIEW_MASK_MARGIN: usize = 512;

/// Byte offset of the char `n` chars after `from` (or the end).
fn advance(s: &str, from: usize, n: usize) -> usize {
    s[from..]
        .char_indices()
        .nth(n)
        .map_or(s.len(), |(i, _)| from + i)
}

/// Byte offset of the char `n` chars before `from` (or 0).
fn retreat(s: &str, from: usize, n: usize) -> usize {
    s[..from]
        .char_indices()
        .rev()
        .nth(n.saturating_sub(1))
        .map_or(0, |(i, _)| i)
}

/// `after` around the first char that differs from `before`, with every secret
/// that overlaps the window masked before the window is cut (P4).
fn preview(before: &str, after: &str) -> String {
    let diff = before
        .chars()
        .zip(after.chars())
        .take_while(|(a, b)| a == b)
        .count();
    let start = diff.saturating_sub(PREVIEW_CONTEXT);
    let mut start_b = after
        .char_indices()
        .nth(start)
        .map_or(after.len(), |(i, _)| i);
    // Take a bounded slice first so collapsing whitespace stays cheap.
    let mut end_b = advance(after, start_b, MAX_PREVIEW_CHARS * 4);
    // Grow the window to whole secrets that cross its edges, then mask.
    let ctx_start = retreat(after, start_b, PREVIEW_MASK_MARGIN);
    let ctx_end = advance(after, end_b, PREVIEW_MASK_MARGIN);
    for m in secret::find(&after[ctx_start..ctx_end], &PackSet::default()) {
        let (s, e) = (ctx_start + m.span.start, ctx_start + m.span.end);
        if s < end_b && e > start_b {
            start_b = start_b.min(s);
            end_b = end_b.max(e);
        }
    }
    let window = &after[start_b..end_b];
    let body = one_line(&mask_secrets(window));
    let mut out = String::new();
    if start_b > 0 {
        out.push('…');
    }
    let cut = body.chars().nth(MAX_PREVIEW_CHARS).is_some() || end_b < after.len();
    out.extend(body.chars().take(MAX_PREVIEW_CHARS));
    if cut {
        out.push('…');
    }
    out
}

// ---- shared literal helpers (PowerShell / shell string literals) ----

/// A PowerShell string literal without interpolation: `'…'` (with `''` escapes)
/// or `"…"` without `$` or backticks. No newlines.
pub(crate) const LIT: &str = r#"(?:'(?:[^'\r\n]|'')*'|"[^"\r\n$`]*")"#;

/// The value of a literal matched by [`LIT`].
pub(crate) fn lit_value(lit: &str) -> Option<String> {
    let inner = lit.get(1..lit.len().checked_sub(1)?)?;
    match lit.as_bytes().first() {
        Some(b'\'') => Some(inner.replace("''", "'")),
        Some(b'"') => Some(inner.to_owned()),
        _ => None,
    }
}

/// `value` as a single-quoted PowerShell literal.
pub(crate) fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(s: &str) -> String {
        deobfuscate(s).output
    }

    fn kinds(s: &str) -> Vec<StepKind> {
        deobfuscate(s).layers.iter().map(|l| l.kind).collect()
    }

    #[test]
    fn plain_text_is_untouched() {
        let d = deobfuscate("hello world");
        assert_eq!(d.output, "hello world");
        assert!(d.layers.is_empty());
    }

    #[test]
    fn powershell_layers() {
        assert_eq!(out("& ('ms'+'hta') x.hta"), "& mshta x.hta");
        assert_eq!(out("p`o`w`e`r`s`h`e`l`l -c x"), "powershell -c x");
        assert_eq!(out("& ([char]109+[char]0x73+'hta')"), "& mshta");
        assert_eq!(out("-join ('m','s','h','t','a')"), "'mshta'");
        assert_eq!(out("('{1}{0}' -f 'hta','ms')"), "'mshta'");
        assert_eq!(out("('mXhta' -replace 'x','s')"), "'mshta'");
        assert_eq!(out("[string]::Concat('ms','hta')"), "'mshta'");
        assert_eq!(out("-join [char[]](109,115,104,116,97)"), "'mshta'");
        assert_eq!(
            out("$a='ms'; $b='hta'; & ($a+$b)"),
            "$a='ms'; $b='hta'; & mshta"
        );
    }

    #[test]
    fn encodings() {
        // "iwr x" as UTF-8 Base64 and UTF-16LE Base64.
        assert_eq!(
            out("iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aXdyIHg=')))"),
            "iex iwr x"
        );
        assert_eq!(out("x -enc aQB3AHIAIAB4AA=="), "x -enc iwr x");
        assert_eq!(
            out("echo Y3VybCB4LmludmFsaWQgfCBzaA== | base64 -d | sh"),
            "echo curl x.invalid | sh | base64 -d | sh"
        );
        assert_eq!(out("%63%75%72%6c x"), "curl x");
        assert_eq!(out("\\x63\\x75\\x72\\x6c x"), "curl x");
        assert_eq!(out("\u{FF4D}\u{FF53}\u{FF48}\u{FF54}\u{FF41} x"), "mshta x");
    }

    #[test]
    fn cmd_layers() {
        assert_eq!(
            out("set x=abcmshta&& call %x:~3,5% y"),
            "set x=abcmshta&& call mshta y"
        );
        assert_eq!(
            out("set x=abcmshta&& call %x:~-5% y"),
            "set x=abcmshta&& call mshta y"
        );
        assert_eq!(
            out("set x=mzhta&& call %x:z=s% y"),
            "set x=mzhta&& call mshta y"
        );
        assert_eq!(out("%ComSpec:~-7,3% /c x"), "cmd /c x");
        assert_eq!(
            out("set a=ms&& set b=%a%hta&& call %b% y"),
            "set a=ms&& set b=mshta&& call mshta y"
        );
        assert!(kinds("set a=ms&& set b=%a%hta&& call %b% y").contains(&StepKind::NestedVariable));
    }

    #[test]
    fn markdown_is_not_an_escape() {
        let d = deobfuscate("```sh\ncurl https://bun.sh/install | bash\n```\nthen `bun upgrade`");
        assert_eq!(
            d.output,
            "\ncurl https://bun.sh/install | bash\n\nthen bun upgrade"
        );
        assert_eq!(kinds("```sh\nx\n```"), vec![StepKind::Markdown]);
        let r = run("```sh\nx\n```");
        assert!(!r.built && !r.obfuscated);
    }

    #[test]
    fn layers_and_growth_are_capped() {
        // Nested -enc: each layer peels one.
        let mut payload = "calc".to_owned();
        for _ in 0..8 {
            let units: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
            use base64::Engine as _;
            payload = format!(
                "x -enc {}",
                base64::engine::general_purpose::STANDARD.encode(units)
            );
        }
        let d = deobfuscate(&payload);
        assert!(d.layers.iter().all(|l| usize::from(l.layer) <= MAX_LAYERS));
        assert!(d.output.contains("-enc"));
        // Variable blow-up is bounded by the growth cap.
        let big = format!("set a={}&& {}", "x".repeat(1000), "%a%".repeat(64));
        let d = deobfuscate(&big);
        assert!(d.output.chars().count() <= big.chars().count() * MAX_GROWTH);
        assert!(d.capped);
    }

    #[test]
    fn secrets_cut_by_the_preview_window_do_not_leak() {
        // A card number that starts before the preview window: legacy previews
        // showed its tail ("…11 1111 powershell…").
        let ps = ["power", "shell"].concat();
        let text = format!("🔑 身分證 A123456789 卡號 4111 1111 1111 1111 {ps} -enc SQBFAFgA");
        for step in deobfuscate(&text).layers {
            assert!(!step.preview.contains("11 1111"), "{:?}", step.preview);
            assert!(!step.preview.contains("A123456789"), "{:?}", step.preview);
        }
    }

    #[test]
    fn previews_are_short_and_masked() {
        let text = format!("{}'ms'+'hta'", "a ".repeat(400));
        let d = deobfuscate(&text);
        assert!(
            d.layers
                .iter()
                .all(|l| l.preview.chars().count() <= MAX_PREVIEW_CHARS + 2)
        );
        let card = ["4111", "1111", "1111", "1111"].join(" ");
        let d = deobfuscate(&format!("('{card}'+' x')"));
        assert!(!d.layers.is_empty());
        assert!(
            d.layers.iter().all(|l| !l.preview.contains(&card)),
            "{:?}",
            d.layers
        );
    }

    /// `deobfuscate` on a whole 1 Mi-char text (not segmented like `analyze`).
    #[test]
    fn whole_text_is_bounded() {
        for unit in [
            "'a'+",
            "[char]65+",
            "-join ('a','b') ",
            "`a",
            "%41%42%43 ",
            "41",
            "$a='x'; $a ",
            "(('a')) ",
            "x -enc QQBBAEEAQQBBAEEAQQBBAA== ",
        ] {
            let text = unit.repeat((1 << 20) / unit.len());
            let start = std::time::Instant::now();
            let d = deobfuscate(&text);
            let elapsed = start.elapsed();
            assert!(d.output.chars().count() <= MAX_OUTPUT_CHARS);
            assert!(d.layers.len() <= MAX_STEPS);
            if !cfg!(debug_assertions) {
                assert!(elapsed.as_millis() < 1000, "{unit:?} took {elapsed:?}");
            }
        }
    }

    #[test]
    fn literals() {
        assert_eq!(lit_value("'it''s'").as_deref(), Some("it's"));
        assert_eq!(lit_value("\"a\"").as_deref(), Some("a"));
        assert_eq!(quote("it's"), "'it''s'");
    }
}
