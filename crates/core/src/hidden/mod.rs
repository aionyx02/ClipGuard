//! Invisible or disguised characters (legacy `HiddenCharDetector`,
//! docs/spec/detection-rules.md §6.1):
//!
//! - zero-width characters change the content while looking unchanged;
//! - Unicode TAG characters can hide whole sentences (prompt injection for AI);
//! - other invisible characters (soft hyphen, fillers, variation-selector smuggling);
//! - bidi controls (Trojan Source);
//! - homoglyphs: Cyrillic / Greek letters mixed into English words;
//! - a trailing newline after a shell command runs it as soon as it is pasted.
//!
//! Everything is only [`Level::Suspicious`] (warn, never clear the clipboard).
//! Every check is a linear scan; nothing is skipped because of the total length.
//! Reasons carry counts and code points only, never the original text (P4).

mod data;

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

pub use data::{HiddenRules, MAX_TAG_SPEC_LEN};

use crate::{Level, Message, Verdict};

/// At most this many lines containing a soft hyphen get the (more expensive)
/// "does this line look like a command" check; later lines only get the URL check.
pub const MAX_SOFT_HYPHEN_COMMAND_CHECKS: usize = 256;

/// At most this many distinct code points are listed in the "other invisible" reason.
pub const MAX_INVISIBLE_SAMPLES: usize = 3;

/// Analyzes `text` for hidden characters (legacy `HiddenCharDetector.Analyze`).
pub fn analyze(text: &str) -> Verdict {
    if text.is_empty() {
        return Verdict::CLEAN;
    }
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut reasons = Vec::new();

    let zero_width = count_zero_width(&chars);
    if zero_width > 0 {
        reasons.push(Message::new("hidden-zero-width").arg("count", zero_width));
    }

    let tags = count_tag_chars(&chars);
    if tags > 0 {
        reasons.push(Message::new("hidden-tag").arg("count", tags));
    }

    let (invisible, samples) = find_other_invisible(text, &chars);
    if invisible > 0 {
        let cp = |i: usize| {
            samples
                .get(i)
                .map(|&c| format!("U+{:04X}", u32::from(c)))
                .unwrap_or_default()
        };
        reasons.push(
            Message::new("hidden-other-invisible")
                .arg("count", invisible)
                .arg("samples", samples.len())
                .arg("cp1", cp(0))
                .arg("cp2", cp(1))
                .arg("cp3", cp(2)),
        );
    }

    let bidi = chars.iter().filter(|(_, c)| is_bidi_control(*c)).count();
    if bidi > 0 {
        reasons.push(Message::new("hidden-bidi").arg("count", bidi));
    }

    if let Some((glyph, script)) = find_homoglyph(text) {
        reasons.push(
            Message::new("hidden-homoglyph")
                .arg("script", script)
                .arg("glyph", glyph.to_string())
                .arg("code", format!("{:04X}", u32::from(glyph))),
        );
    }

    if has_trailing_newline_after_command(text) {
        reasons.push(Message::new("hidden-trailing-newline"));
    }

    if reasons.is_empty() {
        Verdict::CLEAN
    } else {
        Verdict {
            level: Level::Suspicious,
            reasons,
        }
    }
}

// ---------- Unicode categories (via the `regex` crate's tables) ----------

fn char_matches(re: &Regex, c: char) -> bool {
    let mut buf = [0u8; 4];
    re.is_match(c.encode_utf8(&mut buf))
}

/// `Rune.IsLetter`: general category L*.
fn is_letter(c: char) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A\p{L}\z").ok())
        .as_ref()
        .is_some_and(|re| char_matches(re, c))
}

fn opt_is_letter(c: Option<char>) -> bool {
    c.is_some_and(is_letter)
}

// ---------- zero-width ----------

fn count_zero_width(chars: &[(usize, char)]) -> usize {
    let mut count = 0;
    for (k, &(_, c)) in chars.iter().enumerate() {
        match c {
            '\u{200B}' | '\u{2060}' | '\u{FEFF}' => count += 1,
            // ZWNJ / ZWJ are normal in emoji sequences and in Arabic / Indic scripts.
            '\u{200C}' | '\u{200D}' if !is_legit_joiner(chars, k) => count += 1,
            _ => {}
        }
    }
    count
}

fn is_legit_joiner(chars: &[(usize, char)], k: usize) -> bool {
    let rules = HiddenRules::embedded();
    let Some(&(_, c)) = chars.get(k) else {
        return false;
    };
    let at = |i: Option<usize>| i.and_then(|i| chars.get(i)).map(|x| x.1);
    let prev = at(k.checked_sub(1));
    let next = at(k.checked_add(1));
    if c == '\u{200D}' && is_virama_joiner(rules, at(k.checked_sub(2)), prev, next) {
        return true;
    }
    let (Some(prev), Some(next)) = (prev, next) else {
        return false;
    };
    if c == '\u{200D}' && rules.is_emoji_like(prev) && rules.is_emoji_like(next) {
        return true;
    }
    is_complex_script_letter(prev) && is_complex_script_letter(next)
}

/// Letter + VIRAMA + ZWJ of the same Indic block: a half form, or in Malayalam a
/// chillu letter (`ന്‍` = NA + VIRAMA + ZWJ, the pre-Unicode-5.1 encoding still
/// produced by many keyboards), which ends a word. So the ZWJ may be followed by
/// whitespace, punctuation, another letter of the same block or the end of the
/// text, but not by a Latin letter, a digit or another invisible character.
fn is_virama_joiner(
    rules: &HiddenRules,
    base: Option<char>,
    prev: Option<char>,
    next: Option<char>,
) -> bool {
    let Some(v) = prev.and_then(|p| rules.virama(p)) else {
        return false;
    };
    if !base.is_some_and(|b| v.block.contains(&b) && is_letter(b)) {
        return false;
    }
    next.is_none_or(|n| v.block.contains(&n) || n.is_whitespace() || is_punctuation(n))
}

/// General category P* (`\p{P}`).
fn is_punctuation(c: char) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A\p{P}\z").ok())
        .as_ref()
        .is_some_and(|re| char_matches(re, c))
}

/// General category M* (`\p{M}`).
fn is_mark(c: char) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\A\p{M}\z").ok())
        .as_ref()
        .is_some_and(|re| char_matches(re, c))
}

/// Hebrew through Indic / Southeast Asian scripts (`joiners.json`
/// `complex_script_range`), where ZWNJ / ZWJ control glyph joining: Lo, Mn, Mc or Me.
fn is_complex_script_letter(c: char) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    HiddenRules::embedded().complex_script_range.contains(&c)
        && RE
            .get_or_init(|| Regex::new(r"\A[\p{Lo}\p{Mn}\p{Mc}\p{Me}]\z").ok())
            .as_ref()
            .is_some_and(|re| char_matches(re, c))
}

// ---------- Unicode TAG (U+E0000–U+E007F) ----------

/// Subdivision flags with a standard (RGI) emoji are listed in
/// `rules/hidden/tag-sequences.json` (England, Scotland, Wales). Any other tag
/// sequence shows as a plain black flag, so its tags stay invisible.
const BLACK_FLAG: char = '\u{1F3F4}';
const CANCEL_TAG: char = '\u{E007F}';

fn is_tag(c: char) -> bool {
    ('\u{E0000}'..=CANCEL_TAG).contains(&c)
}

fn count_tag_chars(chars: &[(usize, char)]) -> usize {
    let mut count = 0;
    let mut k = 0;
    while let Some(&(_, c)) = chars.get(k) {
        if c == BLACK_FLAG {
            let flag = rgi_flag_tag_len(chars, k + 1);
            k += 1 + flag;
            continue;
        }
        if is_tag(c) {
            count += 1;
        }
        k += 1;
    }
    count
}

/// If an RGI flag's tag part (including the cancel tag) starts at `start`, its
/// length in chars, else 0.
fn rgi_flag_tag_len(chars: &[(usize, char)], start: usize) -> usize {
    let mut spec = String::with_capacity(MAX_TAG_SPEC_LEN + 1);
    let mut k = start;
    // Legacy bound: stop once more than 8 tag letters were read.
    while let Some(&(_, c)) = chars.get(k).filter(|(_, c)| is_tag(*c)) {
        if spec.len() > MAX_TAG_SPEC_LEN {
            break;
        }
        if c == CANCEL_TAG {
            return if HiddenRules::embedded().rgi_flag_tags.contains(&spec) {
                k + 1 - start
            } else {
                0
            };
        }
        spec.push(char::from_u32(u32::from(c) - 0xE0000).unwrap_or('\0'));
        k += 1;
    }
    0
}

// ---------- other invisible characters ----------

/// Soft hyphens (unless a hyphenation point between letters on a line that is not a
/// command or URL), the Mongolian vowel separator (unless between Mongolian letters),
/// Hangul fillers (unless composing jamo), variation-selector smuggling, the
/// combining grapheme joiner (unless before a combining mark), Khmer inherent vowels
/// (unless between Khmer characters) and invisible math operators (in a run of
/// invisible characters, or on a command / URL line). Returns the count and up to [`MAX_INVISIBLE_SAMPLES`] distinct code points.
fn find_other_invisible(text: &str, chars: &[(usize, char)]) -> (usize, Vec<char>) {
    let mut count = 0usize;
    let mut samples: Vec<char> = Vec::with_capacity(MAX_INVISIBLE_SAMPLES);
    let mut hit = |c: char| {
        count += 1;
        if samples.len() < MAX_INVISIBLE_SAMPLES && !samples.contains(&c) {
            samples.push(c);
        }
    };

    let mut command_lines: HashMap<usize, bool> = HashMap::new();
    let mut line_start = 0usize;
    let mut k = 0usize;
    while let Some(&(offset, c)) = chars.get(k) {
        let prev = k.checked_sub(1).and_then(|p| chars.get(p)).map(|x| x.1);
        let next = chars.get(k + 1).map(|x| x.1);
        if c == '\r' || c == '\n' {
            line_start = offset + 1;
        }

        if is_variation_selector(c) {
            let mut end = k;
            let mut all_emoji_style = true;
            while let Some(&(_, v)) = chars.get(end).filter(|(_, v)| is_variation_selector(*v)) {
                all_emoji_style &= v == '\u{FE0E}' || v == '\u{FE0F}';
                end += 1;
            }
            if end - k >= 2 && !all_emoji_style {
                chars
                    .get(k..end)
                    .unwrap_or_default()
                    .iter()
                    .for_each(|&(_, v)| hit(v));
            } else if c >= '\u{E0100}' && !prev.is_some_and(is_ideograph) {
                hit(c);
            }
            // Handle the whole run at once: long runs stay linear.
            k = end;
            continue;
        }

        let suspicious = match c {
            '\u{00AD}' => {
                is_suspicious_soft_hyphen(text, offset, line_start, prev, next, &mut command_lines)
            }
            // Combining grapheme joiner: only meaningful before a combining mark
            // (blocks canonical reordering / collation contraction).
            '\u{034F}' => !next.is_some_and(is_mark),
            // Khmer inherent vowels: deprecated, invisible; tolerated inside Khmer text.
            '\u{17B4}' | '\u{17B5}' => !(prev.is_some_and(is_khmer) && next.is_some_and(is_khmer)),
            // Invisible math operators: Word / MathML equations put a single one
            // between operands (`sin⁡x`); steganography tools (StegCloak) emit runs.
            '\u{2061}'..='\u{2064}' => {
                prev.is_some_and(is_zero_width_like)
                    || next.is_some_and(is_zero_width_like)
                    || line_is_command_or_url(text, offset, line_start, &mut command_lines)
            }
            '\u{180E}' => !(prev.is_some_and(is_mongolian) && next.is_some_and(is_mongolian)),
            '\u{115F}' => !next
                .is_some_and(|n| matches!(n, '\u{1161}'..='\u{11A7}' | '\u{D7B0}'..='\u{D7C6}')),
            '\u{1160}' => !prev
                .is_some_and(|p| matches!(p, '\u{1100}'..='\u{115E}' | '\u{A960}'..='\u{A97C}')),
            '\u{3164}' | '\u{FFA0}' => true,
            _ => false,
        };
        if suspicious {
            hit(c);
        }
        k += 1;
    }
    (count, samples)
}

/// Zero-width characters and invisible math operators (used together in runs by
/// zero-width steganography).
fn is_zero_width_like(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}')
}

fn is_khmer(c: char) -> bool {
    ('\u{1780}'..='\u{17FF}').contains(&c)
}

fn is_variation_selector(c: char) -> bool {
    matches!(c, '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}')
}

fn is_mongolian(c: char) -> bool {
    ('\u{1800}'..='\u{18AF}').contains(&c)
}

fn is_ideograph(c: char) -> bool {
    matches!(c,
        '\u{3400}'..='\u{4DBF}' | '\u{4E00}'..='\u{9FFF}' | '\u{F900}'..='\u{FAFF}'
        | '\u{20000}'..='\u{3FFFF}')
}

fn is_suspicious_soft_hyphen(
    text: &str,
    offset: usize,
    line_start: usize,
    prev: Option<char>,
    next: Option<char>,
    line_cache: &mut HashMap<usize, bool>,
) -> bool {
    // A hyphenation point is always between two letters.
    if !opt_is_letter(prev) || !opt_is_letter(next) {
        return true;
    }
    // Commands and URLs never contain hyphenation points (powe<SHY>rshell,
    // exam<SHY>ple.com).
    line_is_command_or_url(text, offset, line_start, line_cache)
}

/// Does the line around `offset` (invisible characters removed) contain a URL or
/// look like a shell command? Each line is judged once; at most
/// [`MAX_SOFT_HYPHEN_COMMAND_CHECKS`] lines get the command check.
fn line_is_command_or_url(
    text: &str,
    offset: usize,
    line_start: usize,
    line_cache: &mut HashMap<usize, bool>,
) -> bool {
    if let Some(&cached) = line_cache.get(&line_start) {
        return cached;
    }
    let line_end = text
        .get(offset..)
        .and_then(|rest| rest.find(['\r', '\n']))
        .map_or(text.len(), |e| offset + e);
    let line = text.get(line_start..line_end).unwrap_or_default().replace(
        ['\u{00AD}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}'],
        "",
    );
    let line = line.trim();
    let result = line.contains("://")
        || line.to_ascii_lowercase().contains("www.")
        || (line_cache.len() < MAX_SOFT_HYPHEN_COMMAND_CHECKS && looks_like_shell_command(line));
    line_cache.insert(line_start, result);
    result
}

// ---------- bidi ----------

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

// ---------- homoglyphs ----------

fn is_latin_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || ('\u{00C0}'..='\u{024F}').contains(&c) && is_letter(c)
}

/// Cyrillic / Greek look-alikes come from `rules/hidden/homoglyphs.json`.
/// Two patterns count as a homoglyph attack:
/// 1. a word mixing Latin letters and confusables (`powershеll`);
/// 2. no genuine (non-confusable) Cyrillic / Greek letter anywhere, yet a word made
///    only of confusables among English words (`echo һоѕt`).
///
/// Real Russian or Greek text always contains non-confusable letters (и, л, λ…).
/// Returns the first offending look-alike and its script.
fn find_homoglyph(text: &str) -> Option<(char, &'static str)> {
    let rules = HiddenRules::embedded();
    // Legacy words are runs of UTF-16 letters, so supplementary-plane chars split words.
    static WORDS: OnceLock<Option<Regex>> = OnceLock::new();
    let words = WORDS
        .get_or_init(|| Regex::new(r"[\p{L}&&[\x{0}-\x{FFFF}]]+").ok())
        .as_ref()?;

    let mut has_latin_word = false;
    let mut has_genuine_foreign = false;
    let mut all_confusable_candidate = None;
    for word in words.find_iter(text).map(|m| m.as_str()) {
        let mut latin = false;
        let mut confusable = None;
        let mut all_confusable = true;
        for c in word.chars() {
            if is_latin_letter(c) {
                latin = true;
            }
            if let Some(script) = rules.confusable_script(c) {
                confusable = confusable.or(Some((c, script)));
            } else {
                all_confusable = false;
                if rules.in_homoglyph_script(c) {
                    has_genuine_foreign = true;
                }
            }
        }
        if latin && confusable.is_some() {
            return confusable;
        }
        if latin {
            has_latin_word = true;
        }
        if all_confusable && confusable.is_some() && word.chars().count() >= 2 {
            all_confusable_candidate = all_confusable_candidate.or(confusable);
        }
    }
    if has_latin_word && !has_genuine_foreign {
        all_confusable_candidate
    } else {
        None
    }
}

// ---------- trailing newline ----------

fn has_trailing_newline_after_command(text: &str) -> bool {
    if !text.ends_with(['\n', '\r']) {
        return false;
    }
    let body = text.trim_end_matches(['\r', '\n', ' ', '\t']);
    if body.is_empty() {
        return false;
    }
    let last_line = body.rfind(['\r', '\n']).map_or(body, |i| &body[i + 1..]);
    looks_like_shell_command(last_line.trim())
}

/// Does a (trimmed) line look like a shell command? Legacy `LooksLikeShellCommand`.
fn looks_like_shell_command(line: &str) -> bool {
    // Strip common documentation prompts: "$ git pull", "> npm i", "PS C:\> dir".
    let line = if let Some(rest) = ["$ ", "> ", "# "].iter().find_map(|p| line.strip_prefix(p)) {
        rest.trim_start()
    } else if line.starts_with("PS ") {
        match line.find('>') {
            Some(gt) if gt > 0 => line[gt + 1..].trim_start(),
            _ => line,
        }
    } else {
        line
    };
    if line.is_empty() {
        return false;
    }

    // Legacy: `CommandDetector.Analyze(line).Level != None`.
    if crate::command::analyze(line).level != Level::None {
        return true;
    }

    let mut tokens = line.split([' ', '\t']).filter(|t| !t.is_empty());
    let Some(first) = tokens.next() else {
        return false;
    };
    let program = match first.len().checked_sub(4) {
        Some(cut) if first.is_char_boundary(cut) && first[cut..].eq_ignore_ascii_case(".exe") => {
            &first[..cut]
        }
        _ => first,
    };
    // Programs from `rules/hidden/shell-commands.json` (lowercase).
    let known = HiddenRules::embedded()
        .shell_commands
        .contains(&program.to_ascii_lowercase())
        || program.starts_with("./")
        || program.starts_with(".\\");
    if !known {
        return false;
    }
    // "git 是版本控制工具": a program name followed by CJK text is a sentence, not a command.
    tokens
        .next()
        .and_then(|t| t.chars().next())
        .is_none_or(|c| !is_cjk(c))
}

fn is_cjk(c: char) -> bool {
    matches!(c,
        '\u{3040}'..='\u{30FF}'     // hiragana, katakana
        | '\u{3400}'..='\u{9FFF}'   // CJK ideographs
        | '\u{AC00}'..='\u{D7AF}'   // Hangul
        | '\u{FF00}'..='\u{FFEF}') // full width
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(text: &str) -> Vec<String> {
        analyze(text)
            .reasons
            .iter()
            .map(|m| m.id.to_string())
            .collect()
    }

    #[test]
    fn clean_inputs() {
        assert_eq!(analyze(""), Verdict::CLEAN);
        assert_eq!(analyze("Hello world\n"), Verdict::CLEAN);
        assert_eq!(analyze("git 是版本控制工具\n"), Verdict::CLEAN);
        assert_eq!(analyze("Donau\u{ad}dampf\u{ad}schiff"), Verdict::CLEAN);
        assert_eq!(analyze("2πr, 10 μm"), Verdict::CLEAN);
    }

    #[test]
    fn tags_and_flags() {
        let england = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";
        assert_eq!(analyze(england), Verdict::CLEAN);
        let v = analyze(&format!("{england}\u{E0068}\u{E0069}"));
        assert_eq!(v.reasons[0].args[0].1, crate::Arg::Num(2));
        // A flag without the cancel tag: all five tags count.
        let v = analyze("\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067} x");
        assert_eq!(v.reasons[0].args[0].1, crate::Arg::Num(5));
    }

    #[test]
    fn trailing_newline_uses_command_detector() {
        assert_eq!(
            ids("PS C:\\> Remove-Item foo; pwsh -c whoami\n"),
            ["hidden-trailing-newline"]
        );
        assert_eq!(ids("./install.sh\n"), ["hidden-trailing-newline"]);
        assert_eq!(ids("GIT.EXE pull\r\n"), ["hidden-trailing-newline"]);
    }

    #[test]
    fn invisible_samples_are_code_points() {
        let v = analyze("secret\u{3164}value\u{ad}");
        let m = &v.reasons[0];
        assert_eq!(m.id, "hidden-other-invisible");
        assert!(
            m.args
                .contains(&("cp1".into(), crate::Arg::Str("U+3164".into())))
        );
        assert!(
            m.args
                .contains(&("cp2".into(), crate::Arg::Str("U+00AD".into())))
        );
    }

    #[test]
    fn virama_joiners() {
        // Malayalam chillu (NA + VIRAMA + ZWJ) before a space, punctuation, end.
        assert_eq!(analyze("അവന്\u{200d} വന്നു"), Verdict::CLEAN);
        assert_eq!(analyze("അവന്\u{200d}, വന്നു"), Verdict::CLEAN);
        assert_eq!(analyze("അവന്\u{200d}"), Verdict::CLEAN);
        assert_eq!(analyze("അവന്\u{200d}\n"), Verdict::CLEAN);
        // Devanagari half form at a word end.
        assert_eq!(analyze("क्\u{200d} "), Verdict::CLEAN);
        // Not after a virama of the same block / Latin around / runs / ZWNJ.
        assert_eq!(ids("pow\u{200d}ershell"), ["hidden-zero-width"]);
        assert_eq!(ids("a\u{0d4d}\u{200d} b"), ["hidden-zero-width"]);
        assert_eq!(ids("क\u{0d4d}\u{200d} "), ["hidden-zero-width"]);
        assert_eq!(ids("\u{0d4d}\u{200d} "), ["hidden-zero-width"]);
        assert_eq!(ids("അവന്\u{200d}powershell"), ["hidden-zero-width"]);
        assert_eq!(ids("അവന്\u{200d}1"), ["hidden-zero-width"]);
        assert_eq!(ids("അവന്\u{200d}\u{200d} "), ["hidden-zero-width"]);
        assert_eq!(ids("അവന്\u{200c} "), ["hidden-zero-width"]);
    }

    #[test]
    fn new_invisible_characters() {
        // Combining grapheme joiner: only before a combining mark.
        assert_eq!(analyze("u\u{034f}\u{0308}"), Verdict::CLEAN);
        assert_eq!(ids("pay\u{034f}pal"), ["hidden-other-invisible"]);
        // Khmer inherent vowels: only inside Khmer text.
        assert_eq!(analyze("\u{1780}\u{17b4}\u{1781}"), Verdict::CLEAN);
        assert_eq!(ids("adm\u{17b5}in"), ["hidden-other-invisible"]);
        // Invisible math operators: single ones in equations are fine.
        assert_eq!(analyze("sin\u{2061}x + 2\u{2062}y"), Verdict::CLEAN);
        assert_eq!(
            ids("Hi\u{2062}\u{2063}\u{2064} there"),
            ["hidden-other-invisible"]
        );
        assert_eq!(
            ids("hello\u{200c}\u{2061}world"),
            ["hidden-zero-width", "hidden-other-invisible"]
        );
        assert_eq!(
            ids("https://exam\u{2062}ple.invalid"),
            ["hidden-other-invisible"]
        );
        assert_eq!(ids("git pu\u{2063}ll"), ["hidden-other-invisible"]);
    }

    /// 1 Mi-char pathological inputs; timing only asserted in optimized builds.
    #[test]
    fn pathological_inputs_are_fast() {
        const N: usize = 1 << 20;
        let line = format!("{}\n", "git pu\u{ad}ll ".repeat(400));
        let inputs = [
            "\u{200d}".repeat(N),
            "\u{0d28}\u{0d4d}\u{200d}".repeat(N / 3),
            "a\u{2061}".repeat(N / 2),
            "\u{2062}".repeat(N),
            format!("{}\n", "git pu\u{2063}ll ".repeat(N / 12)),
            line.repeat(N / line.chars().count()),
            "u\u{034f}".repeat(N / 2),
            "\u{17b4}".repeat(N),
            "еa ".repeat(N / 3),
            format!("{}\n", "curl x | sh ".repeat(N / 12)),
        ];
        for input in &inputs {
            let start = std::time::Instant::now();
            let v = analyze(input);
            let elapsed = start.elapsed();
            assert!(v.reasons.len() <= 7);
            if !cfg!(debug_assertions) {
                assert!(
                    elapsed.as_millis() <= crate::text::perf_budget_ms(150),
                    "{} chars took {elapsed:?}",
                    input.chars().count()
                );
            }
        }
    }

    #[test]
    fn variation_selector_runs() {
        assert_eq!(analyze("\u{2764}\u{fe0f}\u{fe0f}"), Verdict::CLEAN);
        assert_eq!(analyze("\u{845b}\u{E0100}"), Verdict::CLEAN);
        assert_eq!(ids("a\u{E0100}b"), ["hidden-other-invisible"]);
    }
}
