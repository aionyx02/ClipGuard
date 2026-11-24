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

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

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

    if let Some(glyph) = find_homoglyph(text) {
        let script = if glyph >= '\u{0400}' {
            "cyrillic"
        } else {
            "greek"
        };
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
    let Some(&(_, c)) = chars.get(k) else {
        return false;
    };
    let prev = k.checked_sub(1).and_then(|p| chars.get(p)).map(|x| x.1);
    let next = chars.get(k + 1).map(|x| x.1);
    let (Some(prev), Some(next)) = (prev, next) else {
        return false;
    };
    if c == '\u{200D}' && is_emoji_like(prev) && is_emoji_like(next) {
        return true;
    }
    is_complex_script_letter(prev) && is_complex_script_letter(next)
}

fn is_emoji_like(c: char) -> bool {
    let cp = u32::from(c);
    cp >= 0x1F000 // most emoji, skin tones
        || (0x2600..=0x27BF).contains(&cp) // ♀ ♂ ⚕ ❤ …
        || (0x2B00..=0x2BFF).contains(&cp)
        || cp == 0xFE0F // emoji variation selector
}

/// Hebrew through Indic / Southeast Asian scripts (U+0590–U+1CFF), where ZWNJ / ZWJ
/// control glyph joining: Lo, Mn, Mc or Me.
fn is_complex_script_letter(c: char) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    ('\u{0590}'..='\u{1CFF}').contains(&c)
        && RE
            .get_or_init(|| Regex::new(r"\A[\p{Lo}\p{Mn}\p{Mc}\p{Me}]\z").ok())
            .as_ref()
            .is_some_and(|re| char_matches(re, c))
}

// ---------- Unicode TAG (U+E0000–U+E007F) ----------

/// Subdivision flags with a standard (RGI) emoji: England, Scotland, Wales.
/// Any other tag sequence shows as a plain black flag, so its tags stay invisible.
const RGI_FLAG_TAGS: [&str; 3] = ["gbeng", "gbsct", "gbwls"];
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
    let mut spec = String::with_capacity(9);
    let mut k = start;
    // Legacy bound: stop once more than 8 tag letters were read.
    while let Some(&(_, c)) = chars.get(k).filter(|(_, c)| is_tag(*c)) {
        if spec.len() > 8 {
            break;
        }
        if c == CANCEL_TAG {
            return if RGI_FLAG_TAGS.contains(&spec.as_str()) {
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
/// Hangul fillers (unless composing jamo), and variation-selector smuggling.
/// Returns the count and up to [`MAX_INVISIBLE_SAMPLES`] distinct code points.
fn find_other_invisible(text: &str, chars: &[(usize, char)]) -> (usize, Vec<char>) {
    let mut count = 0usize;
    let mut samples: Vec<char> = Vec::with_capacity(MAX_INVISIBLE_SAMPLES);
    let mut hit = |c: char| {
        count += 1;
        if samples.len() < MAX_INVISIBLE_SAMPLES && !samples.contains(&c) {
            samples.push(c);
        }
    };

    let mut soft_hyphen_lines: HashMap<usize, bool> = HashMap::new();
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
            '\u{00AD}' => is_suspicious_soft_hyphen(
                text,
                offset,
                line_start,
                prev,
                next,
                &mut soft_hyphen_lines,
            ),
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
    // exam<SHY>ple.com). Each line is judged once.
    if let Some(&cached) = line_cache.get(&line_start) {
        return cached;
    }
    let line_end = text
        .get(offset..)
        .and_then(|rest| rest.find(['\r', '\n']))
        .map_or(text.len(), |e| offset + e);
    let line = text
        .get(line_start..line_end)
        .unwrap_or_default()
        .replace('\u{00AD}', "");
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

/// Cyrillic / Greek letters that look (almost) exactly like Latin letters.
const CONFUSABLES: &[char] = &[
    // Cyrillic lowercase
    'а', 'е', 'о', 'р', 'с', 'у', 'х', 'і', 'ј', 'ѕ', 'ԁ', 'һ', 'ӏ', 'ԛ', 'ԝ', 'ү',
    // Cyrillic uppercase
    'А', 'В', 'Е', 'К', 'М', 'Н', 'О', 'Р', 'С', 'Т', 'Х', 'І', 'Ј', 'Ѕ', 'Ү',
    // Greek lowercase
    'ο', 'ν', 'ρ', 'ι', // Greek uppercase
    'Α', 'Β', 'Ε', 'Ζ', 'Η', 'Ι', 'Κ', 'Μ', 'Ν', 'Ο', 'Ρ', 'Τ', 'Υ', 'Χ',
];

fn is_latin_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || ('\u{00C0}'..='\u{024F}').contains(&c) && is_letter(c)
}

fn is_cyrillic_or_greek(c: char) -> bool {
    matches!(c, '\u{0370}'..='\u{03FF}' | '\u{0400}'..='\u{052F}' | '\u{1F00}'..='\u{1FFF}')
}

/// Two patterns count as a homoglyph attack:
/// 1. a word mixing Latin letters and confusables (`powershеll`);
/// 2. no genuine (non-confusable) Cyrillic / Greek letter anywhere, yet a word made
///    only of confusables among English words (`echo һоѕt`).
///
/// Real Russian or Greek text always contains non-confusable letters (и, л, λ…).
fn find_homoglyph(text: &str) -> Option<char> {
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
            if CONFUSABLES.contains(&c) {
                confusable = confusable.or(Some(c));
            } else {
                all_confusable = false;
                if is_cyrillic_or_greek(c) {
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

/// Programs that make a line look like a shell command.
const SHELL_COMMANDS: &[&str] = &[
    "sudo",
    "su",
    "git",
    "gh",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "pip",
    "pip3",
    "python",
    "python3",
    "py",
    "node",
    "deno",
    "bun",
    "dotnet",
    "cargo",
    "go",
    "docker",
    "kubectl",
    "helm",
    "terraform",
    "az",
    "aws",
    "gcloud",
    "curl",
    "wget",
    "ssh",
    "scp",
    "rm",
    "del",
    "rmdir",
    "rd",
    "mv",
    "cp",
    "copy",
    "move",
    "chmod",
    "chown",
    "cd",
    "ls",
    "dir",
    "cat",
    "echo",
    "mkdir",
    "touch",
    "make",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pacman",
    "brew",
    "winget",
    "choco",
    "scoop",
    "powershell",
    "pwsh",
    "cmd",
    "bash",
    "sh",
    "zsh",
    "start",
    "iex",
    "irm",
    "iwr",
    "invoke-webrequest",
    "invoke-restmethod",
    "invoke-expression",
    "start-process",
    "set-executionpolicy",
    "reg",
    "net",
    "netsh",
    "sc",
    "taskkill",
    "schtasks",
    "wmic",
    "shutdown",
    "mshta",
    "certutil",
    "bitsadmin",
    "rundll32",
    "regsvr32",
    "msiexec",
    "conhost",
];

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

    if command_detector_flags(line) {
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
    let known = SHELL_COMMANDS
        .iter()
        .any(|c| c.eq_ignore_ascii_case(program))
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

/// Stand-in for legacy `CommandDetector.Analyze(line).Level != None`.
///
/// The full command detector lives in [`crate::command`] (ported in parallel); until
/// the two are wired together this uses the extension's execution-signal subset
/// ([`crate::pastejack::command_signals`]), which covers the program invocations
/// (PowerShell, mshta, cmd /c, download-pipe-to-shell, iex, LOLBins, sudo) the
/// corpus relies on.
fn command_detector_flags(line: &str) -> bool {
    !crate::pastejack::command_signals(line).is_empty()
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
    fn trailing_newline_uses_command_signals() {
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
    fn variation_selector_runs() {
        assert_eq!(analyze("\u{2764}\u{fe0f}\u{fe0f}"), Verdict::CLEAN);
        assert_eq!(analyze("\u{845b}\u{E0100}"), Verdict::CLEAN);
        assert_eq!(ids("a\u{E0100}b"), ["hidden-other-invisible"]);
    }
}
