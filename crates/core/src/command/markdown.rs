//! Markdown code markers (phase-1.md 1b 待辦, docs/spec/detection-rules.md §3.0).
//!
//! READMEs wrap commands in fences (```` ```sh ````) and inline code (`` `bun upgrade` ``).
//! Those backticks are not PowerShell escapes, so they must neither count as a
//! "built string" (which disables the official installer list) nor be removed by
//! the backtick deobfuscation layer as if they were escapes.
//!
//! - A **fence line** is a line whose first non-blank characters (after optional
//!   `>` quote markers) are three or more backticks or tildes; the whole line (the
//!   info string such as `powershell` included) is dropped, the newline kept.
//! - An **inline code span** is a run of one or two backticks that starts the text
//!   or follows a non-word character, whose next backtick run on the same line has
//!   the same length, is followed by a non-word character (or the end) and encloses
//!   at least one character. Its two delimiter runs are removed, the content kept.
//!
//! Everything else (`` p`ow`er ``, `` "a`.b" ``, a line-continuation backtick) is left
//! alone, so it still counts as a PowerShell escape. One pass, linear time.

use std::borrow::Cow;

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Is `line` a fence line: three or more backticks / tildes, then at most one
/// info-string token (`sh`, `powershell`, `c++`) and nothing else? A line such as
/// ```` ```& ('ms'+'hta') ```` is not a fence and keeps its backticks.
fn is_fence(line: &str) -> bool {
    let t = line.trim_start_matches(|c: char| c.is_whitespace() || c == '>');
    let Some(mark) = ['`', '~'].into_iter().find(|m| t.starts_with(*m)) else {
        return false;
    };
    let run = t.len() - t.trim_start_matches(mark).len();
    let info = t[run..].trim();
    run >= 3
        && info
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '+' | '.' | '#'))
}

/// Removes fence lines and inline code delimiters. Borrowed when nothing changed.
pub(crate) fn strip_code_markers(text: &str) -> Cow<'_, str> {
    if !text.contains('`') && !text.contains("~~~") {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if is_fence(line) {
            // Keep a trailing \r so line endings stay consistent.
            if line.ends_with('\r') {
                out.push('\r');
            }
            changed = true;
            continue;
        }
        changed |= strip_inline(line, &mut out);
    }
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(text)
    }
}

/// Appends `line` without inline code delimiters; returns whether any were removed.
fn strip_inline(line: &str, out: &mut String) -> bool {
    if !line.contains('`') {
        out.push_str(line);
        return false;
    }
    let chars: Vec<char> = line.chars().collect();
    let bytes: Vec<usize> = line
        .char_indices()
        .map(|(i, _)| i)
        .chain([line.len()])
        .collect();
    let byte = |k: usize| bytes.get(k).copied().unwrap_or(line.len());
    // Backtick runs as (start, end) char indices.
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut k = 0;
    while k < chars.len() {
        if chars[k] == '`' {
            let start = k;
            while k < chars.len() && chars[k] == '`' {
                k += 1;
            }
            runs.push((start, k));
        } else {
            k += 1;
        }
    }
    // next_same[r]: the next run after `r` with the same length (1 or 2), found
    // right to left in one pass so the whole scan stays linear.
    let mut next_same: Vec<Option<usize>> = vec![None; runs.len()];
    let mut last_of_len: [Option<usize>; 3] = [None; 3];
    for r in (0..runs.len()).rev() {
        let len = runs[r].1 - runs[r].0;
        if len <= 2 {
            next_same[r] = last_of_len[len];
            last_of_len[len] = Some(r);
        }
    }
    let mut changed = false;
    let mut copied = 0usize; // byte offset in `line` copied so far
    let mut r = 0usize;
    while r < runs.len() {
        let (start, end) = runs[r];
        let prev_ok = start == 0 || !is_word(chars[start - 1]);
        let close = next_same[r].filter(|_| prev_ok && end - start <= 2);
        let Some(c) = close else {
            r += 1;
            continue;
        };
        let (close_start, close_end) = runs[c];
        let next_ok = close_end == chars.len() || !is_word(chars[close_end]);
        if !next_ok || close_start == end {
            r += 1;
            continue;
        }
        out.push_str(&line[copied..byte(start)]);
        out.push_str(&line[byte(end)..byte(close_start)]);
        copied = byte(close_end);
        changed = true;
        r = c + 1;
    }
    out.push_str(&line[copied..]);
    changed
}

/// Does `text` contain a backtick outside markdown code markers (a PowerShell
/// escape or line continuation)?
pub(crate) fn has_code_backtick(text: &str) -> bool {
    text.contains('`') && strip_code_markers(text).contains('`')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fences_and_spans_are_removed() {
        assert_eq!(
            strip_code_markers("## Install\n```sh\ncurl x | sh\n```\nthen `bun upgrade`."),
            "## Install\n\ncurl x | sh\n\nthen bun upgrade."
        );
        assert_eq!(strip_code_markers("> ```powershell\r\nx"), "\r\nx");
        assert_eq!(strip_code_markers("use ``a`b`` here"), "use a`b here");
    }

    #[test]
    fn escapes_are_kept() {
        for s in [
            "p`ow`er`shell",
            "i`ex",
            "\"https://a.b`.evil\"",
            "Get-Item `\n -Path x",
            "x`",
            "`i`ex",
            "```& ('ms'+'hta') x",
        ] {
            assert!(has_code_backtick(s), "{s}");
        }
        for s in ["run `cmd /c dir` now", "```\ncode\n```", "`a` and `b`"] {
            assert!(!has_code_backtick(s), "{s}");
        }
    }

    #[test]
    fn linear_on_many_backticks() {
        let s = "a`".repeat(200_000);
        let start = std::time::Instant::now();
        let _ = strip_code_markers(&s);
        assert!(start.elapsed().as_secs() < 5);
    }
}
