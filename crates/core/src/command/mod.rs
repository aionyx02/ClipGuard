//! ClickFix / FileFix command detection (docs/spec/detection-rules.md §3).
//!
//! - [`analyze`]: verdict + reasons (legacy `CommandDetector.Analyze`, plus the 1b
//!   deobfuscation)
//! - [`analyze_in`]: verdict, risk score, onion trace and hosts for a text copied in
//!   a [`crate::Context`]
//! - [`deobfuscate`]: the onion of deobfuscation layers on its own
//! - [`normalize`]: normalization applied before matching (legacy `CommandNormalizer`)
//! - [`explain`]: plain-language explanation (legacy `CommandExplainer`)
//! - [`is_official_host`]: official installer host list (legacy `DownloadExecution`)
//!
//! Word lists (known programs, official hosts and URL prefixes, bait keywords,
//! extensions) are data in `rules/command/`; structural logic stays here. Every
//! regex comes from the `regex` crate (linear time); long inputs are segmented and
//! bounded (see [`verdict`] and [`deobfuscate`] constants), so no input can stall
//! the caller.

pub mod deobfuscate;
mod download_exec;
mod explain;
mod finding;
mod markdown;
mod normalize;
pub(crate) mod re;
mod signals;
mod verdict;

pub use deobfuscate::{
    Deobfuscated, DeobfuscationStep, MAX_GROWTH, MAX_LAYERS, MAX_OUTPUT_CHARS, StepKind,
    deobfuscate,
};
pub use explain::{
    Explanation, MAX_EXPLAIN_LENGTH, MAX_HOSTS, MSG_ACTION_SEPARATOR, MSG_DISPLAY_DECODED,
    MSG_DISPLAY_SUMMARY, decode_encoded, explain, truncate_display,
};
pub use finding::{CommandFinding, analyze_in, risk_score};
pub use normalize::{MAX_EXPANSIONS, MAX_QUOTE_PASSES, MAX_VALUE_LENGTH, MAX_VARIABLES, normalize};
pub use verdict::{
    MAX_FINDING_HOSTS, MAX_LINES, MAX_SCANNED_CHARS, MAX_WHITESPACE_RUN, WINDOW_LENGTH,
    WINDOW_STEP, analyze,
};

/// Every verdict-reason and deobfuscation-step message id the command module can
/// produce (explanation ids live in `explain.rs`), for locale completeness tests.
pub const MESSAGE_IDS: &[&str] = &[
    "cmd-reason-powershell",
    "cmd-reason-mshta",
    "cmd-reason-cmd",
    "cmd-reason-delayed-expansion",
    "cmd-reason-certutil",
    "cmd-reason-bitsadmin",
    "cmd-reason-rundll32",
    "cmd-reason-regsvr32",
    "cmd-reason-msiexec",
    "cmd-reason-conhost",
    "cmd-reason-curl-shell",
    "cmd-reason-script-host",
    "cmd-reason-html-help",
    "cmd-reason-cmstp",
    "cmd-reason-pcalua",
    "cmd-reason-odbcconf",
    "cmd-reason-installutil",
    "cmd-reason-ftp-script",
    "cmd-reason-remote-file",
    "cmd-reason-webdav",
    "cmd-reason-search-ms",
    "cmd-reason-ms-msdt",
    "cmd-reason-net-use",
    "cmd-reason-download-exec",
    "cmd-reason-osascript",
    "cmd-reason-quarantine",
    "cmd-reason-decode-shell",
    "cmd-reason-dev-tcp",
    "cmd-reason-hidden-window",
    "cmd-reason-encoded",
    "cmd-reason-iex",
    "cmd-reason-download",
    "cmd-reason-bait-comment",
    "cmd-reason-check-mark",
    "cmd-reason-padding",
    "cmd-reason-mshta-remote",
    "cmd-reason-unofficial-source",
    "cmd-reason-reverse-shell",
    "cmd-reason-background",
    "cmd-reason-msiexec-quiet",
    "cmd-reason-obfuscated",
    "cmd-deob-invisible",
    "cmd-deob-dash",
    "cmd-deob-caret",
    "cmd-deob-variable",
    "cmd-deob-quote",
    "cmd-deob-program-path",
    "cmd-deob-markdown",
    "cmd-deob-full-width",
    "cmd-deob-backtick",
    "cmd-deob-url-decode",
    "cmd-deob-hex-decode",
    "cmd-deob-char-code",
    "cmd-deob-concat",
    "cmd-deob-join",
    "cmd-deob-format",
    "cmd-deob-replace",
    "cmd-deob-string-method",
    "cmd-deob-ps-variable",
    "cmd-deob-unwrap",
    "cmd-deob-base64",
    "cmd-deob-encoded-command",
    "cmd-deob-cmd-substring",
    "cmd-deob-nested-variable",
];

/// Is `host_or_url` an official installer host (or a subdomain of one)?
/// A URL (`https://user@astral.sh:443/x`) is reduced to its real host first.
/// ASCII only, case-insensitive; substrings and look-alikes never match.
pub fn is_official_host(host_or_url: &str) -> bool {
    if host_or_url.contains("://") {
        return download_exec::hosts(host_or_url)
            .first()
            .is_some_and(|h| download_exec::is_official_host(h));
    }
    download_exec::is_official_host(host_or_url)
}

/// Download hosts named in `text` (URLs and scheme-less download targets),
/// lowercase, deduplicated, in order. `text` should be [`normalize`]d.
pub fn download_hosts(text: &str) -> Vec<String> {
    download_exec::hosts(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_host_accepts_urls() {
        assert!(is_official_host("https://astral.sh/uv/install.sh"));
        assert!(is_official_host("https://user@docs.astral.sh:443/"));
        assert!(!is_official_host("https://astral.sh@example.invalid/"));
        assert!(!is_official_host("astral.sh$x"));
    }
}
