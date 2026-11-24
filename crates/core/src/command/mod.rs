//! ClickFix / FileFix command detection (docs/spec/detection-rules.md §3).
//!
//! - [`analyze`]: verdict + reasons (legacy `CommandDetector.Analyze`)
//! - [`normalize`]: normalization applied before matching (legacy `CommandNormalizer`)
//! - [`explain`]: plain-language explanation (legacy `CommandExplainer`)
//! - [`is_official_host`]: official installer host list (legacy `DownloadExecution`)
//!
//! Word lists (known programs, official hosts, bait keywords, extensions) are data
//! in `rules/command/`; structural logic stays here. Every regex comes from the
//! `regex` crate (linear time); long inputs are segmented and bounded (see
//! [`verdict`] constants), so no input can stall the caller.

mod download_exec;
mod explain;
mod normalize;
pub(crate) mod re;
mod signals;
mod verdict;

pub use explain::{
    Explanation, MAX_EXPLAIN_LENGTH, MAX_HOSTS, MSG_ACTION_SEPARATOR, MSG_DISPLAY_DECODED,
    MSG_DISPLAY_SUMMARY, decode_encoded, explain, truncate_display,
};
pub use normalize::{MAX_EXPANSIONS, MAX_QUOTE_PASSES, MAX_VALUE_LENGTH, MAX_VARIABLES, normalize};
pub use verdict::{
    MAX_LINES, MAX_SCANNED_CHARS, MAX_WHITESPACE_RUN, WINDOW_LENGTH, WINDOW_STEP, analyze,
};

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
