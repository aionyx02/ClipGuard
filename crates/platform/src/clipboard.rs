//! Platform-independent clipboard plumbing (docs/plan/phase-4.md §4.3, §4.4):
//! the event the monitor sends, de-duplication, the self-write cache and
//! source-URL parsing. Pure logic: time is passed in, nothing is logged.
//!
//! Privacy (P3): clipboard text only ever lives in [`Zeroizing`] buffers and
//! is never formatted into errors or `Debug` output.

use std::collections::VecDeque;
use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use paste_warden_core::limits::MAX_ANALYZED_CHARS;

/// Window during which our own clipboard writes (masked paste, restore) do
/// not raise notifications again (detection-rules.md §5.3).
pub const SELF_WRITE_SUPPRESS_MS: u64 = 3_000;
/// How many of our own recent writes are remembered.
pub const SELF_WRITE_CACHE_LEN: usize = 4;
/// Longest source URL kept for `Context.source.url`; longer ones are dropped.
pub const SOURCE_URL_MAX_BYTES: usize = 2_048;
/// Bytes of a CF_HTML payload scanned for the `SourceURL:` header (the header
/// is a few hundred bytes; the page markup after it is never read).
pub const HTML_HEADER_SCAN_BYTES: usize = 4_096;
/// Analyze the current clipboard right after start-up (legacy #9).
pub const RUN_INITIAL_CHECK: bool = true;

/// SHA-256 of the analyzed text. Only ever compared, never stored on disk.
pub type ContentHash = [u8; 32];

/// Hashes `text` for de-duplication and the self-write cache.
pub fn content_hash(text: &str) -> ContentHash {
    Sha256::digest(text.as_bytes()).into()
}

/// Why a clipboard change carries no text to analyze.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyReason {
    /// No text format (empty, image, files) — including our own clearing.
    NoText,
    /// A password manager marked the content (`ExcludeClipboardContentFromMonitorProcessing`
    /// or `CanIncludeInClipboardHistory = 0`); the text was not read.
    Excluded,
    /// The clipboard could not be opened or read.
    Unreadable,
}

/// One clipboard change, as sent by the platform monitor to the worker.
pub enum ClipEvent {
    Text(ClipText),
    Empty { sequence: u32, reason: EmptyReason },
}

/// Text read from the clipboard.
pub struct ClipText {
    /// `GetClipboardSequenceNumber` (Windows) at read time.
    pub sequence: u32,
    /// At most [`MAX_ANALYZED_CHARS`] chars.
    pub text: Zeroizing<String>,
    /// The clipboard holds more than [`MAX_ANALYZED_CHARS`] chars.
    pub truncated: bool,
    /// Page URL from browser metadata, when present and short enough.
    pub source_url: Option<String>,
    /// Executable name (no extension) of the clipboard owner, when known.
    pub owner_process: Option<String>,
    /// We wrote this ourselves within [`SELF_WRITE_SUPPRESS_MS`]: analyze it
    /// (the guard state machine needs it) but do not notify.
    pub self_write: bool,
}

impl fmt::Debug for ClipText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the text or the URL (P3).
        f.debug_struct("ClipText")
            .field("sequence", &self.sequence)
            .field("chars", &self.text.chars().count())
            .field("truncated", &self.truncated)
            .field("has_source_url", &self.source_url.is_some())
            .field("owner_process", &self.owner_process)
            .field("self_write", &self.self_write)
            .finish()
    }
}

impl fmt::Debug for ClipEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClipEvent::Text(t) => t.fmt(f),
            ClipEvent::Empty { sequence, reason } => f
                .debug_struct("Empty")
                .field("sequence", sequence)
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Formats seen on the clipboard that decide whether the text may be read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClipboardFlags {
    pub has_text: bool,
    /// `ExcludeClipboardContentFromMonitorProcessing` is present.
    pub exclude_monitor: bool,
    /// `CanIncludeInClipboardHistory` is present with value 0. A lone
    /// `CanUploadToCloudClipboard = 0` does **not** count (S3 finding 7).
    pub history_disabled: bool,
}

impl ClipboardFlags {
    /// What to do with this change before reading any text.
    pub fn empty_reason(&self) -> Option<EmptyReason> {
        if self.exclude_monitor || self.history_disabled {
            Some(EmptyReason::Excluded)
        } else if !self.has_text {
            Some(EmptyReason::NoText)
        } else {
            None
        }
    }
}

/// Drops repeated notifications of one copy (S3 finding 4: the same sequence
/// number twice, or a helper rewriting the same text 2–3 times).
///
/// Only the last text is remembered, and an empty clipboard forgets it, so
/// copying the same text again after it was cleared (quarantine) is analyzed
/// again.
#[derive(Debug, Default)]
pub struct Deduper {
    last: Option<(u32, ContentHash)>,
    last_empty: Option<u32>,
}

impl Deduper {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when this text change repeats the previous one.
    pub fn is_repeat(&mut self, sequence: u32, hash: &ContentHash) -> bool {
        let repeat = self
            .last
            .as_ref()
            .is_some_and(|(s, h)| *s == sequence || h == hash);
        self.last = Some((sequence, *hash));
        self.last_empty = None;
        repeat
    }

    /// The clipboard no longer holds readable text. Returns `true` when this
    /// repeats the previous empty notification (same sequence number).
    pub fn on_empty(&mut self, sequence: u32) -> bool {
        self.last = None;
        let repeat = self.last_empty == Some(sequence);
        self.last_empty = Some(sequence);
        repeat
    }
}

/// Our own recent clipboard writes (detection-rules.md §5.3 re-entry rule).
///
/// Our writes carry `CanIncludeInClipboardHistory = 0`, which would otherwise
/// look like a password manager's copy; the sequence number tells the monitor
/// to read them anyway.
#[derive(Debug, Default)]
pub struct SelfWriteCache {
    entries: VecDeque<SelfWrite>,
}

#[derive(Debug, Clone, Copy)]
struct SelfWrite {
    sequence: u32,
    hash: ContentHash,
    at_ms: u64,
}

impl SelfWriteCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a write of text with `hash` that left the clipboard at `sequence`.
    pub fn record(&mut self, sequence: u32, hash: ContentHash, now_ms: u64) {
        if self.entries.len() == SELF_WRITE_CACHE_LEN {
            self.entries.pop_front();
        }
        self.entries.push_back(SelfWrite {
            sequence,
            hash,
            at_ms: now_ms,
        });
    }

    fn expire(&mut self, now_ms: u64) {
        self.entries
            .retain(|w| now_ms.saturating_sub(w.at_ms) <= SELF_WRITE_SUPPRESS_MS);
    }

    /// `true` when the clipboard at `sequence` is one of our writes.
    pub fn is_ours(&mut self, sequence: u32, now_ms: u64) -> bool {
        self.expire(now_ms);
        self.entries.iter().any(|w| w.sequence == sequence)
    }

    /// `true` when text with `hash` was written by us within the window.
    pub fn contains(&mut self, hash: &ContentHash, now_ms: u64) -> bool {
        self.expire(now_ms);
        self.entries.iter().any(|w| &w.hash == hash)
    }
}

/// Decodes at most [`MAX_ANALYZED_CHARS`] chars of NUL-terminated UTF-16
/// (`CF_UNICODETEXT`). Unpaired surrogates become U+FFFD. Returns the text
/// and whether it was cut.
pub fn decode_utf16_prefix(units: &[u16]) -> (Zeroizing<String>, bool) {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    let units = &units[..end];
    let mut out = Zeroizing::new(String::with_capacity(units.len().min(MAX_ANALYZED_CHARS)));
    for (chars, c) in char::decode_utf16(units.iter().copied()).enumerate() {
        if chars == MAX_ANALYZED_CHARS {
            return (out, true);
        }
        out.push(c.unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    (out, false)
}

/// Accepts a source URL only when it is an http(s) URL within
/// [`SOURCE_URL_MAX_BYTES`] and without control characters.
pub fn accept_source_url(url: &str) -> Option<String> {
    let url = url.trim();
    let lower = url
        .get(..8)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let scheme_ok = lower.starts_with("https://") || lower.starts_with("http://");
    (scheme_ok && url.len() <= SOURCE_URL_MAX_BYTES && !url.chars().any(char::is_control))
        .then(|| url.to_owned())
}

/// The `SourceURL:` header of a CF_HTML (`HTML Format`) payload. Only the
/// header (before `<`) is scanned, so the page markup is never searched.
pub fn html_source_url(cf_html: &[u8]) -> Option<String> {
    let header_end = cf_html
        .iter()
        .position(|&b| b == b'<')
        .unwrap_or(cf_html.len());
    let header = std::str::from_utf8(&cf_html[..header_end]).ok()?;
    header
        .lines()
        .find_map(|l| l.strip_prefix("SourceURL:"))
        .and_then(accept_source_url)
}

/// Decodes a small text clipboard format whose encoding is not documented
/// (`Chromium internal source URL`): UTF-16LE when every odd byte of the
/// first character is 0, UTF-8 otherwise. Trailing NULs are dropped.
pub fn decode_format_text(bytes: &[u8]) -> Option<String> {
    let utf16 = bytes.len() >= 2 && bytes.len().is_multiple_of(2) && bytes[1] == 0 && bytes[0] != 0;
    let text = if utf16 {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16(&units).ok()?
    } else {
        String::from_utf8(bytes.to_vec()).ok()?
    };
    Some(text.trim_end_matches('\0').to_owned())
}

/// The executable's file name without directory and `.exe` (case kept).
pub fn process_name_from_path(path: &str) -> Option<String> {
    let name = path.rsplit(['\\', '/']).next()?;
    let stem = match name.len().checked_sub(4) {
        Some(i) if name.is_char_boundary(i) && name[i..].eq_ignore_ascii_case(".exe") => &name[..i],
        _ => name,
    };
    (!stem.is_empty()).then(|| stem.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_decide_before_reading() {
        let text = ClipboardFlags {
            has_text: true,
            ..Default::default()
        };
        assert_eq!(text.empty_reason(), None);
        assert_eq!(
            ClipboardFlags::default().empty_reason(),
            Some(EmptyReason::NoText)
        );
        for flags in [
            ClipboardFlags {
                has_text: true,
                exclude_monitor: true,
                history_disabled: false,
            },
            ClipboardFlags {
                has_text: true,
                exclude_monitor: false,
                history_disabled: true,
            },
        ] {
            assert_eq!(flags.empty_reason(), Some(EmptyReason::Excluded));
        }
    }

    #[test]
    fn dedupe_by_sequence_or_hash_and_forget_on_empty() {
        let a = content_hash("alpha");
        let b = content_hash("beta");
        let mut d = Deduper::new();
        assert!(!d.is_repeat(1, &a));
        assert!(d.is_repeat(1, &a), "same sequence twice");
        assert!(d.is_repeat(2, &a), "helper rewrote the same text");
        assert!(!d.is_repeat(3, &b));
        assert!(!d.on_empty(4));
        assert!(d.on_empty(4), "same empty notification twice");
        assert!(
            !d.is_repeat(5, &b),
            "same text after the clipboard was cleared"
        );
        assert!(
            !d.on_empty(4),
            "an older sequence after text is a new change"
        );
    }

    #[test]
    fn self_write_cache_expires_and_is_bounded() {
        let mut c = SelfWriteCache::new();
        let h = content_hash("masked");
        c.record(40, h, 1_000);
        assert!(c.is_ours(40, 1_000 + SELF_WRITE_SUPPRESS_MS));
        assert!(!c.is_ours(41, 1_000));
        assert!(c.contains(&h, 1_000 + SELF_WRITE_SUPPRESS_MS));
        assert!(!c.contains(&h, 1_001 + SELF_WRITE_SUPPRESS_MS));
        assert!(!c.is_ours(40, 1_001 + SELF_WRITE_SUPPRESS_MS));

        for i in 0..=SELF_WRITE_CACHE_LEN as u32 {
            c.record(i, content_hash(&i.to_string()), 10_000);
        }
        assert!(!c.is_ours(0, 10_000), "oldest evicted");
        assert!(c.is_ours(1, 10_000));
    }

    #[test]
    fn utf16_prefix_stops_at_nul_and_limit() {
        let units: Vec<u16> = "ab😀\0junk".encode_utf16().collect();
        let (t, cut) = decode_utf16_prefix(&units);
        assert_eq!(t.as_str(), "ab😀");
        assert!(!cut);

        let units = vec![u16::from(b'a'); MAX_ANALYZED_CHARS + 1];
        let (t, cut) = decode_utf16_prefix(&units);
        assert_eq!(t.chars().count(), MAX_ANALYZED_CHARS);
        assert!(cut);

        let (t, _) = decode_utf16_prefix(&[0xD800, u16::from(b'x')]);
        assert_eq!(t.as_str(), "\u{FFFD}x");
    }

    #[test]
    fn source_url_from_cf_html_header_only() {
        let html = b"Version:0.9\r\nStartHTML:00000097\r\nSourceURL:https://example.invalid/page\r\n<html>SourceURL:https://example.invalid/fake</html>";
        assert_eq!(
            html_source_url(html).as_deref(),
            Some("https://example.invalid/page")
        );
        let body_only = b"Version:0.9\r\n<p>SourceURL:https://example.invalid/x</p>";
        assert_eq!(html_source_url(body_only), None);
    }

    #[test]
    fn source_url_must_be_http_and_short() {
        assert!(accept_source_url("HTTPS://example.invalid/").is_some());
        assert!(accept_source_url("file:///C:/x").is_none());
        assert!(accept_source_url("javascript:alert(1)").is_none());
        assert!(accept_source_url("https://example.invalid/\nx").is_none());
        let long = format!(
            "https://example.invalid/{}",
            "a".repeat(SOURCE_URL_MAX_BYTES)
        );
        assert!(accept_source_url(&long).is_none());
    }

    #[test]
    fn format_text_in_either_encoding() {
        let url = "https://example.invalid/a";
        let utf16: Vec<u8> = url
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_format_text(&utf16).as_deref(), Some(url));
        let utf8 = format!("{url}\0");
        assert_eq!(decode_format_text(utf8.as_bytes()).as_deref(), Some(url));
        assert_eq!(decode_format_text(&[0xff, 0xfe, 0xfd]), None);
    }

    #[test]
    fn process_names() {
        assert_eq!(
            process_name_from_path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
                .as_deref(),
            Some("chrome")
        );
        assert_eq!(
            process_name_from_path("Notepad.EXE").as_deref(),
            Some("Notepad")
        );
        assert_eq!(
            process_name_from_path("wezterm-gui").as_deref(),
            Some("wezterm-gui")
        );
        assert_eq!(process_name_from_path(r"C:\dir\"), None);
    }

    #[test]
    fn debug_never_prints_text() {
        let ev = ClipEvent::Text(ClipText {
            sequence: 7,
            text: Zeroizing::new("top-secret-text".into()),
            truncated: false,
            source_url: Some("https://example.invalid/private".into()),
            owner_process: Some("chrome".into()),
            self_write: false,
        });
        let s = format!("{ev:?}");
        assert!(!s.contains("top-secret-text"));
        assert!(!s.contains("example.invalid"));
    }
}
