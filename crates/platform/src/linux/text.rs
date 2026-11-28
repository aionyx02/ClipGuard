//! What to read from a selection, and how (phase-4.md §4.9.2, S5). Pure: the
//! offered MIME types / TARGETS names and the bytes read are passed in.
//!
//! Privacy (P3): text only ever lives in [`Zeroizing`] buffers.

use std::fmt;

use zeroize::Zeroizing;

use crate::clipboard::{ClipEvent, ClipText, EmptyReason, MAX_ANALYZED_CHARS};

/// KDE / KeePassXC marker (S5): when offered, the text is never read.
pub const PASSWORD_MANAGER_HINT: &str = "x-kde-passwordManagerHint";
/// Text MIME types / targets in order of preference. `UTF8_STRING` is the
/// X11 name; Wayland sources offer it too when they bridge X11.
pub const TEXT_MIME_PREFERENCE: [&str; 4] = [
    "text/plain;charset=utf-8",
    "UTF8_STRING",
    "text/plain",
    "STRING",
];
/// What our own writes offer (text only, phase-4.md §4.9.2).
pub const WRITE_MIME_TYPES: [&str; 3] = ["text/plain;charset=utf-8", "UTF8_STRING", "text/plain"];
/// Longest wait for a selection source to deliver its data; on timeout the
/// change is given up (`Empty{Unreadable}`).
pub const DATA_CONTROL_READ_TIMEOUT_MS: u64 = 500;
/// Bytes read from a selection source at most (UTF-8 is at most 4 bytes per
/// char, so this always covers [`MAX_ANALYZED_CHARS`]). A source that keeps
/// sending is cut here (S5 pitfall 4).
pub const DATA_CONTROL_READ_MAX_BYTES: usize = MAX_ANALYZED_CHARS * 4;
/// Cap for [`super::ClipboardHandle::read_full`] / snapshots (custom: far
/// above any text a user pastes, low enough that a streaming source cannot
/// exhaust memory).
pub const FULL_READ_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Timeout for [`FULL_READ_MAX_BYTES`] reads (custom).
pub const FULL_READ_TIMEOUT_MS: u64 = 3_000;
/// Longest time spent writing our text to one requestor (custom; a reader
/// that never reads must not block the thread).
pub const WRITE_TIMEOUT_MS: u64 = 500;
/// MIME types / targets looked at per offer; the rest are ignored (custom).
pub const MAX_OFFERED_TYPES: usize = 64;
/// Longest MIME type / atom name considered (custom).
pub const MAX_MIME_LEN: usize = 256;

/// What to do with a selection, decided from its type list alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferDecision {
    /// Read the text in this MIME type / target.
    Read(&'static str),
    /// Do not read: password manager hint or no text type.
    Skip(EmptyReason),
}

/// Collects the types of one offer, bounded by [`MAX_OFFERED_TYPES`] and
/// [`MAX_MIME_LEN`]. Remembers only what the decision needs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OfferTypes {
    hint: bool,
    /// Bit i set = `TEXT_MIME_PREFERENCE[i]` offered.
    text: u8,
    seen: usize,
}

impl OfferTypes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one offered type.
    pub fn add(&mut self, mime: &str) {
        if self.seen >= MAX_OFFERED_TYPES || mime.len() > MAX_MIME_LEN {
            return;
        }
        self.seen += 1;
        let mime = mime.trim();
        if mime == PASSWORD_MANAGER_HINT {
            self.hint = true;
            return;
        }
        if let Some(i) = TEXT_MIME_PREFERENCE
            .iter()
            .position(|t| t.eq_ignore_ascii_case(mime))
        {
            self.text |= 1 << i;
        }
    }

    pub fn from_types<S: AsRef<str>>(types: impl IntoIterator<Item = S>) -> Self {
        let mut t = Self::new();
        for m in types {
            t.add(m.as_ref());
        }
        t
    }

    pub fn has_password_hint(&self) -> bool {
        self.hint
    }

    /// The hint wins over everything; then the preferred text type.
    pub fn decide(&self) -> OfferDecision {
        if self.hint {
            return OfferDecision::Skip(EmptyReason::Excluded);
        }
        match (0..TEXT_MIME_PREFERENCE.len()).find(|i| self.text & (1 << i) != 0) {
            Some(i) => OfferDecision::Read(TEXT_MIME_PREFERENCE[i]),
            None => OfferDecision::Skip(EmptyReason::NoText),
        }
    }
}

/// Decodes at most [`MAX_ANALYZED_CHARS`] chars of UTF-8 (invalid sequences
/// become U+FFFD) straight into a zeroized buffer. Returns the text and
/// whether it was cut. Same contract as the macOS decoder.
pub fn decode_utf8_prefix(bytes: &[u8]) -> (Zeroizing<String>, bool) {
    let scan = &bytes[..bytes.len().min(DATA_CONTROL_READ_MAX_BYTES)];
    let mut out = Zeroizing::new(String::with_capacity(scan.len().min(MAX_ANALYZED_CHARS)));
    let mut chars = 0usize;
    for chunk in scan.utf8_chunks() {
        let pieces = chunk
            .valid()
            .chars()
            .chain((!chunk.invalid().is_empty()).then_some(char::REPLACEMENT_CHARACTER));
        for c in pieces {
            if chars == MAX_ANALYZED_CHARS {
                return (out, true);
            }
            out.push(c);
            chars += 1;
        }
    }
    (out, bytes.len() > scan.len())
}

/// Decodes all of `bytes` (for `read_full`); invalid sequences become U+FFFD.
pub fn decode_utf8_lossy(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len()));
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out
}

/// How a capped read ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadEnd {
    /// The source closed the pipe / finished the transfer.
    Complete,
    /// The byte cap was reached; the source may have more.
    Capped,
    /// The deadline passed first.
    TimedOut,
    /// The transfer failed (I/O error, conversion refused).
    Failed,
}

/// Bytes read from a selection source.
pub struct ReadResult {
    pub bytes: Zeroizing<Vec<u8>>,
    pub end: ReadEnd,
}

impl fmt::Debug for ReadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadResult")
            .field("len", &self.bytes.len())
            .field("end", &self.end)
            .finish()
    }
}

/// Turns a read into the event for the worker. A timeout or failure gives
/// the change up (phase-4.md §4.9.2: "逾時就放棄這一筆"); a cap keeps the
/// prefix and marks it truncated.
pub fn event_from_read(sequence: u32, read: ReadResult, self_write: bool) -> ClipEvent {
    match read.end {
        ReadEnd::TimedOut | ReadEnd::Failed => ClipEvent::Empty {
            sequence,
            reason: EmptyReason::Unreadable,
        },
        ReadEnd::Complete | ReadEnd::Capped => {
            let (text, cut) = decode_utf8_prefix(&read.bytes);
            if text.is_empty() && read.end == ReadEnd::Complete {
                return ClipEvent::Empty {
                    sequence,
                    reason: EmptyReason::NoText,
                };
            }
            ClipEvent::Text(ClipText {
                sequence,
                text,
                truncated: cut || read.end == ReadEnd::Capped,
                source_url: None,
                owner_process: None,
                self_write,
            })
        }
    }
}

/// Process name from `/proc/<pid>/comm` contents (trailing newline dropped;
/// empty or non-printable names rejected).
pub fn comm_name(bytes: &[u8]) -> Option<String> {
    /// `TASK_COMM_LEN` - 1; anything longer is not a comm file.
    const COMM_MAX: usize = 64;
    let s = std::str::from_utf8(bytes).ok()?.trim_end_matches('\n');
    (!s.is_empty() && s.len() <= COMM_MAX && !s.chars().any(char::is_control)).then(|| s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_wins_without_reading() {
        // KeePassXC on Wayland (S5).
        let t = OfferTypes::from_types([
            "text/plain",
            PASSWORD_MANAGER_HINT,
            "text/plain;charset=utf-8",
        ]);
        assert!(t.has_password_hint());
        assert_eq!(t.decide(), OfferDecision::Skip(EmptyReason::Excluded));
        // KeePassXC on X11: TARGETS names.
        let t = OfferTypes::from_types([
            "text/plain",
            "UTF8_STRING",
            "STRING",
            "TEXT",
            PASSWORD_MANAGER_HINT,
            "TARGETS",
        ]);
        assert_eq!(t.decide(), OfferDecision::Skip(EmptyReason::Excluded));
    }

    #[test]
    fn text_preference() {
        let t = OfferTypes::from_types(["text/plain", "UTF8_STRING", "text/plain;charset=utf-8"]);
        assert_eq!(t.decide(), OfferDecision::Read("text/plain;charset=utf-8"));
        let t = OfferTypes::from_types(["TARGETS", "STRING", "UTF8_STRING"]);
        assert_eq!(t.decide(), OfferDecision::Read("UTF8_STRING"));
        let t = OfferTypes::from_types(["text/html", "text/plain"]);
        assert_eq!(t.decide(), OfferDecision::Read("text/plain"));
        let t = OfferTypes::from_types(["TEXT/PLAIN;CHARSET=UTF-8"]);
        assert_eq!(t.decide(), OfferDecision::Read("text/plain;charset=utf-8"));
        let t = OfferTypes::from_types(["image/png", "text/uri-list"]);
        assert_eq!(t.decide(), OfferDecision::Skip(EmptyReason::NoText));
        assert_eq!(
            OfferTypes::new().decide(),
            OfferDecision::Skip(EmptyReason::NoText)
        );
    }

    #[test]
    fn offer_types_are_bounded() {
        let mut t = OfferTypes::new();
        for i in 0..MAX_OFFERED_TYPES {
            t.add(&format!("application/x-filler-{i}"));
        }
        t.add(PASSWORD_MANAGER_HINT);
        t.add("text/plain");
        assert_eq!(t.decide(), OfferDecision::Skip(EmptyReason::NoText));
        let mut t = OfferTypes::new();
        t.add(&"x".repeat(MAX_MIME_LEN + 1));
        t.add("text/plain");
        assert_eq!(t.decide(), OfferDecision::Read("text/plain"));
    }

    #[test]
    fn utf8_prefix_limits() {
        let (t, cut) = decode_utf8_prefix("ab😀".as_bytes());
        assert_eq!(t.as_str(), "ab😀");
        assert!(!cut);
        let (t, cut) = decode_utf8_prefix(b"a\xffb");
        assert_eq!(t.as_str(), "a\u{FFFD}b");
        assert!(!cut);
        let long = vec![b'a'; MAX_ANALYZED_CHARS + 1];
        let (t, cut) = decode_utf8_prefix(&long);
        assert_eq!(t.chars().count(), MAX_ANALYZED_CHARS);
        assert!(cut);
        let wide = "😀".repeat(MAX_ANALYZED_CHARS).into_bytes();
        let (t, cut) = decode_utf8_prefix(&wide);
        assert_eq!(t.chars().count(), MAX_ANALYZED_CHARS);
        assert!(!cut);
        let junk = vec![0xffu8; DATA_CONTROL_READ_MAX_BYTES + 10];
        let (t, cut) = decode_utf8_prefix(&junk);
        assert_eq!(t.chars().count(), MAX_ANALYZED_CHARS);
        assert!(cut);
    }

    fn read(bytes: &[u8], end: ReadEnd) -> ReadResult {
        ReadResult {
            bytes: Zeroizing::new(bytes.to_vec()),
            end,
        }
    }

    #[test]
    fn read_outcomes() {
        match event_from_read(3, read(b"hello", ReadEnd::Complete), false) {
            ClipEvent::Text(t) => {
                assert_eq!(t.sequence, 3);
                assert_eq!(t.text.as_str(), "hello");
                assert!(!t.truncated && !t.self_write);
            }
            e => panic!("unexpected {e:?}"),
        }
        match event_from_read(4, read(b"partial", ReadEnd::Capped), true) {
            ClipEvent::Text(t) => assert!(t.truncated && t.self_write),
            e => panic!("unexpected {e:?}"),
        }
        for end in [ReadEnd::TimedOut, ReadEnd::Failed] {
            assert!(matches!(
                event_from_read(5, read(b"some", end), false),
                ClipEvent::Empty {
                    sequence: 5,
                    reason: EmptyReason::Unreadable
                }
            ));
        }
        assert!(matches!(
            event_from_read(6, read(b"", ReadEnd::Complete), false),
            ClipEvent::Empty {
                reason: EmptyReason::NoText,
                ..
            }
        ));
    }

    #[test]
    fn read_result_debug_hides_bytes() {
        let d = format!("{:?}", read(b"hidden-words", ReadEnd::Complete));
        assert!(!d.contains("hidden"));
    }

    #[test]
    fn comm_names() {
        assert_eq!(comm_name(b"keepassxc\n").as_deref(), Some("keepassxc"));
        assert_eq!(comm_name(b"\n"), None);
        assert_eq!(comm_name(b"a\x1bb\n"), None);
        assert_eq!(comm_name(&[0xff, b'\n']), None);
    }

    #[test]
    fn lossy_full_decode() {
        assert_eq!(decode_utf8_lossy(b"a\xffb").as_str(), "a\u{FFFD}b");
    }
}
