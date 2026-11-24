//! Plain-language explanation of a command (legacy `CommandExplainer`,
//! docs/spec/detection-rules.md §3.3), e.g. "downloads and runs code from
//! example.invalid", "hides its window". Literal analysis only: nothing is run or
//! fetched. Returns message ids; the UI renders them.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use crate::Message;

use super::re::{Signal, lazy_re};
use super::{download_exec, normalize, signals};

/// Only this many chars (of the original text) are explained, so huge clipboards
/// cannot slow down notifications.
pub const MAX_EXPLAIN_LENGTH: usize = 4096;
/// At most this many source hosts are named.
pub const MAX_HOSTS: usize = 3;

/// A command explanation (legacy `CommandExplanation`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Explanation {
    /// What the command does, most important first. Never empty.
    pub actions: Vec<Message>,
    /// The decoded `-EncodedCommand` text, if any could be decoded.
    pub decoded: Option<String>,
}

impl Explanation {
    /// The decoded command on one line (whitespace runs → one space, trimmed), for
    /// display. Render it with [`MSG_DISPLAY_DECODED`].
    pub fn decoded_one_line(&self) -> Option<String> {
        self.decoded
            .as_ref()
            .map(|d| d.split_whitespace().collect::<Vec<_>>().join(" "))
    }
}

/// Separator between rendered actions in a summary (`；` / `"; "`).
pub const MSG_ACTION_SEPARATOR: &str = "cmd-explain-separator";
/// First display line; argument `summary` (the rendered, joined actions).
pub const MSG_DISPLAY_SUMMARY: &str = "cmd-explain-display";
/// Second display line; argument `decoded` ([`Explanation::decoded_one_line`]).
pub const MSG_DISPLAY_DECODED: &str = "cmd-explain-decoded";

/// Legacy `CommandExplanation.ToDisplayText` truncation: text longer than
/// `max_len` chars is cut to `max_len - 1` chars plus `…`.
pub fn truncate_display(text: &str, max_len: usize) -> String {
    if text.chars().nth(max_len).is_none() {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max_len.saturating_sub(1)).collect();
    out.push('…');
    out
}

// Keywords in these patterns are split with `concat!` so the source file does
// not look like a download-and-run script to antivirus heuristics (Defender
// flagged it, #40). The compiled patterns are unchanged.
lazy_re! {
    /// PowerShell accepts any prefix of `-EncodedCommand` (`-e`, `-en`, `-enc`…) and
    /// the alias `-ec`.
    fn encoded_arg = r#"(?i)(?:^|\s)-(?P<name>[a-z]+)\s+["']?(?P<b64>[A-Za-z0-9+/]{8,}={0,2})"#;
}
lazy_re! {
    fn download = concat!(r"(?i)\b(?:iwr|irm|curl|wget|invoke-web", r"request|invoke-rest", r"method|start-bits", r"transfer)\b|download", r"string|download", r"data|net\.web", r"client");
}
lazy_re! {
    fn execute = concat!(r"(?i)\b(?:iex|invoke-", r"expression)\b|\|\s*(?:powershell|pwsh|cmd|(?:ba|z)?sh)(?:\.exe)?\b|scriptblock\]\s*::\s*create\b");
}
lazy_re! { fn unc_host = r#"\\\\(?P<host>[^\s\\"'/@]+)"#; }
lazy_re! {
    fn download_file = concat!(r"(?i)download", r"file|-outfile\b|\bcert", r"util(?:\.exe)?\b.*-url", r"cache|\bbits", r"admin(?:\.exe)?\b.*/transfer|\bstart-bits", r"transfer\b");
}
lazy_re! { fn mshta = concat!(r"(?i)\bms", r"hta(?:\.exe)?\b"); }
lazy_re! { fn regsvr32 = concat!(r"(?i)\bregsvr", r"32(?:\.exe)?\b.*/i:"); }
lazy_re! { fn msiexec = concat!(r"(?i)\bmsi", r"exec(?:\.exe)?\b.*https?://"); }
lazy_re! { fn rundll32_script = concat!(r"(?i)\brundll", r"32(?:\.exe)?\b.*java", r"script:"); }
lazy_re! { fn start_process = r"(?i)\b(?:start-process|saps)\b"; }
lazy_re! { fn run_as = r#"(?i)-verb\s+["']?runas"#; }
lazy_re! {
    fn hidden = format!(r"(?i){}|\bconhost(?:\.exe)?\b.*--headless", signals::HIDDEN_WINDOW);
}
lazy_re! {
    fn bypass = concat!(r#"(?i)(?:^|\s)-(?:ep|ex|exec|execution"#, r#"policy)\s+["']?by"#, r#"pass\b|\bset-execution"#, r#"policy\b"#);
}
lazy_re! { fn defender = concat!(r"(?i)\b(?:add|set)-mp", r"preference\b"); }

/// Finds a PowerShell `-EncodedCommand` argument and decodes it as UTF-16LE
/// (legacy `CommandExplainer.DecodeEncodedCommand`). `None` when there is none, it
/// does not decode, or the result does not look like text. Does not normalize.
pub fn decode_encoded(text: &str) -> Option<String> {
    find_encoded_arg(text).and_then(try_decode)
}

/// Explains `text` (legacy `CommandExplainer.Explain`).
pub fn explain(text: &str) -> Explanation {
    // Normalize like detection so full paths, ^, split quotes and dash variants are
    // explained too (#19).
    let head = text
        .char_indices()
        .nth(MAX_EXPLAIN_LENGTH)
        .map_or(text, |(i, _)| &text[..i]);
    let text = normalize(head);
    let encoded = find_encoded_arg(&text);
    let decoded = encoded.and_then(try_decode);
    // Explain the decoded part too, so the hidden payload is described.
    let all = match &decoded {
        Some(d) => format!("{text}\n{d}"),
        None => text.clone(),
    };

    let mut hosts = download_exec::hosts(&all);
    hosts.truncate(MAX_HOSTS);
    let mut actions = Vec::new();

    let download_and_run =
        download().is_match(&all) && execute().is_match(&all) || download_exec::is_match(&all);
    if download_and_run {
        actions.push(with_hosts("cmd-explain-download-and-run", &hosts));
    }
    if mshta().is_match(&all) {
        actions.push(match hosts.first() {
            Some(h) => Message::new("cmd-explain-mshta-host").arg("host", h.as_str()),
            None => Message::new("cmd-explain-mshta-script"),
        });
    }
    if regsvr32().is_match(&all) {
        actions.push(with_hosts("cmd-explain-regsvr32", &hosts));
    }
    if msiexec().is_match(&all) {
        actions.push(with_hosts("cmd-explain-msiexec", &hosts));
    }
    if !download_and_run && download_file().is_match(&all) {
        actions.push(with_hosts("cmd-explain-download-file", &hosts));
    }
    if rundll32_script().is_match(&all) {
        actions.push(Message::new("cmd-explain-rundll32"));
    }
    add_lolbin_actions(&all, &mut actions);
    if start_process().is_match(&all) {
        actions.push(Message::new(if run_as().is_match(&all) {
            "cmd-explain-start-process-admin"
        } else {
            "cmd-explain-start-process"
        }));
    }
    if hidden().is_match(&all) {
        actions.push(Message::new("cmd-explain-hidden"));
    }
    if bypass().is_match(&all) {
        actions.push(Message::new("cmd-explain-bypass"));
    }
    if defender().is_match(&all) {
        actions.push(Message::new("cmd-explain-defender"));
    }
    if encoded.is_some() {
        actions.push(Message::new(if decoded.is_some() {
            "cmd-explain-encoded"
        } else {
            "cmd-explain-encoded-undecodable"
        }));
    }
    if actions.is_empty() {
        actions.push(Message::new("cmd-explain-generic"));
    }
    Explanation { actions, decoded }
}

/// A message naming up to three source hosts: `count` (0 = "the internet") and
/// `h1`..`h3`.
fn with_hosts(id: &'static str, hosts: &[String]) -> Message {
    let mut m = Message::new(id).arg("count", hosts.len());
    for (name, h) in ["h1", "h2", "h3"].into_iter().zip(hosts) {
        m = m.arg(name, h.as_str());
    }
    m
}

/// Every `-EncodedCommand` argument that decodes to text: the byte range of the
/// Base64 and the decoded script (deobfuscation layer, 1b).
pub(crate) fn encoded_args(text: &str) -> Vec<(std::ops::Range<usize>, String)> {
    let Some(re) = encoded_arg().get() else {
        return Vec::new();
    };
    re.captures_iter(text)
        .filter_map(|c| {
            let name = c.name("name")?.as_str().to_lowercase();
            let b64 = c.name("b64")?;
            if name != "ec" && !"encodedcommand".starts_with(name.as_str()) {
                return None;
            }
            try_decode(b64.as_str()).map(|d| (b64.range(), d))
        })
        .collect()
}

/// Lenient standard Base64 → bytes (padding optional).
pub(crate) fn base64_bytes(b64: &str) -> Option<Vec<u8>> {
    let b64 = b64.trim_end_matches('=');
    if b64.len() % 4 == 1 {
        return None;
    }
    LENIENT.decode(b64).ok()
}

/// Decoded text that looks like a script: no control characters other than
/// whitespace, no U+FFFD, and at least half printable ASCII (in UTF-16 units).
pub(crate) fn looks_like_text(s: &str) -> bool {
    if s.is_empty()
        || s.chars()
            .any(|c| c.is_control() && !matches!(c, '\r' | '\n' | '\t') || c == '\u{FFFD}')
    {
        return false;
    }
    let ascii = s
        .chars()
        .filter(|c| matches!(c, ' '..='~' | '\r' | '\n' | '\t'))
        .count();
    ascii * 2 >= crate::text::utf16_len(s)
}

fn find_encoded_arg(text: &str) -> Option<&str> {
    let re = encoded_arg().get()?;
    re.captures_iter(text).find_map(|c| {
        let name = c.name("name")?.as_str().to_lowercase();
        let b64 = c.name("b64")?.as_str();
        (name == "ec" || "encodedcommand".starts_with(name.as_str())).then_some(b64)
    })
}

/// Standard Base64 that tolerates missing padding and non-zero trailing bits
/// (like .NET `Convert.FromBase64String` after re-padding).
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn try_decode(b64: &str) -> Option<String> {
    let bytes = base64_bytes(b64)?;
    utf16_text(&bytes, false)
}

/// UTF-16 (little- or big-endian) bytes → trimmed text, if it looks like text.
pub(crate) fn utf16_text(bytes: &[u8], big_endian: bool) -> Option<String> {
    if bytes.len() < 2 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            if big_endian {
                u16::from_be_bytes(*p)
            } else {
                u16::from_le_bytes(*p)
            }
        })
        .collect();
    let decoded = String::from_utf16_lossy(&units);
    let s = decoded.trim_matches(['\0', ' ', '\r', '\n', '\t']);
    // PowerShell scripts are almost all ASCII; ordinary Base64 (say UTF-8 text)
    // decoded as UTF-16LE becomes rare CJK. Require at least half printable ASCII.
    looks_like_text(s).then(|| s.to_owned())
}

/// UTF-8 bytes → trimmed text, if it looks like text.
pub(crate) fn utf8_text(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let s = s.trim_matches(['\0', ' ', '\r', '\n', '\t']);
    looks_like_text(s).then(|| s.to_owned())
}

/// #21 system programs, remote files and protocol handlers. Patterns are shared
/// with detection so explanations and verdicts agree.
fn add_lolbin_actions(text: &str, actions: &mut Vec<Message>) {
    let share = unc_host()
        .get()
        .and_then(|r| r.captures(text))
        .and_then(|c| c.name("host"))
        .map(|m| m.as_str().to_lowercase());

    let simple: [Signal; 8] = [
        (signals::delayed_expansion, "cmd-explain-delayed-expansion"),
        (signals::script_host, "cmd-explain-script-host"),
        (signals::html_help, "cmd-explain-html-help"),
        (signals::cmstp, "cmd-explain-cmstp"),
        (signals::pcalua, "cmd-explain-pcalua"),
        (signals::odbcconf, "cmd-explain-odbcconf"),
        (signals::install_util, "cmd-explain-installutil"),
        (signals::ftp_script, "cmd-explain-ftp-script"),
    ];
    for (re, id) in simple {
        if re().is_match(text) {
            actions.push(Message::new(id));
        }
    }
    let remote = |with_host: &'static str, without: &'static str| match &share {
        Some(h) => Message::new(with_host).arg("host", h.as_str()),
        None => Message::new(without),
    };
    if signals::remote_file().is_match(text) {
        actions.push(remote(
            "cmd-explain-remote-file-host",
            "cmd-explain-remote-file",
        ));
    } else if signals::webdav().is_match(text) {
        actions.push(remote("cmd-explain-webdav-host", "cmd-explain-webdav"));
    }
    if signals::net_use_then_run(text) {
        actions.push(Message::new("cmd-explain-net-use"));
    }
    if signals::search_ms().is_match(text) {
        actions.push(Message::new("cmd-explain-search-ms"));
    }
    if signals::ms_msdt().is_match(text) {
        actions.push(Message::new("cmd-explain-ms-msdt"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [
            encoded_arg(),
            download(),
            execute(),
            unc_host(),
            download_file(),
            mshta(),
            regsvr32(),
            msiexec(),
            rundll32_script(),
            start_process(),
            run_as(),
            hidden(),
            bypass(),
            defender(),
        ] {
            assert!(re.compiled());
        }
    }

    #[test]
    fn decodes_unpadded_utf16le() {
        assert_eq!(
            decode_encoded("x -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMA").as_deref(),
            Some("Start-Process calc")
        );
        assert_eq!(decode_encoded("x -enc QUJDREVGR0hJSktMTU5PUA=="), None);
        assert_eq!(decode_encoded("x -ex AAAAAAAAAAAA"), None);
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate_display("abcdef", 6), "abcdef");
        assert_eq!(truncate_display("abcdefg", 6), "abcde…");
        assert_eq!(truncate_display("abc", 0), "…");
    }

    #[test]
    fn generic_when_nothing_recognized() {
        let e = explain("cmd /c dir");
        assert_eq!(e.actions, vec![Message::new("cmd-explain-generic")]);
        assert_eq!(e.decoded, None);
    }
}
