//! Encodings: full-width letters, URL escapes, hex, Base64 (PowerShell
//! `FromBase64String`, shell `base64 -d`, Python `b64decode`) and PowerShell
//! `-EncodedCommand`. Decoded bytes are used only when they look like text
//! (`explain::looks_like_text`), so random data is never substituted.

use crate::command::explain::{base64_bytes, encoded_args, utf8_text, utf16_text};
use crate::command::re::lazy_re;

use super::{LIT, lit_value, quote};

lazy_re! { fn url_escapes = r"(?:%[0-9A-Fa-f]{2}){3,}"; }
lazy_re! { fn hex_escapes = r"(?:\\x[0-9A-Fa-f]{2}){3,}"; }
lazy_re! { fn hex_token = r"(?-u:\b)(?:[0-9A-Fa-f]{2}){8,}(?-u:\b)"; }
lazy_re! {
    fn ps_base64 = format!(
        r"(?i)\[(?:system\.)?text\.encoding\]\s*::\s*(?P<enc>\w+)\s*\.\s*getstring\s*\(\s*\[(?:system\.)?convert\]\s*::\s*frombase64string\s*\(\s*(?P<b>{LIT})\s*\)\s*\)"
    );
}
lazy_re! {
    fn shell_base64 = r#"(?P<b>[A-Za-z0-9+/]{16,}={0,2})["']?\s*\|\s*base64\s+(?:-\w+\s+)*(?:-d|-D|--decode)(?-u:\b)|(?-u:\b)base64\s+(?:-\w+\s+)*(?:-d|-D|--decode)\s*<<<\s*["']?(?P<b2>[A-Za-z0-9+/]{16,}={0,2})"#;
}
lazy_re! { fn py_base64 = r#"b64decode\(\s*b?["'](?P<b>[A-Za-z0-9+/]{16,}={0,2})["']\s*\)"#; }

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Bytes from pairs of hex digits (other characters skipped).
fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|p| Some(hex_val(*p.first()?)? << 4 | hex_val(*p.get(1)?)?))
        .collect()
}

/// Strictly printable ASCII (plus tab / newline), at least one letter.
fn printable_ascii(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| matches!(b, b' '..=b'~' | b'\t' | b'\n' | b'\r'))
        && bytes.iter().any(u8::is_ascii_alphabetic)
}

/// Replaces matches of `re` whose decoded value (`f`) exists.
fn decode_matches(
    re: Option<&regex::Regex>,
    s: &str,
    f: impl Fn(&regex::Captures<'_>) -> Option<String>,
) -> Option<(String, usize)> {
    let re = re?;
    let mut count = 0usize;
    let out = re.replace_all(s, |c: &regex::Captures<'_>| match f(c) {
        Some(v) => {
            count += 1;
            v
        }
        None => c.get(0).map_or("", |m| m.as_str()).to_owned(),
    });
    (count > 0).then(|| (out.into_owned(), count))
}

/// Full-width Latin letters and digits (U+FF10–FF19, FF21–FF3A, FF41–FF5A) →
/// ASCII. Full-width punctuation (`：`, `（`) is common in CJK prose and stays.
pub(super) fn full_width(s: &str) -> Option<(String, usize)> {
    let is_fw = |c: char| matches!(c, '\u{FF10}'..='\u{FF19}' | '\u{FF21}'..='\u{FF3A}' | '\u{FF41}'..='\u{FF5A}');
    let count = s.chars().filter(|&c| is_fw(c)).count();
    if count == 0 {
        return None;
    }
    let out = s
        .chars()
        .map(|c| {
            if is_fw(c) {
                char::from_u32(c as u32 - 0xFF10 + 0x30).unwrap_or(c)
            } else {
                c
            }
        })
        .collect();
    Some((out, count))
}

/// Runs of three or more `%xx` that decode to UTF-8 text.
pub(super) fn url_decode(s: &str) -> Option<(String, usize)> {
    if !s.contains('%') {
        return None;
    }
    decode_matches(url_escapes().get(), s, |c| {
        let bytes = hex_bytes(c.get(0)?.as_str())?;
        let t = String::from_utf8(bytes).ok()?;
        (!t.chars().any(char::is_control)).then_some(t)
    })
}

/// `\x63\x75…` escapes, and long hex strings (16+ digits) that decode to
/// printable ASCII (`echo 6375726c… | xxd -r -p`).
pub(super) fn hex_decode(s: &str) -> Option<(String, usize)> {
    let a = if s.contains("\\x") {
        decode_matches(hex_escapes().get(), s, |c| {
            let bytes = hex_bytes(&c.get(0)?.as_str().replace("\\x", ""))?;
            printable_ascii(&bytes).then(|| String::from_utf8_lossy(&bytes).into_owned())
        })
    } else {
        None
    };
    let src = a.as_ref().map_or(s, |(t, _)| t.as_str());
    let b = decode_matches(hex_token().get(), src, |c| {
        let bytes = hex_bytes(c.get(0)?.as_str())?;
        printable_ascii(&bytes).then(|| String::from_utf8_lossy(&bytes).into_owned())
    });
    match (a, b) {
        (Some((_, n1)), Some((t, n2))) => Some((t, n1 + n2)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

/// PowerShell `-EncodedCommand <Base64>` → the decoded script in its place.
pub(super) fn encoded_command(s: &str) -> Option<(String, usize)> {
    let args = encoded_args(s);
    if args.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut copied = 0usize;
    for (range, decoded) in &args {
        out.push_str(s.get(copied..range.start)?);
        out.push_str(decoded);
        copied = range.end;
    }
    out.push_str(s.get(copied..)?);
    Some((out, args.len()))
}

/// `[Text.Encoding]::X.GetString([Convert]::FromBase64String('…'))` → literal;
/// `echo <b64> | base64 -d` / `base64 -d <<< <b64>` → decoded text in place of
/// the Base64; Python `b64decode('…')` → literal.
pub(super) fn base64(s: &str) -> Option<(String, usize)> {
    let lower = s.to_ascii_lowercase();
    let mut cur = s.to_owned();
    let mut count = 0usize;
    if lower.contains("frombase64string")
        && let Some((t, n)) = decode_matches(ps_base64().get(), &cur, |c| {
            let b64 = lit_value(c.name("b")?.as_str())?;
            let bytes = base64_bytes(b64.trim())?;
            let enc = c.name("enc")?.as_str().to_ascii_lowercase();
            let text = match enc.as_str() {
                "unicode" => utf16_text(&bytes, false)?,
                "bigendianunicode" => utf16_text(&bytes, true)?,
                "utf8" | "ascii" | "default" | "utf7" | "latin1" => utf8_text(&bytes)?,
                _ => return None,
            };
            Some(quote(&text))
        })
    {
        cur = t;
        count += n;
    }
    if lower.contains("base64")
        && let Some((t, n)) = shell_base64_decode(&cur)
    {
        cur = t;
        count += n;
    }
    if lower.contains("b64decode")
        && let Some((t, n)) = decode_matches(py_base64().get(), &cur, |c| {
            utf8_text(&base64_bytes(c.name("b")?.as_str())?).map(|t| quote(&t))
        })
    {
        cur = t;
        count += n;
    }
    (count > 0).then_some((cur, count))
}

/// Replaces only the Base64 group of each shell match.
fn shell_base64_decode(s: &str) -> Option<(String, usize)> {
    let re = shell_base64().get()?;
    let mut out = String::with_capacity(s.len());
    let mut copied = 0usize;
    let mut count = 0usize;
    for c in re.captures_iter(s) {
        let Some(b) = c.name("b").or_else(|| c.name("b2")) else {
            continue;
        };
        let Some(text) = base64_bytes(b.as_str()).and_then(|x| utf8_text(&x)) else {
            continue;
        };
        out.push_str(&s[copied..b.start()]);
        out.push_str(&text);
        copied = b.end();
        count += 1;
    }
    if count == 0 {
        return None;
    }
    out.push_str(&s[copied..]);
    Some((out, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [
            url_escapes(),
            hex_escapes(),
            hex_token(),
            ps_base64(),
            shell_base64(),
            py_base64(),
        ] {
            assert!(re.compiled());
        }
    }

    #[test]
    fn random_data_is_not_decoded() {
        // A SHA-256 is not printable when decoded.
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex_decode(sha), None);
        assert_eq!(url_decode("a%20b"), None);
        assert_eq!(url_decode("%00%01%02"), None);
        assert_eq!(full_width("全形：（）"), None);
        assert_eq!(
            base64("echo aGVsbG8gd29ybGQgaGVsbG8= | base64 -d")
                .map(|x| x.0)
                .as_deref(),
            Some("echo hello world hello | base64 -d")
        );
    }
}
