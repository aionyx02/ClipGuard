//! Native Messaging protocol v1 (phase-4.md §4.3, S9 "訊息格式").
//!
//! The extension sends `{"v":1,"id":7,"op":"hello",...}`; `paste-warden-nmh`
//! validates it into a typed [`Request`] and forwards the **same JSON** to the
//! desktop app, which parses it again with [`parse_request`] (it never trusts
//! the forwarder). The desktop answers with a [`Response`].
//!
//! Every op must assume the caller is an attacker (argv can be forged by any
//! local program, S9 §3), so no op reads the clipboard or secrets, and no
//! message carries clipboard / input text, unmasked secrets, full URLs (host
//! only) or the HMAC key (T16). Every string is length- and charset-checked
//! here; nothing panics on any input.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::NMH_PROTOCOL_VERSION;

/// Ops the host understands (phase-4.md §4.3 `NMH_OPS`).
pub const NMH_OPS: [&str; 4] = ["hello", "policy.get", "verdict", "match_registered"];

/// Longest version string (`ext.ver`, desktop `ver`).
pub const VERSION_MAX_LEN: usize = 32;
/// Most capabilities in one `caps` list.
pub const CAPS_MAX: usize = 16;
/// Longest capability name.
pub const CAP_MAX_LEN: usize = 32;
/// Longest rule id in a `verdict` (`gitleaks.…` ids are well under this).
pub const RULE_ID_MAX_LEN: usize = 96;
/// Longest `origin_host` (DNS limit).
pub const HOST_MAX_LEN: usize = 253;
/// Longest `label_id` of a registered secret.
pub const LABEL_ID_MAX_LEN: usize = 64;
/// Largest request id (JS `Number.MAX_SAFE_INTEGER`).
pub const ID_MAX: u64 = (1 << 53) - 1;
/// HMAC-SHA256 output length.
pub const HMAC_LEN: usize = 32;

/// One of [`NMH_OPS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Hello,
    PolicyGet,
    Verdict,
    MatchRegistered,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::PolicyGet => "policy.get",
            Self::Verdict => "verdict",
            Self::MatchRegistered => "match_registered",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "hello" => Self::Hello,
            "policy.get" => Self::PolicyGet,
            "verdict" => Self::Verdict,
            "match_registered" => Self::MatchRegistered,
            _ => return None,
        })
    }
}

/// `hello` payload: what the extension is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtInfo {
    pub ver: String,
    pub caps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            _ => return None,
        })
    }
}

/// What the extension did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictAction {
    /// A clipboard write was replaced (quarantine).
    Blocked,
    /// A warning was shown.
    Warned,
    /// The user was asked before pasting a secret.
    Confirm,
}

impl VerdictAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Warned => "warned",
            Self::Confirm => "confirm",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "blocked" => Self::Blocked,
            "warned" => Self::Warned,
            "confirm" => Self::Confirm,
            _ => return None,
        })
    }
}

/// `verdict`: something the extension already showed in the page. The
/// desktop only logs it, never notifies (phase-4.md §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// Rule id (`gitleaks.aws-access-token`, a command reason id, …).
    pub kind: String,
    pub severity: Severity,
    /// Hostname only, never a URL. May be empty (`file:` pages).
    pub origin_host: String,
    pub action: VerdictAction,
}

/// HMAC-SHA256 of a candidate, computed by the extension. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct RegisteredHmac(pub [u8; HMAC_LEN]);

impl fmt::Debug for RegisteredHmac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisteredHmac(..)")
    }
}

/// A validated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Hello(ExtInfo),
    PolicyGet,
    Verdict(Verdict),
    MatchRegistered(RegisteredHmac),
}

impl Request {
    pub fn op(&self) -> Op {
        match self {
            Self::Hello(_) => Op::Hello,
            Self::PolicyGet => Op::PolicyGet,
            Self::Verdict(_) => Op::Verdict,
            Self::MatchRegistered(_) => Op::MatchRegistered,
        }
    }
}

/// A request plus the caller's correlation id (echoed back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub id: Option<u64>,
    pub req: Request,
}

/// Error codes on the wire (`"err"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Not one of [`NMH_OPS`]. The connection stays open.
    UnknownOp,
    /// Not JSON, not an object, or a field failed validation.
    BadRequest,
    /// `v` is not [`NMH_PROTOCOL_VERSION`]: the extension works alone.
    Version,
    /// The desktop app isn't running (or didn't answer in time).
    NotRunning,
    /// The desktop app failed to handle the request.
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownOp => "unknown_op",
            Self::BadRequest => "bad_request",
            Self::Version => "version",
            Self::NotRunning => "not_running",
            Self::Internal => "internal",
        }
    }
}

/// Why a request was rejected: the code plus the id, if one could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected {
    pub id: Option<u64>,
    pub code: ErrorCode,
}

/// Desktop policy the extension may adopt (`policy.get`). Flags only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Policy {
    /// The desktop paste guard confirms registered secrets.
    pub paste_guard_registered: bool,
    /// The desktop paste guard confirms detected secrets.
    pub paste_guard_detected: bool,
}

/// The desktop app's answer to one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "r", rename_all = "snake_case")]
pub enum Response {
    Hello {
        /// Desktop app version.
        ver: String,
        caps: Vec<String>,
    },
    Policy {
        policy: Policy,
    },
    /// `verdict` was logged.
    Logged,
    Match {
        matched: bool,
        /// Opaque id of the registered secret (`reg-3`), never its label text.
        label_id: Option<String>,
    },
    Error {
        err: ErrorCode,
    },
}

impl Response {
    /// Whether this response is a valid answer to `op` and every string is
    /// within bounds. The nmh host checks this before relaying anything the
    /// desktop sent.
    pub fn is_valid_for(&self, op: Op) -> bool {
        match (self, op) {
            (Self::Hello { ver, caps }, Op::Hello) => valid_version(ver) && valid_caps(caps),
            (Self::Policy { .. }, Op::PolicyGet) | (Self::Logged, Op::Verdict) => true,
            (Self::Match { matched, label_id }, Op::MatchRegistered) => match label_id {
                None => true,
                Some(l) => *matched && valid_token(l, LABEL_ID_MAX_LEN),
            },
            (Self::Error { .. }, _) => true,
            _ => false,
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        // Serializing these plain types can't fail.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Parses and validates a desktop reply to `op`.
    pub fn parse_for(bytes: &[u8], op: Op) -> Option<Self> {
        let r: Self = serde_json::from_slice(bytes).ok()?;
        r.is_valid_for(op).then_some(r)
    }
}

fn valid_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_version(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= VERSION_MAX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
}

fn valid_caps(caps: &[String]) -> bool {
    caps.len() <= CAPS_MAX && caps.iter().all(|c| valid_token(c, CAP_MAX_LEN))
}

/// Hostname or IP literal; never anything with `/`, `@`, `?`, `#` or spaces.
fn valid_host(s: &str) -> bool {
    s.len() <= HOST_MAX_LEN
        && s.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
        })
}

/// Parses and validates one request. Never panics.
pub fn parse_request(bytes: &[u8]) -> Result<Envelope, Rejected> {
    let bad = |id| Rejected {
        id,
        code: ErrorCode::BadRequest,
    };
    let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(bytes) else {
        return Err(bad(None));
    };
    let id = match obj.get("id") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64().filter(|&n| n <= ID_MAX) {
            Some(n) => Some(n),
            None => return Err(bad(None)),
        },
    };
    if obj.get("v").and_then(Value::as_u64) != Some(u64::from(NMH_PROTOCOL_VERSION)) {
        return Err(Rejected {
            id,
            code: ErrorCode::Version,
        });
    }
    let Some(op) = obj.get("op").and_then(Value::as_str) else {
        return Err(bad(id));
    };
    let Some(op) = Op::parse(op) else {
        return Err(Rejected {
            id,
            code: ErrorCode::UnknownOp,
        });
    };
    let req = match op {
        Op::Hello => parse_hello(&obj),
        Op::PolicyGet => Some(Request::PolicyGet),
        Op::Verdict => parse_verdict(&obj),
        Op::MatchRegistered => obj
            .get("hmac")
            .and_then(Value::as_str)
            .and_then(decode_hmac)
            .map(|h| Request::MatchRegistered(RegisteredHmac(h))),
    };
    req.map(|req| Envelope { id, req }).ok_or(bad(id))
}

fn parse_hello(obj: &Map<String, Value>) -> Option<Request> {
    let ext = match obj.get("ext") {
        None => ExtInfo::default(),
        Some(Value::Object(ext)) => {
            let ver = match ext.get("ver") {
                None => String::new(),
                Some(v) => {
                    let s = v.as_str()?;
                    valid_version(s).then(|| s.to_owned())?
                }
            };
            let caps = match ext.get("caps") {
                None => Vec::new(),
                Some(v) => {
                    let arr = v.as_array().filter(|a| a.len() <= CAPS_MAX)?;
                    let caps: Option<Vec<String>> = arr
                        .iter()
                        .map(|c| {
                            c.as_str()
                                .filter(|c| valid_token(c, CAP_MAX_LEN))
                                .map(str::to_owned)
                        })
                        .collect();
                    caps?
                }
            };
            ExtInfo { ver, caps }
        }
        Some(_) => return None,
    };
    Some(Request::Hello(ext))
}

fn parse_verdict(obj: &Map<String, Value>) -> Option<Request> {
    let field = |k: &str| obj.get(k).and_then(Value::as_str);
    let kind = field("kind").filter(|k| valid_token(k, RULE_ID_MAX_LEN))?;
    let severity = field("severity").and_then(Severity::parse)?;
    let origin_host = field("origin_host").filter(|h| valid_host(h))?;
    let action = field("action").and_then(VerdictAction::parse)?;
    Some(Request::Verdict(Verdict {
        kind: kind.to_owned(),
        severity,
        origin_host: origin_host.to_owned(),
        action,
    }))
}

/// Serializes a request in the wire format [`parse_request`] reads.
pub fn encode_request(env: &Envelope) -> Vec<u8> {
    let mut obj = Map::new();
    obj.insert("v".into(), json!(NMH_PROTOCOL_VERSION));
    if let Some(id) = env.id {
        obj.insert("id".into(), json!(id));
    }
    obj.insert("op".into(), json!(env.req.op().as_str()));
    match &env.req {
        Request::Hello(ext) => {
            obj.insert("ext".into(), json!({ "ver": ext.ver, "caps": ext.caps }));
        }
        Request::PolicyGet => {}
        Request::Verdict(v) => {
            obj.insert("kind".into(), json!(v.kind));
            obj.insert("severity".into(), json!(v.severity.as_str()));
            obj.insert("origin_host".into(), json!(v.origin_host));
            obj.insert("action".into(), json!(v.action.as_str()));
        }
        Request::MatchRegistered(h) => {
            obj.insert("hmac".into(), json!(encode_hmac(&h.0)));
        }
    }
    serde_json::to_vec(&Value::Object(obj)).unwrap_or_default()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

/// Standard padded base64 of exactly 32 bytes (44 chars, canonical).
pub fn decode_hmac(s: &str) -> Option<[u8; HMAC_LEN]> {
    let b = s.as_bytes();
    if b.len() != 44 || b[43] != b'=' {
        return None;
    }
    let mut out = [0u8; HMAC_LEN];
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut n = 0;
    for &c in &b[..43] {
        acc = (acc << 6) | u32::from(b64_value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n)? = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    // 43 * 6 = 258 bits = 32 bytes + 2 leftover bits that must be zero.
    (n == HMAC_LEN && acc == 0).then_some(out)
}

pub fn encode_hmac(h: &[u8; HMAC_LEN]) -> String {
    let mut out = String::with_capacity(44);
    for chunk in h.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Envelope, Rejected> {
        parse_request(s.as_bytes())
    }

    #[test]
    fn hello() {
        let e = parse(r#"{"v":1,"id":7,"op":"hello","ext":{"ver":"0.1.0","caps":["verdict"]}}"#)
            .unwrap();
        assert_eq!(e.id, Some(7));
        assert_eq!(
            e.req,
            Request::Hello(ExtInfo {
                ver: "0.1.0".into(),
                caps: vec!["verdict".into()]
            })
        );
        assert_eq!(parse_request(&encode_request(&e)).unwrap(), e);
        // `ext` is optional.
        assert!(parse(r#"{"v":1,"op":"hello"}"#).is_ok());
    }

    #[test]
    fn unknown_op_keeps_the_id() {
        for op in [
            r#""read_clipboard""#,
            r#""get_secret""#,
            r#""HELLO""#,
            r#""""#,
        ] {
            let r = parse(&format!(r#"{{"v":1,"id":3,"op":{op}}}"#)).unwrap_err();
            assert_eq!(
                r,
                Rejected {
                    id: Some(3),
                    code: ErrorCode::UnknownOp
                }
            );
        }
    }

    #[test]
    fn malformed() {
        for s in [
            "",
            "null",
            "[]",
            "{",
            "\"hello\"",
            r#"{"v":1}"#,
            r#"{"v":1,"op":7}"#,
            r#"{"v":1,"id":-1,"op":"hello"}"#,
            r#"{"v":1,"id":1.5,"op":"hello"}"#,
            r#"{"v":1,"id":9007199254740992,"op":"hello"}"#,
            r#"{"v":1,"op":"hello","ext":[]}"#,
            r#"{"v":1,"op":"hello","ext":{"ver":"1 2"}}"#,
            r#"{"v":1,"op":"hello","ext":{"caps":["a b"]}}"#,
            r#"{"v":1,"op":"match_registered","hmac":"short"}"#,
        ] {
            let r = parse(s).unwrap_err();
            assert_eq!(r.code, ErrorCode::BadRequest, "{s}");
        }
        assert!(parse_request(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn version() {
        for v in ["0", "2", "\"1\"", "null"] {
            let r = parse(&format!(r#"{{"v":{v},"id":1,"op":"hello"}}"#)).unwrap_err();
            assert_eq!(r.code, ErrorCode::Version);
            assert_eq!(r.id, Some(1));
        }
        assert_eq!(
            parse(r#"{"op":"hello"}"#).unwrap_err().code,
            ErrorCode::Version
        );
    }

    #[test]
    fn verdict_rejects_urls_and_text() {
        let ok = r#"{"v":1,"op":"verdict","kind":"gitleaks.aws-access-token","severity":"high","origin_host":"example.invalid","action":"confirm"}"#;
        let e = parse(ok).unwrap();
        assert_eq!(parse_request(&encode_request(&e)).unwrap(), e);
        for host in [
            "https://example.invalid/",
            "example.invalid/path",
            "user@example.invalid",
            "Example.invalid",
            "a b",
        ] {
            let s = ok.replace("example.invalid", host);
            assert_eq!(parse(&s).unwrap_err().code, ErrorCode::BadRequest, "{host}");
        }
        let long = "a".repeat(HOST_MAX_LEN + 1);
        assert!(parse(&ok.replace("example.invalid", &long)).is_err());
        // A rule id can't smuggle text.
        let s = ok.replace("gitleaks.aws-access-token", "rm -rf ~");
        assert!(parse(&s).is_err());
        let s = ok.replace("\"high\"", "\"critical\"");
        assert!(parse(&s).is_err());
        // Empty host is allowed (file: pages).
        assert!(parse(&ok.replace("example.invalid", "")).is_ok());
        assert!(parse(&ok.replace("example.invalid", "[::1]")).is_ok());
    }

    #[test]
    fn hmac_base64() {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (i * 37 + 11) as u8;
        }
        let s = encode_hmac(&h);
        assert_eq!(s.len(), 44);
        assert_eq!(decode_hmac(&s), Some(h));
        assert_eq!(encode_hmac(&[0; 32]), format!("{}=", "A".repeat(43)));
        assert_eq!(encode_hmac(&[0xff; 32]), format!("{}8=", "/".repeat(42)));
        // Non-canonical trailing bits.
        assert_eq!(decode_hmac(&format!("{}B=", "A".repeat(42))), None);
        assert_eq!(decode_hmac(&format!("{}==", "A".repeat(42))), None);
        assert_eq!(decode_hmac(&format!("{}=", "-".repeat(43))), None);
        let e = parse(&format!(
            r#"{{"v":1,"op":"match_registered","hmac":"{s}"}}"#
        ))
        .unwrap();
        assert_eq!(e.req, Request::MatchRegistered(RegisteredHmac(h)));
        assert!(!format!("{e:?}").contains(&s));
    }

    #[test]
    fn response_validation() {
        let ok = Response::Hello {
            ver: "0.1.0".into(),
            caps: vec!["verdict".into()],
        };
        assert_eq!(
            Response::parse_for(&ok.to_json(), Op::Hello),
            Some(ok.clone())
        );
        assert_eq!(Response::parse_for(&ok.to_json(), Op::Verdict), None);
        let bad = Response::Hello {
            ver: "x".repeat(VERSION_MAX_LEN + 1),
            caps: vec![],
        };
        assert!(!bad.is_valid_for(Op::Hello));
        let m = Response::Match {
            matched: false,
            label_id: Some("reg-1".into()),
        };
        assert!(!m.is_valid_for(Op::MatchRegistered));
        let e = Response::Error {
            err: ErrorCode::Internal,
        };
        assert!(e.is_valid_for(Op::PolicyGet));
        assert_eq!(Response::parse_for(b"garbage", Op::Hello), None);
    }
}
