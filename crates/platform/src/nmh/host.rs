//! The `paste-warden-nmh` loop: read framed requests from the browser on
//! stdin, validate, ask the desktop app over IPC, answer on stdout.
//!
//! The host itself holds no state and reads nothing from the system: every
//! answer comes from the desktop app or is a fixed error. Nothing from a
//! message is ever logged.

use std::ffi::OsString;
use std::io::{Read, Write};

use serde_json::{Map, Value, json};

use super::frame::{FrameError, read_frame, write_frame};
use super::ipc::{IpcClient, IpcError};
use super::protocol::{Envelope, ErrorCode, Op, Response, parse_request};
use super::{
    ALLOWED_CHROMIUM_EXTENSION_IDS, ALLOWED_GECKO_IDS, HOST_CAPS, NMH_MIN_EXT_PROTOCOL,
    NMH_PROTOCOL_VERSION,
};

/// Host binary version (sent in `hello`).
pub const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Who launched us, from argv (S9): Chromium passes
/// `chrome-extension://<id>/` (plus `--parent-window=<HWND>` on Windows),
/// Firefox passes the manifest path and then the add-on id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    Chromium(&'static str),
    Firefox(&'static str),
}

/// Checks argv against the allowed extension ids. Defense in depth only: the
/// browser already enforces `allowed_origins`, and argv can be forged by any
/// local program, which is why no op exposes anything secret.
pub fn check_caller(args: &[OsString]) -> Option<Caller> {
    let arg = |i: usize| args.get(i).and_then(|a| a.to_str());
    if let Some(origin) = arg(1)
        && let Some(id) = origin
            .strip_prefix("chrome-extension://")
            .and_then(|rest| rest.strip_suffix('/'))
    {
        // argv[2], if any, must be `--parent-window=…` (Windows) — ignored.
        if args.len() > 3 || arg(2).is_some_and(|a| !a.starts_with("--parent-window=")) {
            return None;
        }
        return ALLOWED_CHROMIUM_EXTENSION_IDS
            .iter()
            .find(|&&a| a == id)
            .map(|&a| Caller::Chromium(a));
    }
    if args.len() == 3
        && let Some(id) = arg(2)
    {
        return ALLOWED_GECKO_IDS
            .iter()
            .find(|&&a| a == id)
            .map(|&a| Caller::Firefox(a));
    }
    None
}

/// Where the host gets desktop answers from (the real [`IpcClient`], or a
/// fake in tests).
pub trait DesktopLink {
    fn query(&self, env: &Envelope) -> Result<Response, IpcError>;
}

impl DesktopLink for IpcClient {
    fn query(&self, env: &Envelope) -> Result<Response, IpcError> {
        IpcClient::query(self, env)
    }
}

/// No IPC endpoint on this system: the desktop never runs.
pub struct NoDesktop;

impl DesktopLink for NoDesktop {
    fn query(&self, _: &Envelope) -> Result<Response, IpcError> {
        Err(IpcError::NotRunning)
    }
}

/// How the loop ended.
#[derive(Debug)]
pub enum HostExit {
    /// The browser closed stdin.
    Eof,
    /// A length prefix over the limit: stop without reading on (S9).
    TooLarge,
    Truncated,
    Io(std::io::Error),
}

impl HostExit {
    /// Process exit code for the binary.
    pub fn code(&self) -> u8 {
        match self {
            Self::Eof => 0,
            Self::TooLarge => 4,
            Self::Truncated => 5,
            Self::Io(_) => 6,
        }
    }
}

/// Runs the host loop until EOF or a framing error.
pub fn run<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    desktop: &dyn DesktopLink,
) -> HostExit {
    loop {
        let bytes = match read_frame(input) {
            Ok(Some(b)) => b,
            Ok(None) => return HostExit::Eof,
            Err(FrameError::TooLarge(_)) => return HostExit::TooLarge,
            Err(FrameError::Truncated) => return HostExit::Truncated,
            Err(FrameError::Io(e)) => return HostExit::Io(e),
        };
        let reply = answer(&bytes, desktop);
        let payload = serde_json::to_vec(&reply).unwrap_or_default();
        if let Err(e) = write_frame(output, &payload) {
            return match e {
                FrameError::Io(e) => HostExit::Io(e),
                _ => HostExit::TooLarge,
            };
        }
    }
}

/// The reply to one request (pure apart from `desktop`).
pub fn answer(bytes: &[u8], desktop: &dyn DesktopLink) -> Value {
    let env = match parse_request(bytes) {
        Ok(env) => env,
        Err(rej) => return error_reply(rej.id, rej.code, None),
    };
    let op = env.req.op();
    let result = desktop.query(&env);
    let mut obj = base(env.id);
    match (op, result) {
        (Op::Hello, result) => {
            obj.insert("ok".into(), json!(true));
            obj.insert(
                "host".into(),
                json!({
                    "ver": HOST_VERSION,
                    "proto": NMH_PROTOCOL_VERSION,
                    "min_ext": NMH_MIN_EXT_PROTOCOL,
                    "caps": HOST_CAPS,
                }),
            );
            match result {
                Ok(Response::Hello { ver, caps }) => {
                    obj.insert("desktop".into(), json!("running"));
                    obj.insert("desktop_info".into(), json!({ "ver": ver, "caps": caps }));
                }
                // Running but refused / broken hello: report it as running
                // without capabilities.
                Ok(_) | Err(IpcError::Protocol) => {
                    obj.insert("desktop".into(), json!("running"));
                    obj.insert("desktop_info".into(), json!({ "ver": null, "caps": [] }));
                }
                Err(_) => {
                    obj.insert("desktop".into(), json!("not_running"));
                }
            }
            Value::Object(obj)
        }
        (_, Err(e)) => {
            if e.means_not_running() {
                error_reply(env.id, ErrorCode::NotRunning, Some("not_running"))
            } else {
                error_reply(env.id, ErrorCode::Internal, Some("running"))
            }
        }
        (_, Ok(Response::Error { err })) => error_reply(env.id, err, Some("running")),
        (_, Ok(resp)) => {
            obj.insert("ok".into(), json!(true));
            obj.insert("desktop".into(), json!("running"));
            match resp {
                Response::Policy { policy } => {
                    obj.insert("policy".into(), json!(policy));
                }
                Response::Match { matched, label_id } => {
                    obj.insert("matched".into(), json!(matched));
                    obj.insert("label_id".into(), json!(label_id));
                }
                _ => {}
            }
            Value::Object(obj)
        }
    }
}

fn base(id: Option<u64>) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("v".into(), json!(NMH_PROTOCOL_VERSION));
    obj.insert("id".into(), json!(id));
    obj
}

fn error_reply(id: Option<u64>, code: ErrorCode, desktop: Option<&str>) -> Value {
    let mut obj = base(id);
    obj.insert("ok".into(), json!(false));
    obj.insert("err".into(), json!(code.as_str()));
    if let Some(d) = desktop {
        obj.insert("desktop".into(), json!(d));
    }
    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::super::frame::encode_frame;
    use super::super::protocol::{Policy, Request};
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn caller() {
        let a = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        let chrome = format!("chrome-extension://{}/", ALLOWED_CHROMIUM_EXTENSION_IDS[0]);
        assert!(matches!(
            check_caller(&a(&["host", &chrome])),
            Some(Caller::Chromium(_))
        ));
        assert!(check_caller(&a(&["host", &chrome, "--parent-window=0"])).is_some());
        assert!(check_caller(&a(&["host", &chrome, "--other"])).is_none());
        assert!(
            check_caller(&a(&[
                "host",
                "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
            ]))
            .is_none()
        );
        assert!(check_caller(&a(&["host"])).is_none());
        let gecko = ALLOWED_GECKO_IDS[0];
        assert!(matches!(
            check_caller(&a(&["host", "/x/org.pastewarden.nmh.json", gecko])),
            Some(Caller::Firefox(_))
        ));
        assert!(check_caller(&a(&["host", "/x/m.json", "evil@example.invalid"])).is_none());
    }

    struct Fake(
        RefCell<Vec<Envelope>>,
        fn(&Envelope) -> Result<Response, IpcError>,
    );
    impl DesktopLink for Fake {
        fn query(&self, env: &Envelope) -> Result<Response, IpcError> {
            self.0.borrow_mut().push(env.clone());
            (self.1)(env)
        }
    }

    fn round(input: &[&str], desktop: &dyn DesktopLink) -> (Vec<Value>, HostExit) {
        let mut stdin = Vec::new();
        for m in input {
            stdin.extend(encode_frame(m.as_bytes()).unwrap());
        }
        let mut out = Vec::new();
        let exit = run(&mut &stdin[..], &mut out, desktop);
        let mut r = &out[..];
        let mut replies = Vec::new();
        while let Some(f) = read_frame(&mut r).unwrap() {
            replies.push(serde_json::from_slice(&f).unwrap());
        }
        (replies, exit)
    }

    #[test]
    fn desktop_not_running() {
        let (r, exit) = round(
            &[
                r#"{"v":1,"id":1,"op":"hello"}"#,
                r#"{"v":1,"id":2,"op":"policy.get"}"#,
                r#"{"v":1,"id":3,"op":"read_clipboard"}"#,
                "not json",
            ],
            &NoDesktop,
        );
        assert!(matches!(exit, HostExit::Eof));
        assert_eq!(r[0]["ok"], true);
        assert_eq!(r[0]["desktop"], "not_running");
        assert_eq!(r[0]["host"]["proto"], 1);
        assert_eq!(r[1]["err"], "not_running");
        assert_eq!(r[1]["desktop"], "not_running");
        assert_eq!(r[2]["err"], "unknown_op");
        assert_eq!(r[2]["id"], 3);
        assert_eq!(r[3]["err"], "bad_request");
        assert_eq!(r[3]["id"], Value::Null);
    }

    #[test]
    fn desktop_running() {
        let fake = Fake(RefCell::default(), |env| {
            Ok(match &env.req {
                Request::Hello(_) => Response::Hello {
                    ver: "0.1.0".into(),
                    caps: vec!["verdict".into()],
                },
                Request::PolicyGet => Response::Policy {
                    policy: Policy {
                        paste_guard_registered: true,
                        paste_guard_detected: false,
                    },
                },
                Request::Verdict(_) => Response::Logged,
                Request::MatchRegistered(_) => Response::Match {
                    matched: true,
                    label_id: Some("reg-3".into()),
                },
            })
        });
        let hmac = format!("{}=", "A".repeat(43));
        let (r, _) = round(
            &[
                r#"{"v":1,"id":1,"op":"hello","ext":{"ver":"0.1.0","caps":[]}}"#,
                r#"{"v":1,"id":2,"op":"policy.get"}"#,
                r#"{"v":1,"id":3,"op":"verdict","kind":"command-malicious","severity":"high","origin_host":"example.invalid","action":"blocked"}"#,
                &format!(r#"{{"v":1,"id":4,"op":"match_registered","hmac":"{hmac}"}}"#),
                r#"{"v":2,"id":5,"op":"hello"}"#,
            ],
            &fake,
        );
        assert_eq!(r[0]["desktop"], "running");
        assert_eq!(r[0]["desktop_info"]["ver"], "0.1.0");
        assert_eq!(r[1]["policy"]["paste_guard_registered"], true);
        assert_eq!(r[2]["ok"], true);
        assert_eq!(r[3]["matched"], true);
        assert_eq!(r[3]["label_id"], "reg-3");
        assert_eq!(r[4]["err"], "version");
        // Invalid requests never reach the desktop.
        assert_eq!(fake.0.borrow().len(), 4);
    }

    #[test]
    fn oversize_ends_the_loop() {
        let mut stdin = encode_frame(br#"{"v":1,"id":1,"op":"hello"}"#).unwrap();
        stdin.extend_from_slice(&u32::MAX.to_ne_bytes());
        stdin.extend_from_slice(&[0; 64]);
        let mut out = Vec::new();
        let exit = run(&mut &stdin[..], &mut out, &NoDesktop);
        assert!(matches!(exit, HostExit::TooLarge));
        assert_eq!(exit.code(), 4);
        assert!(!out.is_empty());
    }
}
