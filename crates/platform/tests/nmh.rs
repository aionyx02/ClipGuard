//! Native Messaging: IPC round trip (Unix here; the Windows pipe test is
//! `#[ignore]`d and run by hand), the host binary end to end, and a
//! never-panics property test over the public parsing entry points.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use paste_warden_platform::nmh::frame::{encode_frame, read_frame, split_frame};
use paste_warden_platform::nmh::host::answer;
use paste_warden_platform::nmh::protocol::{Response, parse_request};
use paste_warden_platform::nmh::{
    ALLOWED_CHROMIUM_EXTENSION_IDS, DesktopHandler, Envelope, ExtInfo, IpcClient, IpcError, Op,
    Policy, Request,
};
use proptest::prelude::*;

struct Desk(AtomicUsize);

impl DesktopHandler for Desk {
    fn handle(&self, req: Request) -> Response {
        self.0.fetch_add(1, Ordering::SeqCst);
        match req {
            Request::Hello(_) => Response::Hello {
                ver: "0.1.0".into(),
                caps: vec!["verdict".into()],
            },
            Request::PolicyGet => Response::Policy {
                policy: Policy {
                    paste_guard_registered: true,
                    paste_guard_detected: true,
                },
            },
            Request::Verdict(_) => Response::Logged,
            Request::MatchRegistered(_) => Response::Match {
                matched: false,
                label_id: None,
            },
        }
    }
}

fn hello() -> Envelope {
    Envelope {
        id: Some(1),
        req: Request::Hello(ExtInfo {
            ver: "0.1.0".into(),
            caps: vec![],
        }),
    }
}

#[cfg(unix)]
#[test]
fn unix_round_trip_and_stop() {
    use paste_warden_platform::nmh::ipc::{Endpoint, serve_at};
    use std::os::unix::fs::PermissionsExt;

    // Short path: macOS limits socket paths to 104 bytes.
    let dir = tempfile::Builder::new()
        .prefix("pw")
        .tempdir_in("/tmp")
        .unwrap();
    let path = dir.path().join("sub/nmh.sock");
    let desk = Arc::new(Desk(AtomicUsize::new(0)));
    let server = serve_at(Endpoint(path.clone()), desk.clone()).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let dir_mode = std::fs::metadata(path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o777, 0o700);

    // A second instance is refused.
    assert!(matches!(
        serve_at(Endpoint(path.clone()), desk.clone()),
        Err(IpcError::AlreadyRunning)
    ));

    let client = IpcClient::at(Endpoint(path.clone()));
    for _ in 0..3 {
        assert_eq!(
            client.query(&hello()).unwrap(),
            Response::Hello {
                ver: "0.1.0".into(),
                caps: vec!["verdict".into()]
            }
        );
    }
    let policy = Envelope {
        id: None,
        req: Request::PolicyGet,
    };
    assert!(matches!(
        client.query(&policy).unwrap(),
        Response::Policy { .. }
    ));
    assert_eq!(desk.0.load(Ordering::SeqCst), 4);

    // The host's answer with a live desktop.
    let reply = answer(br#"{"v":1,"id":9,"op":"hello"}"#, &client);
    assert_eq!(reply["desktop"], "running");
    assert_eq!(reply["id"], 9);

    // Raw garbage over the socket gets an error, not a crash.
    {
        use std::os::unix::net::UnixStream;
        let mut s = UnixStream::connect(&path).unwrap();
        s.write_all(&encode_frame(b"{nope").unwrap()).unwrap();
        let r = read_frame(&mut s).unwrap().unwrap();
        assert_eq!(
            Response::parse_for(&r, Op::Hello),
            Some(Response::Error {
                err: paste_warden_platform::nmh::ErrorCode::BadRequest
            })
        );
    }

    drop(server);
    assert!(!path.exists(), "socket removed on drop");
    assert!(matches!(client.query(&hello()), Err(IpcError::NotRunning)));
    let reply = answer(br#"{"v":1,"id":9,"op":"hello"}"#, &client);
    assert_eq!(reply["desktop"], "not_running");

    // A stale socket file (crashed app) is replaced.
    {
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(path.exists());
        let _server = serve_at(Endpoint(path.clone()), desk.clone()).unwrap();
        assert!(client.query(&hello()).is_ok());
    }
}

#[cfg(unix)]
#[test]
fn refuses_to_replace_a_regular_file() {
    use paste_warden_platform::nmh::ipc::{Endpoint, serve_at};
    let dir = tempfile::Builder::new()
        .prefix("pw")
        .tempdir_in("/tmp")
        .unwrap();
    let path = dir.path().join("nmh.sock");
    std::fs::write(&path, b"keep").unwrap();
    let desk = Arc::new(Desk(AtomicUsize::new(0)));
    assert!(serve_at(Endpoint(path.clone()), desk).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
}

#[cfg(windows)]
#[test]
#[ignore = "creates a named pipe; run by hand on Windows"]
fn windows_pipe_round_trip() {
    use paste_warden_platform::nmh::ipc::{Endpoint, serve_at};
    let name = format!(r"\\.\pipe\paste-warden-test-{}", std::process::id());
    let desk = Arc::new(Desk(AtomicUsize::new(0)));
    let server = serve_at(Endpoint(name.clone()), desk.clone()).unwrap();
    assert!(matches!(
        serve_at(Endpoint(name.clone()), desk.clone()),
        Err(IpcError::AlreadyRunning)
    ));
    let client = IpcClient::at(Endpoint(name.clone()));
    for _ in 0..3 {
        assert!(matches!(
            client.query(&hello()).unwrap(),
            Response::Hello { .. }
        ));
    }
    drop(server);
    assert!(matches!(client.query(&hello()), Err(IpcError::NotRunning)));
    // The default endpoint embeds the user SID.
    let ep = paste_warden_platform::nmh::ipc::default_endpoint().unwrap();
    assert!(ep.0.starts_with(r"\\.\pipe\paste-warden-S-1-"));
}

#[cfg(windows)]
#[test]
#[ignore = "writes HKCU; run by hand on Windows"]
fn windows_registry_install_round_trip() {
    use paste_warden_platform::nmh::install::{install, uninstall, windows_registry_keys};
    let host = std::env::current_exe().unwrap();
    let done = install(&host).unwrap();
    assert_eq!(done.len(), 4);
    uninstall().unwrap();
    // Uninstall twice is fine.
    uninstall().unwrap();
    assert_eq!(windows_registry_keys().len(), 4);
}

fn host_cmd() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_paste-warden-nmh"));
    // No desktop endpoint can exist under these.
    let none = std::env::temp_dir().join("pw-nmh-no-such-home");
    c.env("HOME", &none)
        .env("XDG_RUNTIME_DIR", &none)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

#[test]
fn host_binary_without_desktop() {
    let origin = format!("chrome-extension://{}/", ALLOWED_CHROMIUM_EXTENSION_IDS[0]);
    let mut child = host_cmd().arg(&origin).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&encode_frame(br#"{"v":1,"id":1,"op":"hello"}"#).unwrap())
        .unwrap();
    stdin
        .write_all(&encode_frame(br#"{"v":1,"id":2,"op":"read_clipboard"}"#).unwrap())
        .unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let mut r = &out.stdout[..];
    let a: serde_json::Value =
        serde_json::from_slice(&read_frame(&mut r).unwrap().unwrap()).unwrap();
    let b: serde_json::Value =
        serde_json::from_slice(&read_frame(&mut r).unwrap().unwrap()).unwrap();
    assert_eq!(a["desktop"], "not_running");
    assert_eq!(b["err"], "unknown_op");
    assert!(out.stderr.is_empty());
}

#[test]
fn host_binary_rejects_unknown_caller_and_oversize() {
    let out = host_cmd()
        .arg("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());

    let origin = format!("chrome-extension://{}/", ALLOWED_CHROMIUM_EXTENSION_IDS[0]);
    let mut child = host_cmd()
        .args([origin.as_str(), "--parent-window=0"])
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // 2 GiB prefix: the host must stop without trying to allocate it.
    let _ = stdin.write_all(&0x8000_0000u32.to_ne_bytes());
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(out.stdout.is_empty());
}

proptest! {
    #[test]
    fn parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = split_frame(&bytes);
        let _ = parse_request(&bytes);
        let _ = read_frame(&mut &bytes[..]);
        let _ = Response::parse_for(&bytes, Op::Hello);
        let _ = answer(&bytes, &paste_warden_platform::nmh::host::NoDesktop);
    }

    #[test]
    fn json_shaped_input_never_panics(
        op in "(hello|policy\\.get|verdict|match_registered|[a-z.]{0,8})",
        v in 0u64..3,
        field in "[ -~]{0,64}",
    ) {
        let s = format!(
            r#"{{"v":{v},"id":1,"op":"{op}","kind":"{field}","severity":"{field}","origin_host":"{field}","action":"{field}","hmac":"{field}","ext":{{"ver":"{field}","caps":["{field}"]}}}}"#
        );
        let _ = parse_request(s.as_bytes());
    }
}
