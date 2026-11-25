//! Local IPC between `paste-warden-nmh` and the desktop app (phase-4.md
//! §4.3, §4.9.1, §4.9.2):
//!
//! | OS | Endpoint | Who may connect |
//! |---|---|---|
//! | macOS | `~/Library/Application Support/PasteWarden/nmh.sock` (`0600`) | `getpeereid` = our uid |
//! | Linux | `$XDG_RUNTIME_DIR/paste-warden/nmh.sock` (`0600`) | `SO_PEERCRED` = our uid |
//! | Windows | `\\.\pipe\paste-warden-<user SID>` | DACL: our SID only; the client checks the server's SID |
//!
//! One request per connection, framed like Native Messaging
//! ([`super::frame`]), the request in the extension's own JSON format so the
//! desktop re-validates it. Every query is bounded by [`IPC_TIMEOUT_MS`];
//! when the desktop app isn't there the client says so and **never starts
//! it**.

use std::fmt;
use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::frame::{FrameError, read_frame, write_frame};
use super::protocol::{Envelope, ErrorCode, Request, Response, encode_request, parse_request};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Endpoint, IpcServer, default_endpoint, serve_at};

#[cfg(windows)]
mod pipe;
#[cfg(windows)]
pub use pipe::{Endpoint, IpcServer, default_endpoint, serve_at};

/// How long one query may take end to end (phase-4.md §4.3).
pub const IPC_TIMEOUT_MS: u64 = 500;
/// Connections the desktop serves at once; more are closed right away.
pub const IPC_MAX_CONNECTIONS: usize = 8;

pub(crate) const IPC_TIMEOUT: Duration = Duration::from_millis(IPC_TIMEOUT_MS);

/// What the desktop app implements. Called on an IPC worker thread with a
/// request that already passed [`parse_request`]; a panic becomes
/// `Response::Error { err: Internal }`.
pub trait DesktopHandler: Send + Sync {
    fn handle(&self, req: Request) -> Response;
}

#[derive(Debug)]
pub enum IpcError {
    /// Nobody is listening: the desktop app isn't running.
    NotRunning,
    /// The desktop app didn't answer within [`IPC_TIMEOUT_MS`].
    Timeout,
    /// The other end runs as a different user.
    PeerMismatch,
    /// Another desktop instance already serves the endpoint.
    AlreadyRunning,
    /// The endpoint path can't be determined (`HOME` / `XDG_RUNTIME_DIR`
    /// unset) or this OS has no IPC.
    NoEndpoint,
    /// The other end sent something that isn't a valid reply.
    Protocol,
    Io(io::Error),
}

impl IpcError {
    /// Whether the extension should hear `desktop: "not_running"`.
    pub fn means_not_running(&self) -> bool {
        !matches!(self, Self::Protocol)
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => f.write_str("desktop app is not running"),
            Self::Timeout => f.write_str("desktop app did not answer in time"),
            Self::PeerMismatch => f.write_str("IPC peer runs as another user"),
            Self::AlreadyRunning => f.write_str("another instance serves the IPC endpoint"),
            Self::NoEndpoint => f.write_str("no IPC endpoint on this system"),
            Self::Protocol => f.write_str("invalid IPC reply"),
            Self::Io(e) => write!(f, "IPC i/o error: {e}"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<FrameError> for IpcError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Io(e) => from_io(e),
            FrameError::TooLarge(_) | FrameError::Truncated => Self::Protocol,
        }
    }
}

pub(crate) fn from_io(e: io::Error) -> IpcError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => IpcError::Timeout,
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => IpcError::NotRunning,
        _ => IpcError::Io(e),
    }
}

/// Starts serving on the default endpoint for this user. Dropping the
/// returned server stops it and removes the endpoint.
pub fn serve(handler: Arc<dyn DesktopHandler>) -> Result<IpcServer, IpcError> {
    serve_at(default_endpoint()?, handler)
}

/// The nmh side: one query per connection.
#[derive(Debug, Clone)]
pub struct IpcClient {
    endpoint: Endpoint,
}

impl IpcClient {
    /// Client for this user's default endpoint.
    pub fn new() -> Result<Self, IpcError> {
        Ok(Self::at(default_endpoint()?))
    }

    pub fn at(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Sends one request and waits at most [`IPC_TIMEOUT_MS`] for a reply
    /// that is valid for that op.
    pub fn query(&self, env: &Envelope) -> Result<Response, IpcError> {
        let endpoint = self.endpoint.clone();
        let payload = encode_request(env);
        let op = env.req.op();
        let (tx, rx) = mpsc::channel();
        // A thread so a stuck connect / read can't hold the extension past the
        // deadline. The socket timeouts end the thread soon after.
        thread::Builder::new()
            .name("pw-nmh-ipc".into())
            .spawn(move || {
                let r = (|| {
                    let mut conn = endpoint.connect()?;
                    write_frame(&mut conn, &payload)?;
                    let reply = read_frame(&mut conn)?.ok_or(IpcError::Protocol)?;
                    Response::parse_for(&reply, op).ok_or(IpcError::Protocol)
                })();
                let _ = tx.send(r);
            })
            .map_err(IpcError::Io)?;
        rx.recv_timeout(IPC_TIMEOUT)
            .unwrap_or(Err(IpcError::Timeout))
    }
}

/// Serves one connection: read one request, answer, done.
pub(crate) fn serve_connection<S: Read + Write>(conn: &mut S, handler: &dyn DesktopHandler) {
    let Ok(Some(bytes)) = read_frame(conn) else {
        return;
    };
    let resp = match parse_request(&bytes) {
        Ok(env) => {
            catch_unwind(AssertUnwindSafe(|| handler.handle(env.req))).unwrap_or(Response::Error {
                err: ErrorCode::Internal,
            })
        }
        Err(rej) => Response::Error { err: rej.code },
    };
    let _ = write_frame(conn, &resp.to_json());
}

/// Counts live connection threads, capped at [`IPC_MAX_CONNECTIONS`].
#[derive(Clone, Default)]
pub(crate) struct ConnLimit(Arc<AtomicUsize>);

pub(crate) struct ConnSlot(Arc<AtomicUsize>);

impl ConnLimit {
    pub(crate) fn try_acquire(&self) -> Option<ConnSlot> {
        let prev = self.0.fetch_add(1, Ordering::AcqRel);
        if prev >= IPC_MAX_CONNECTIONS {
            self.0.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(ConnSlot(Arc::clone(&self.0)))
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_limit() {
        let l = ConnLimit::default();
        let slots: Vec<_> = (0..IPC_MAX_CONNECTIONS)
            .map(|_| l.try_acquire().unwrap())
            .collect();
        assert!(l.try_acquire().is_none());
        drop(slots);
        assert!(l.try_acquire().is_some());
    }

    struct Panics;
    impl DesktopHandler for Panics {
        fn handle(&self, _: Request) -> Response {
            panic!("handler bug")
        }
    }

    #[test]
    fn serve_connection_answers_errors() {
        use super::super::frame::encode_frame;
        use std::io::Cursor;

        struct Duplex(Cursor<Vec<u8>>, Vec<u8>);
        impl Read for Duplex {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.0.read(b)
            }
        }
        impl Write for Duplex {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.1.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let reply = |req: &[u8]| {
            let mut d = Duplex(Cursor::new(encode_frame(req).unwrap()), Vec::new());
            serve_connection(&mut d, &Panics);
            let mut out = &d.1[..];
            serde_json::from_slice::<Response>(&read_frame(&mut out).unwrap().unwrap()).unwrap()
        };
        assert_eq!(
            reply(br#"{"v":1,"op":"nope"}"#),
            Response::Error {
                err: ErrorCode::UnknownOp
            }
        );
        assert_eq!(
            reply(b"{"),
            Response::Error {
                err: ErrorCode::BadRequest
            }
        );
        assert_eq!(
            reply(br#"{"v":1,"op":"policy.get"}"#),
            Response::Error {
                err: ErrorCode::Internal
            }
        );
    }
}
