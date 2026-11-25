//! Unix-socket IPC (macOS §4.9.1, Linux §4.9.2).

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use super::{ConnLimit, DesktopHandler, IPC_TIMEOUT, IpcError, from_io, serve_connection};

/// Socket file name inside the per-user directory.
pub const SOCKET_NAME: &str = "nmh.sock";

/// A socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint(pub PathBuf);

/// `~/Library/Application Support/PasteWarden/nmh.sock` (§4.9.1).
pub fn macos_socket_path(home: &Path) -> PathBuf {
    home.join("Library/Application Support/PasteWarden")
        .join(SOCKET_NAME)
}

/// `$XDG_RUNTIME_DIR/paste-warden/nmh.sock` (§4.9.2).
pub fn linux_socket_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("paste-warden").join(SOCKET_NAME)
}

/// Endpoint for this OS from the given environment values. Only absolute
/// paths count (an empty or relative `HOME` would put the socket in the cwd).
pub fn endpoint_from(
    home: Option<&OsStr>,
    xdg_runtime_dir: Option<&OsStr>,
) -> Result<Endpoint, IpcError> {
    fn abs(v: Option<&OsStr>) -> Option<&Path> {
        v.map(Path::new).filter(|p| p.is_absolute())
    }
    if cfg!(target_os = "macos") {
        abs(home).map(macos_socket_path)
    } else if cfg!(target_os = "linux") {
        abs(xdg_runtime_dir).map(linux_socket_path)
    } else {
        None
    }
    .map(Endpoint)
    .ok_or(IpcError::NoEndpoint)
}

pub fn default_endpoint() -> Result<Endpoint, IpcError> {
    endpoint_from(
        std::env::var_os("HOME").as_deref(),
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
    )
}

impl Endpoint {
    pub(super) fn connect(&self) -> Result<UnixStream, IpcError> {
        let s = UnixStream::connect(&self.0).map_err(from_io)?;
        if !same_user(&s) {
            return Err(IpcError::PeerMismatch);
        }
        s.set_read_timeout(Some(IPC_TIMEOUT))
            .map_err(IpcError::Io)?;
        s.set_write_timeout(Some(IPC_TIMEOUT))
            .map_err(IpcError::Io)?;
        Ok(s)
    }
}

/// Whether the peer runs as our (effective) user.
fn same_user(s: &UnixStream) -> bool {
    peer::peer_uid(s).is_some_and(|uid| uid == peer::our_uid())
}

#[cfg(target_os = "linux")]
mod peer {
    use std::os::unix::net::UnixStream;

    pub fn peer_uid(s: &UnixStream) -> Option<u32> {
        rustix::net::sockopt::socket_peercred(s)
            .ok()
            .map(|c| c.uid.as_raw())
    }

    pub fn our_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod peer {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    unsafe extern "C" {
        fn getpeereid(fd: i32, euid: *mut u32, egid: *mut u32) -> i32;
        fn geteuid() -> u32;
    }

    pub fn peer_uid(s: &UnixStream) -> Option<u32> {
        let (mut uid, mut gid) = (u32::MAX, u32::MAX);
        // SAFETY: the fd is a live socket owned by `s`; both out-pointers are
        // valid for writes of one `uid_t` / `gid_t` (u32 on macOS).
        let rc = unsafe { getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
        (rc == 0).then_some(uid)
    }

    pub fn our_uid() -> u32 {
        // SAFETY: no arguments, always succeeds.
        unsafe { geteuid() }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod peer {
    use std::os::unix::net::UnixStream;

    // No peer-credential check: refuse everyone.
    pub fn peer_uid(_: &UnixStream) -> Option<u32> {
        None
    }
    pub fn our_uid() -> u32 {
        u32::MAX
    }
}

/// A running IPC server. Dropping it stops the accept loop and removes the
/// socket file.
pub struct IpcServer {
    path: PathBuf,
    /// (dev, ino) of the socket we bound, so drop never removes another
    /// instance's socket.
    id: (u64, u64),
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcServer")
            .field("path", &self.path)
            .finish()
    }
}

/// Starts serving `endpoint`. Creates the parent directory (`0700`) if
/// missing, replaces a stale socket, refuses when another instance answers.
pub fn serve_at(
    endpoint: Endpoint,
    handler: Arc<dyn DesktopHandler>,
) -> Result<IpcServer, IpcError> {
    let path = endpoint.0;
    if let Some(dir) = path.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(IpcError::Io)?;
    }
    match fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_socket() => {
            if UnixStream::connect(&path).is_ok() {
                return Err(IpcError::AlreadyRunning);
            }
            fs::remove_file(&path).map_err(IpcError::Io)?;
        }
        // Never delete something that isn't a socket.
        Ok(_) => {
            return Err(IpcError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "IPC path exists and is not a socket",
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(IpcError::Io(e)),
    }
    let listener = UnixListener::bind(&path).map_err(IpcError::Io)?;
    // Peer credentials are checked per connection too, so the short window
    // before this chmod can't let another user in.
    fs::set_permissions(&path, Permissions::from_mode(0o600)).map_err(IpcError::Io)?;
    let meta = fs::symlink_metadata(&path).map_err(IpcError::Io)?;
    let id = (meta.dev(), meta.ino());

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let limit = ConnLimit::default();
    let thread = thread::Builder::new()
        .name("pw-nmh-ipc-accept".into())
        .spawn(move || {
            for conn in listener.incoming() {
                if stop2.load(Ordering::Acquire) {
                    break;
                }
                let Ok(mut conn) = conn else { continue };
                if !same_user(&conn) {
                    continue;
                }
                let Some(slot) = limit.try_acquire() else {
                    continue;
                };
                let handler = Arc::clone(&handler);
                let _ = thread::Builder::new()
                    .name("pw-nmh-ipc-conn".into())
                    .spawn(move || {
                        let _slot = slot;
                        if conn.set_read_timeout(Some(IPC_TIMEOUT)).is_ok()
                            && conn.set_write_timeout(Some(IPC_TIMEOUT)).is_ok()
                        {
                            serve_connection(&mut conn, &*handler);
                        }
                    });
            }
        })
        .map_err(IpcError::Io)?;
    Ok(IpcServer {
        path,
        id,
        stop,
        thread: Some(thread),
    })
}

impl IpcServer {
    pub fn endpoint(&self) -> Endpoint {
        Endpoint(self.path.clone())
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake the blocking accept.
        let _ = UnixStream::connect(&self.path);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Ok(m) = fs::symlink_metadata(&self.path)
            && (m.dev(), m.ino()) == self.id
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(
            macos_socket_path(Path::new("/Users/u")),
            Path::new("/Users/u/Library/Application Support/PasteWarden/nmh.sock")
        );
        assert_eq!(
            linux_socket_path(Path::new("/run/user/1000")),
            Path::new("/run/user/1000/paste-warden/nmh.sock")
        );
        let none = endpoint_from(Some(OsStr::new("relative")), Some(OsStr::new("")));
        assert!(matches!(none, Err(IpcError::NoEndpoint)));
        assert!(matches!(
            endpoint_from(None, None),
            Err(IpcError::NoEndpoint)
        ));
    }
}
