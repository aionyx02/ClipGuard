//! Named-pipe IPC (phase-4.md §4.3 `IPC_PIPE_NAME`).
//!
//! - The pipe is `\\.\pipe\paste-warden-<user SID>`, created with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE` (so we never join a pipe someone else
//!   created first), `PIPE_REJECT_REMOTE_CLIENTS`, and a protected DACL that
//!   grants access to our SID only.
//! - The client opens it with `SECURITY_IDENTIFICATION` (the server can't
//!   impersonate us) and checks that the server process runs as our SID
//!   before sending anything.
//! - Server-side reads have no timeout (synchronous pipe I/O); only our own
//!   user can connect and at most `IPC_MAX_CONNECTIONS` threads exist.
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL,
    LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetLengthSid, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT, WaitNamedPipeW,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::{HSTRING, PWSTR};

use super::super::NMH_MAX_MESSAGE_BYTES;
use super::{ConnLimit, DesktopHandler, IPC_TIMEOUT_MS, IpcError, from_io, serve_connection};

/// Pipe name prefix; the user SID follows.
pub const PIPE_PREFIX: &str = r"\\.\pipe\paste-warden-";

/// A pipe name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint(pub String);

pub fn default_endpoint() -> Result<Endpoint, IpcError> {
    let sid = our_sid().ok_or(IpcError::NoEndpoint)?;
    let s = sid_string(&sid).ok_or(IpcError::NoEndpoint)?;
    Ok(Endpoint(format!("{PIPE_PREFIX}{s}")))
}

/// The user SID (raw bytes) of a process's token.
fn process_sid(process: HANDLE) -> Option<Vec<u8>> {
    let mut token = HANDLE::default();
    // SAFETY: `process` is a valid process handle; `token` receives a handle
    // we close below.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
    let mut len = 0u32;
    // SAFETY: size query with no buffer; `len` is a valid out-pointer.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` is 8-byte aligned and at least `len` bytes long.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    };
    let sid = ok.ok().and_then(|()| {
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID
        // points inside `buf`, which is still alive.
        unsafe {
            let user = &*(buf.as_ptr().cast::<TOKEN_USER>());
            let sid = user.User.Sid;
            let n = GetLengthSid(sid) as usize;
            (n > 0).then(|| std::slice::from_raw_parts(sid.0.cast::<u8>(), n).to_vec())
        }
    });
    // SAFETY: `token` was opened above.
    let _ = unsafe { CloseHandle(token) };
    sid
}

fn our_sid() -> Option<Vec<u8>> {
    // SAFETY: the pseudo-handle needs no closing.
    process_sid(unsafe { GetCurrentProcess() })
}

/// `S-1-5-21-…` for raw SID bytes.
fn sid_string(sid: &[u8]) -> Option<String> {
    let mut out = PWSTR::null();
    // SAFETY: `sid` holds a valid SID copied from a token; `out` receives a
    // LocalAlloc'd string freed below.
    unsafe { ConvertSidToStringSidW(PSID(sid.as_ptr() as *mut _), &mut out) }.ok()?;
    // SAFETY: on success `out` is a NUL-terminated wide string.
    let s = unsafe { out.to_string() }.ok();
    // SAFETY: allocated by ConvertSidToStringSidW.
    let _ = unsafe { LocalFree(Some(HLOCAL(out.0.cast()))) };
    s
}

/// The user SID of the process serving `pipe`.
fn server_sid(pipe: &File) -> Option<Vec<u8>> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is an open client end of a named pipe.
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }.ok()?;
    // SAFETY: plain query; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let sid = process_sid(process);
    // SAFETY: opened above.
    let _ = unsafe { CloseHandle(process) };
    sid
}

impl Endpoint {
    pub(super) fn connect(&self) -> Result<File, IpcError> {
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .security_qos_flags(SECURITY_IDENTIFICATION.0)
                .open(&self.0)
        };
        let file = match open() {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) => {
                // SAFETY: valid NUL-terminated name.
                let ready = unsafe {
                    WaitNamedPipeW(&HSTRING::from(self.0.as_str()), IPC_TIMEOUT_MS as u32)
                };
                if !ready.as_bool() {
                    return Err(IpcError::Timeout);
                }
                open().map_err(from_io)?
            }
            Err(e) => return Err(from_io(e)),
        };
        match (server_sid(&file), our_sid()) {
            (Some(a), Some(b)) if a == b => Ok(file),
            _ => Err(IpcError::PeerMismatch),
        }
    }
}

/// An owner-only DACL for our SID, as SDDL.
fn owner_only_sddl() -> Option<String> {
    Some(format!("D:P(A;;GA;;;{})", sid_string(&our_sid()?)?))
}

/// Creates one pipe instance.
fn create_instance(name: &HSTRING, sddl: &HSTRING, first: bool) -> Result<OwnedHandle, IpcError> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: valid SDDL string; `sd` receives a LocalAlloc'd descriptor
    // freed below (CreateNamedPipeW copies it).
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &mut sd, None)
    }
    .map_err(|e| IpcError::Io(io::Error::from_raw_os_error(e.code().0)))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let buf = (NMH_MAX_MESSAGE_BYTES + 4) as u32;
    // SAFETY: valid name and security attributes that outlive the call.
    let h = unsafe {
        CreateNamedPipeW(
            name,
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            buf,
            buf,
            0,
            Some(&raw const sa),
        )
    };
    let err = io::Error::last_os_error();
    // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    let _ = unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    if h.is_invalid() {
        if first && err.raw_os_error() == Some(ERROR_ACCESS_DENIED.0 as i32) {
            return Err(IpcError::AlreadyRunning);
        }
        return Err(IpcError::Io(err));
    }
    // SAFETY: `h` is a fresh, valid handle we now own.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0) })
}

/// A running pipe server. Dropping it stops accepting.
pub struct IpcServer {
    name: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcServer")
            .field("name", &self.name)
            .finish()
    }
}

pub fn serve_at(
    endpoint: Endpoint,
    handler: Arc<dyn DesktopHandler>,
) -> Result<IpcServer, IpcError> {
    let name = HSTRING::from(endpoint.0.as_str());
    let sddl = HSTRING::from(owner_only_sddl().ok_or(IpcError::NoEndpoint)?);
    let first = create_instance(&name, &sddl, true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    let limit = ConnLimit::default();
    let thread = thread::Builder::new()
        .name("pw-nmh-ipc-accept".into())
        .spawn(move || {
            let mut next = Some(first);
            while !stop2.load(Ordering::Acquire) {
                let pipe = match next.take() {
                    Some(p) => p,
                    None => match create_instance(&name, &sddl, false) {
                        Ok(p) => p,
                        Err(_) => {
                            thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                    },
                };
                let h = HANDLE(pipe.as_raw_handle());
                // SAFETY: `h` is a valid pipe instance; synchronous wait.
                let connected = match unsafe { ConnectNamedPipe(h, None) } {
                    Ok(()) => true,
                    Err(e) => e.code() == ERROR_PIPE_CONNECTED.to_hresult(),
                };
                if stop2.load(Ordering::Acquire) {
                    break;
                }
                if !connected {
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
                        let mut file = File::from(pipe);
                        serve_connection(&mut file, &*handler);
                        let h = HANDLE(file.as_raw_handle());
                        // SAFETY: `h` stays valid until `file` drops below.
                        unsafe {
                            let _ = FlushFileBuffers(h);
                            let _ = DisconnectNamedPipe(h);
                        }
                    });
            }
        })
        .map_err(IpcError::Io)?;
    Ok(IpcServer {
        name: endpoint.0,
        stop,
        thread: Some(thread),
    })
}

impl IpcServer {
    pub fn endpoint(&self) -> Endpoint {
        Endpoint(self.name.clone())
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let Some(t) = self.thread.take() else { return };
        // Wake the blocking ConnectNamedPipe; retry briefly in case the loop
        // is between instances.
        for _ in 0..50 {
            if t.is_finished() {
                break;
            }
            let _ = OpenOptions::new().read(true).write(true).open(&self.name);
            thread::sleep(Duration::from_millis(10));
        }
        if t.is_finished() {
            let _ = t.join();
        }
    }
}
