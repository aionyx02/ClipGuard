//! Process names for the clipboard owner and (C2) the foreground window.

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::clipboard::process_name_from_path;

/// Longest image path read (`QueryFullProcessImageNameW` buffer, UTF-16 units).
pub const MAX_IMAGE_PATH_UNITS: usize = 32_768;

/// Executable name without `.exe` of process `pid`, or `None` when access is
/// denied (S3: Windows Hello's dialog refuses even limited queries).
pub fn process_name(pid: u32) -> Option<String> {
    // SAFETY: limited query rights only; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = vec![0u16; MAX_IMAGE_PATH_UNITS];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` units; `len` receives the written length.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    }
    .is_ok();
    // SAFETY: `process` came from OpenProcess.
    let _ = unsafe { CloseHandle(process) };
    if !ok {
        return None;
    }
    let path = String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]);
    process_name_from_path(&path)
}
