//! Raw Win32 clipboard access (S3 recommendations). Every function here runs
//! on the monitor thread and opens the clipboard with the monitor's own
//! message-only window — never `OpenClipboard(NULL)` (S3 finding 1).
//!
//! Nothing in this file formats clipboard content into errors or logs (P3).

use std::thread::sleep;
use std::time::Duration;

use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, EnumClipboardFormats, GetClipboardData, GetClipboardOwner,
    GetClipboardSequenceNumber, IsClipboardFormatAvailable, OpenClipboard,
    RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
use windows::core::{HSTRING, PCWSTR};
use zeroize::Zeroizing;

use super::process::process_name;
use crate::clipboard::{
    ClipEvent, ClipText, ClipboardFlags, EmptyReason, HTML_HEADER_SCAN_BYTES, accept_source_url,
    decode_format_text, decode_utf16_prefix, html_source_url,
};

/// `OpenClipboard` attempts while another program holds the clipboard (S3).
pub const OPEN_RETRY_COUNT: u32 = 20;
/// Delay between those attempts (S3).
pub const OPEN_RETRY_DELAY_MS: u64 = 5;
/// Password-manager marker: do not read the content at all (S3).
pub const FORMAT_EXCLUDE_MONITOR: &str = "ExcludeClipboardContentFromMonitorProcessing";
/// Value 0 = password-manager marker; we also write it on our own writes (§5.3).
pub const FORMAT_HISTORY_FLAG: &str = "CanIncludeInClipboardHistory";
/// Page URL that Chromium browsers attach to copies (S3 finding 2).
pub const FORMAT_CHROMIUM_SOURCE_URL: &str = "Chromium internal source URL";
/// CF_HTML; its header carries `SourceURL:` (S3 finding 2).
pub const FORMAT_HTML: &str = "HTML Format";
/// Text formats kept when restoring after a masked paste, besides
/// `CF_UNICODETEXT` (detection-rules.md §5.3).
pub const RESTORE_TEXT_FORMATS: [&str; 3] = ["Rich Text Format", FORMAT_HTML, "CSV"];

/// A clipboard operation failed. Carries no clipboard content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipError {
    /// Another program kept the clipboard open through every retry.
    Busy,
    /// A Win32 call failed (HRESULT).
    Win32(i32),
}

impl From<windows::core::Error> for ClipError {
    fn from(e: windows::core::Error) -> Self {
        ClipError::Win32(e.code().0)
    }
}

/// Registered format ids, looked up once per monitor.
#[derive(Debug, Clone, Copy)]
pub struct Formats {
    exclude_monitor: u32,
    history_flag: u32,
    chromium_source_url: u32,
    html: u32,
    restore: [u32; 3],
}

fn register(name: &str) -> u32 {
    // SAFETY: the HSTRING outlives the call; the function only reads it.
    unsafe { RegisterClipboardFormatW(PCWSTR(HSTRING::from(name).as_ptr())) }
}

impl Formats {
    pub fn register() -> Formats {
        Formats {
            exclude_monitor: register(FORMAT_EXCLUDE_MONITOR),
            history_flag: register(FORMAT_HISTORY_FLAG),
            chromium_source_url: register(FORMAT_CHROMIUM_SOURCE_URL),
            html: register(FORMAT_HTML),
            restore: RESTORE_TEXT_FORMATS.map(register),
        }
    }
}

/// Holds the clipboard open; `Drop` always closes it, also while unwinding.
struct Open;

impl Open {
    fn new(hwnd: HWND) -> Result<Open, ClipError> {
        for attempt in 0..OPEN_RETRY_COUNT {
            // SAFETY: plain Win32 call; `hwnd` is the monitor's own window.
            if unsafe { OpenClipboard(Some(hwnd)) }.is_ok() {
                return Ok(Open);
            }
            if attempt + 1 < OPEN_RETRY_COUNT {
                sleep(Duration::from_millis(OPEN_RETRY_DELAY_MS));
            }
        }
        Err(ClipError::Busy)
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: we opened the clipboard on this thread.
        let _ = unsafe { CloseClipboard() };
    }
}

/// Locks a clipboard memory handle for reading; unlocks on drop.
struct Locked {
    mem: HGLOBAL,
    ptr: *const u8,
    len: usize,
}

impl Locked {
    /// The data of `format`, if present. Must be called while the clipboard is open.
    fn get(format: u32) -> Option<Locked> {
        // SAFETY: the clipboard is open (caller holds `Open`).
        let handle = unsafe { GetClipboardData(format) }.ok()?;
        let mem = HGLOBAL(handle.0);
        // SAFETY: `mem` is a clipboard-owned global handle.
        let len = unsafe { GlobalSize(mem) };
        // SAFETY: as above; a null pointer means the lock failed.
        let ptr = unsafe { GlobalLock(mem) } as *const u8;
        (!ptr.is_null()).then_some(Locked { mem, ptr, len })
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `ptr` points at `len` locked bytes until `self` is dropped.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn units(&self) -> &[u16] {
        // SAFETY: CF_UNICODETEXT memory is UTF-16 and suitably aligned
        // (GlobalAlloc memory is 8-byte aligned); we read len/2 units.
        unsafe { std::slice::from_raw_parts(self.ptr.cast::<u16>(), self.len / 2) }
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: balanced with the GlobalLock in `get`.
        let _ = unsafe { GlobalUnlock(self.mem) };
    }
}

fn available(format: u32) -> bool {
    // SAFETY: plain Win32 call.
    unsafe { IsClipboardFormatAvailable(format) }.is_ok()
}

fn flags(f: &Formats) -> ClipboardFlags {
    let mut flags = ClipboardFlags {
        has_text: available(u32::from(CF_UNICODETEXT.0)),
        ..Default::default()
    };
    let mut format = 0;
    loop {
        // SAFETY: the clipboard is open; 0 starts / ends the enumeration.
        format = unsafe { EnumClipboardFormats(format) };
        if format == 0 {
            break;
        }
        if format == f.exclude_monitor {
            flags.exclude_monitor = true;
        } else if format == f.history_flag {
            flags.history_disabled = Locked::get(format)
                .map(|l| l.bytes().get(..4).is_some_and(|b| b == [0, 0, 0, 0]))
                .unwrap_or(false);
        }
    }
    flags
}

fn source_url(f: &Formats) -> Option<String> {
    if let Some(l) = Locked::get(f.chromium_source_url) {
        let bytes = l.bytes();
        let bytes = &bytes[..bytes
            .len()
            .min(crate::clipboard::SOURCE_URL_MAX_BYTES * 2 + 2)];
        if let Some(url) = decode_format_text(bytes)
            .as_deref()
            .and_then(accept_source_url)
        {
            return Some(url);
        }
    }
    let l = Locked::get(f.html)?;
    let bytes = l.bytes();
    html_source_url(&bytes[..bytes.len().min(HTML_HEADER_SCAN_BYTES)])
}

fn owner_pid() -> Option<u32> {
    // SAFETY: plain Win32 calls; a null owner is handled.
    let owner = unsafe { GetClipboardOwner() }.ok()?;
    if owner.is_invalid() {
        return None;
    }
    let mut pid = 0u32;
    // SAFETY: `pid` is a valid out pointer.
    unsafe { GetWindowThreadProcessId(owner, Some(&mut pid)) };
    (pid != 0).then_some(pid)
}

/// The current clipboard sequence number.
pub fn sequence() -> u32 {
    // SAFETY: plain Win32 call.
    unsafe { GetClipboardSequenceNumber() }
}

/// Reads one clipboard change: flags first, text only when allowed.
///
/// `ours(sequence)` says the clipboard holds our own write: its
/// history-flag marker is ours, so the password-manager check is skipped.
pub fn read_change(hwnd: HWND, f: &Formats, ours: impl FnOnce(u32) -> bool) -> ClipEvent {
    let seq = sequence();
    let Ok(open) = Open::new(hwnd) else {
        return ClipEvent::Empty {
            sequence: seq,
            reason: EmptyReason::Unreadable,
        };
    };
    let mut flags = flags(f);
    let self_write = ours(seq);
    if self_write {
        flags.exclude_monitor = false;
        flags.history_disabled = false;
    }
    if let Some(reason) = flags.empty_reason() {
        return ClipEvent::Empty {
            sequence: seq,
            reason,
        };
    }
    let Some((text, truncated)) =
        Locked::get(u32::from(CF_UNICODETEXT.0)).map(|l| decode_utf16_prefix(l.units()))
    else {
        return ClipEvent::Empty {
            sequence: seq,
            reason: EmptyReason::Unreadable,
        };
    };
    let url = source_url(f);
    let pid = owner_pid();
    drop(open);
    ClipEvent::Text(ClipText {
        sequence: seq,
        text,
        truncated,
        source_url: url,
        owner_process: pid.and_then(process_name),
        self_write,
    })
}

/// The complete clipboard text (only used when quarantining a cut text).
pub fn read_full(hwnd: HWND) -> Option<Zeroizing<String>> {
    let _open = Open::new(hwnd).ok()?;
    let l = Locked::get(u32::from(CF_UNICODETEXT.0))?;
    let units = l.units();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    Some(Zeroizing::new(String::from_utf16_lossy(&units[..end])))
}

/// Copies `bytes` into a movable global block and hands it to the clipboard.
/// Must be called while the clipboard is open and after `EmptyClipboard`.
fn set(format: u32, bytes: &[u8]) -> Result<(), ClipError> {
    // SAFETY: allocate, fill and hand over a global block; on any failure the
    // block is still ours and is freed here.
    unsafe {
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1))?;
        let ptr = GlobalLock(mem) as *mut u8;
        if ptr.is_null() {
            let _ = GlobalFree(Some(mem));
            return Err(ClipError::Win32(0));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        let _ = GlobalUnlock(mem);
        if let Err(e) = SetClipboardData(format, Some(HANDLE(mem.0))) {
            let _ = GlobalFree(Some(mem));
            return Err(e.into());
        }
    }
    Ok(())
}

fn empty() -> Result<(), ClipError> {
    // SAFETY: the clipboard is open; makes our window the owner.
    unsafe { EmptyClipboard() }?;
    Ok(())
}

/// Replaces the clipboard with plain text, marked as not for clipboard
/// history (§5.3). Returns the new sequence number.
pub fn write_text(hwnd: HWND, f: &Formats, text: &str) -> Result<u32, ClipError> {
    let mut units: Zeroizing<Vec<u16>> = Zeroizing::new(text.encode_utf16().chain([0]).collect());
    let bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(units.iter().flat_map(|u| u.to_ne_bytes()).collect());
    units.clear();
    {
        let _open = Open::new(hwnd)?;
        empty()?;
        set(u32::from(CF_UNICODETEXT.0), &bytes)?;
        set(f.history_flag, &0u32.to_ne_bytes())?;
    }
    Ok(sequence())
}

/// Clears the clipboard (quarantine). Returns the new sequence number.
pub fn clear(hwnd: HWND) -> Result<u32, ClipError> {
    {
        let _open = Open::new(hwnd)?;
        empty()?;
    }
    Ok(sequence())
}

/// Text formats saved before a masked paste, to put back afterwards.
pub struct Snapshot {
    items: Vec<(u32, Zeroizing<Vec<u8>>)>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("formats", &self.items.len())
            .finish()
    }
}

/// Saves `CF_UNICODETEXT` and [`RESTORE_TEXT_FORMATS`].
pub fn snapshot(hwnd: HWND, f: &Formats) -> Result<Snapshot, ClipError> {
    let _open = Open::new(hwnd)?;
    let items = std::iter::once(u32::from(CF_UNICODETEXT.0))
        .chain(f.restore)
        .filter_map(|format| {
            Locked::get(format).map(|l| (format, Zeroizing::new(l.bytes().to_vec())))
        })
        .collect();
    Ok(Snapshot { items })
}

/// Puts a [`Snapshot`] back, marked as not for clipboard history. Returns the
/// new sequence number.
pub fn restore(hwnd: HWND, f: &Formats, snap: &Snapshot) -> Result<u32, ClipError> {
    {
        let _open = Open::new(hwnd)?;
        empty()?;
        for (format, bytes) in &snap.items {
            set(*format, bytes)?;
        }
        set(f.history_flag, &0u32.to_ne_bytes())?;
    }
    Ok(sequence())
}
