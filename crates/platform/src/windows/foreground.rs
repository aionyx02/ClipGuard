//! Foreground window tracking on the `pw-clip` thread (docs/plan/phase-4.md
//! §4.2, §4.3, §4.8.2; S3 finding 6).
//!
//! `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` runs out of context, so its
//! callback is delivered by the message loop of the thread that installed it
//! (`pw-clip`). Each change is turned into a [`ForegroundInfo`]: class, title
//! (at most [`WINDOW_TITLE_MAX_CHARS`]), process (UWP apps resolved through
//! their frame host), root owner and whether the process runs at a higher
//! integrity level than we do. A failed integrity query counts as elevated.
//!
//! Privacy (P3): titles never reach logs or errors; [`ForegroundInfo`]'s
//! `Debug` hides them.

use std::cell::RefCell;
use std::sync::OnceLock;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent};
use windows::Win32::UI::WindowsAndMessaging::{
    EVENT_SYSTEM_FOREGROUND, EnumChildWindows, GA_ROOTOWNER, GetAncestor, GetClassNameW,
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, WINEVENT_OUTOFCONTEXT,
    WINEVENT_SKIPOWNPROCESS,
};
use windows::core::BOOL;

use super::process::process_name;
use crate::host::{ForegroundInfo, WINDOW_TITLE_MAX_CHARS, WindowId};
use crate::probe::elevated;

/// Out of context (no DLL injection), and never about our own windows (S3).
pub const WINEVENT_FLAGS: u32 = WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS;
/// Window class names are at most 256 chars (`WNDCLASSEX` limit).
pub const MAX_CLASS_NAME_UNITS: usize = 256;
/// `OBJID_WINDOW`: the event is about the window itself, not a child object.
const OBJID_WINDOW: i32 = 0;

/// Receives every foreground change on `pw-clip` (keep it short).
pub type ForegroundSink = Box<dyn FnMut(ForegroundInfo) + Send>;

/// `rules/policy/windows.json` → `foreground` (S3 finding 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UwpRules {
    /// Process that owns UWP frames (`ApplicationFrameHost`).
    pub host_process: String,
    /// Class of the frame window (`ApplicationFrameWindow`).
    pub frame_class: String,
}

const WINDOWS_JSON: &str = include_str!("../../../../rules/policy/windows.json");

/// The string value of the first `"key": "value"` in `json`. Enough for our
/// own flat, unescaped policy entries; core's `WindowsRules` has no
/// `foreground` section yet (reported in the Phase 4 notes).
fn json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let quoted = format!("\"{key}\"");
    let rest = &json[json.find(&quoted)? + quoted.len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// The embedded UWP data; empty strings (nothing matches) if missing.
pub fn uwp_rules() -> &'static UwpRules {
    static RULES: OnceLock<UwpRules> = OnceLock::new();
    RULES.get_or_init(|| UwpRules {
        host_process: json_str(WINDOWS_JSON, "uwp_host_process")
            .unwrap_or_default()
            .to_owned(),
        frame_class: json_str(WINDOWS_JSON, "uwp_frame_class")
            .unwrap_or_default()
            .to_owned(),
    })
}

fn hwnd_id(h: HWND) -> WindowId {
    h.0 as WindowId
}

fn class_name(hwnd: HWND) -> Option<String> {
    let mut buf = [0u16; MAX_CLASS_NAME_UNITS + 1];
    // SAFETY: `buf` is writable for its whole length.
    let n = unsafe { GetClassNameW(hwnd, &mut buf) };
    let n = usize::try_from(n).ok().filter(|&n| n > 0)?;
    Some(String::from_utf16_lossy(&buf[..n.min(buf.len())]))
}

/// The first `max_chars` chars of `units`, without a split surrogate pair.
pub(crate) fn cap_title(units: &[u16], max_chars: usize) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .take(max_chars)
        .collect()
}

fn title(hwnd: HWND) -> Option<String> {
    // Every char needs at most 2 units; +1 for the terminator.
    let mut buf = [0u16; WINDOW_TITLE_MAX_CHARS * 2 + 1];
    // SAFETY: `buf` is writable for its whole length; GetWindowTextW never
    // writes more and always terminates.
    let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
    let n = usize::try_from(n).ok().filter(|&n| n > 0)?;
    Some(cap_title(&buf[..n.min(buf.len())], WINDOW_TITLE_MAX_CHARS))
}

fn window_pid(hwnd: HWND) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: `pid` is a valid out pointer.
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    (pid != 0).then_some(pid)
}

struct ChildSearch {
    host_pid: u32,
    found: Option<u32>,
}

unsafe extern "system" fn find_app_child(child: HWND, lp: LPARAM) -> BOOL {
    // SAFETY: `lp` is the `ChildSearch` that `uwp_app_pid` keeps alive for
    // the whole EnumChildWindows call.
    let search = unsafe { &mut *(lp.0 as *mut ChildSearch) };
    match window_pid(child) {
        Some(pid) if pid != search.host_pid => {
            search.found = Some(pid);
            BOOL(0)
        }
        _ => BOOL(1),
    }
}

/// The app process behind a UWP frame: a child window whose process is not
/// the frame host (S3 finding 6). `None` while the app is still starting.
fn uwp_app_pid(frame: HWND, host_pid: u32) -> Option<u32> {
    let mut search = ChildSearch {
        host_pid,
        found: None,
    };
    // SAFETY: the callback only touches `search`, which outlives the call;
    // the return value only says whether enumeration was stopped early.
    let _ = unsafe {
        EnumChildWindows(
            Some(frame),
            Some(find_app_child),
            LPARAM(&mut search as *mut ChildSearch as isize),
        )
    };
    search.found
}

/// `TokenIntegrityLevel`'s RID (e.g. 0x2000 medium, 0x3000 high) of the
/// process behind `process`, or `None` when any query fails.
fn token_integrity(process: HANDLE) -> Option<u32> {
    let mut token = HANDLE::default();
    // SAFETY: query-only token handle, closed below.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
    // TOKEN_MANDATORY_LABEL plus one SID (≤ 68 bytes); u64 keeps alignment.
    let mut buf = [0u64; 16];
    let mut len = 0u32;
    // SAFETY: `buf` is writable for `size_of_val(&buf)` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr().cast()),
            size_of_val(&buf) as u32,
            &mut len,
        )
    }
    .is_ok();
    // SAFETY: `token` came from OpenProcessToken.
    let _ = unsafe { CloseHandle(token) };
    if !ok {
        return None;
    }
    // SAFETY: on success `buf` starts with a TOKEN_MANDATORY_LABEL whose SID
    // points into `buf`; the SID's last sub-authority is the level.
    unsafe {
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        if sid.is_invalid() {
            return None;
        }
        let count = *GetSidSubAuthorityCount(sid);
        let last = u32::from(count.checked_sub(1)?);
        Some(*GetSidSubAuthority(sid, last))
    }
}

/// Integrity level of process `pid`.
pub fn integrity_level(pid: u32) -> Option<u32> {
    // SAFETY: limited query rights (enough for elevated processes, S3);
    // the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let level = token_integrity(process);
    // SAFETY: `process` came from OpenProcess.
    let _ = unsafe { CloseHandle(process) };
    level
}

/// Our own integrity level, queried once.
pub fn own_integrity_level() -> Option<u32> {
    static OWN: OnceLock<Option<u32>> = OnceLock::new();
    // SAFETY: the pseudo handle of the current process needs no closing.
    *OWN.get_or_init(|| token_integrity(unsafe { GetCurrentProcess() }))
}

/// Everything §4.4 / §4.8.2 needs about `hwnd`.
pub fn describe(hwnd: HWND) -> ForegroundInfo {
    let class = class_name(hwnd);
    let pid = window_pid(hwnd);
    let mut process = pid.and_then(process_name);
    let mut app_pid = pid;
    let rules = uwp_rules();
    let is_frame = !rules.frame_class.is_empty()
        && class.as_deref() == Some(rules.frame_class.as_str())
        && process
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(&rules.host_process));
    if is_frame && let Some(host) = pid {
        // Unknown until the app's child window exists; the next foreground
        // event resolves it (S3 finding 6).
        app_pid = uwp_app_pid(hwnd, host);
        process = app_pid.and_then(process_name);
        if app_pid.is_none() {
            app_pid = pid;
        }
    }
    // SAFETY: plain Win32 getter; a failed call yields a null window.
    let root = unsafe { GetAncestor(hwnd, GA_ROOTOWNER) };
    let root = if root.is_invalid() { hwnd } else { root };
    ForegroundInfo {
        window: hwnd_id(hwnd),
        root: hwnd_id(root),
        class,
        title: title(hwnd),
        process,
        elevated: elevated(own_integrity_level(), app_pid.and_then(integrity_level)),
    }
}

/// The current foreground window, described; `None` when there is none.
pub fn current() -> Option<ForegroundInfo> {
    // SAFETY: plain Win32 getter.
    let fg = unsafe { GetForegroundWindow() };
    (!fg.is_invalid()).then(|| describe(fg))
}

thread_local! {
    static SINK: RefCell<Option<ForegroundSink>> = const { RefCell::new(None) };
}

unsafe extern "system" fn on_foreground(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    _id_child: i32,
    _thread: u32,
    _time: u32,
) {
    if event != EVENT_SYSTEM_FOREGROUND || id_object != OBJID_WINDOW || hwnd.is_invalid() {
        return;
    }
    // Never unwind into user32.
    let _ = std::panic::catch_unwind(|| {
        let info = describe(hwnd);
        SINK.with(|s| {
            if let Ok(mut s) = s.try_borrow_mut()
                && let Some(sink) = s.as_mut()
            {
                sink(info);
            }
        });
    });
}

/// The installed WinEvent hook; dropping it unhooks. Must be created and
/// dropped on the thread whose message loop delivers the events.
pub struct ForegroundWatch {
    hook: HWINEVENTHOOK,
}

impl ForegroundWatch {
    /// Installs the hook on the calling thread and reports the current
    /// foreground at once. `None` when `SetWinEventHook` fails.
    pub fn install(mut sink: ForegroundSink) -> Option<ForegroundWatch> {
        if let Some(info) = current() {
            sink(info);
        }
        SINK.with(|s| *s.borrow_mut() = Some(sink));
        // SAFETY: out-of-context hook with a callback of the WINEVENTPROC
        // signature; events arrive through this thread's message loop.
        let hook = unsafe {
            SetWinEventHook(
                EVENT_SYSTEM_FOREGROUND,
                EVENT_SYSTEM_FOREGROUND,
                None,
                Some(on_foreground),
                0,
                0,
                WINEVENT_FLAGS,
            )
        };
        if hook.is_invalid() {
            SINK.with(|s| s.borrow_mut().take());
            return None;
        }
        Some(ForegroundWatch { hook })
    }
}

impl Drop for ForegroundWatch {
    fn drop(&mut self) {
        // SAFETY: a hook installed by this thread.
        let _ = unsafe { UnhookWinEvent(self.hook) };
        SINK.with(|s| s.borrow_mut().take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uwp_rules_come_from_the_policy_file() {
        let r = uwp_rules();
        assert_eq!(r.host_process, "ApplicationFrameHost");
        assert_eq!(r.frame_class, "ApplicationFrameWindow");
    }

    #[test]
    fn json_lookup() {
        let j = r#"{"a": {"k" :  "v1", "x": 1}, "k2":"v2"}"#;
        assert_eq!(json_str(j, "k"), Some("v1"));
        assert_eq!(json_str(j, "k2"), Some("v2"));
        assert_eq!(json_str(j, "x"), None);
        assert_eq!(json_str(j, "missing"), None);
    }

    #[test]
    fn titles_are_capped_by_chars() {
        let long: Vec<u16> = "標"
            .repeat(WINDOW_TITLE_MAX_CHARS + 5)
            .encode_utf16()
            .collect();
        assert_eq!(
            cap_title(&long, WINDOW_TITLE_MAX_CHARS).chars().count(),
            WINDOW_TITLE_MAX_CHARS
        );
        // A surrogate pair is never split.
        let emoji: Vec<u16> = "😀😀".encode_utf16().collect();
        assert_eq!(cap_title(&emoji, 1), "😀");
        // A lone surrogate becomes U+FFFD instead of failing.
        assert_eq!(cap_title(&[0xD800, u16::from(b'a')], 5), "\u{FFFD}a");
    }

    #[test]
    fn own_integrity_is_known() {
        assert!(own_integrity_level().is_some());
    }
}
