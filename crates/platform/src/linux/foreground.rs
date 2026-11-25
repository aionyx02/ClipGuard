//! Foreground window history (phase-4.md §4.9.2), same shape as the macOS
//! `ForegroundHistory`. Pure: time is passed in. The X11 tracker
//! (`_NET_ACTIVE_WINDOW`) and the Wayland one (`zwlr_foreign_toplevel`) push
//! into it.
//!
//! For `policy::entry::classify_with` / `paste::is_allowed_with` the platform
//! passes [`ForegroundApp::class`] (WM_CLASS class or Wayland `app_id`) as
//! `class` and [`ForegroundApp::process`] (`/proc/<pid>/comm`) as `process`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Activations remembered (phase-4.md §4.3).
pub const FOREGROUND_HISTORY_LEN: usize = 16;
/// Longest class / instance / process name kept, in chars; longer values
/// are cut.
pub const APP_NAME_MAX_CHARS: usize = 256;
/// Bytes of a `WM_CLASS` property read at most (two short strings).
pub const WM_CLASS_MAX_BYTES: usize = 1_024;

/// One window that came to the front.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundApp {
    /// X11 `WM_CLASS` class (second string), or the Wayland `app_id`.
    pub class: Option<String>,
    /// X11 `WM_CLASS` instance (first string); `None` on Wayland.
    pub instance: Option<String>,
    /// `/proc/<pid>/comm` of the owning process, when known.
    pub process: Option<String>,
    pub pid: Option<u32>,
    /// X11 window id or a per-connection toplevel id; tells two windows of
    /// the same app apart.
    pub window: u64,
}

fn cap(s: String) -> String {
    match s.char_indices().nth(APP_NAME_MAX_CHARS) {
        Some((i, _)) => s[..i].to_owned(),
        None => s,
    }
}

fn clean(s: Option<String>) -> Option<String> {
    s.filter(|s| !s.trim().is_empty() && !s.chars().any(char::is_control))
        .map(cap)
}

impl ForegroundApp {
    /// Builds an entry, cutting overlong strings and dropping empty ones.
    pub fn new(
        class: Option<String>,
        instance: Option<String>,
        process: Option<String>,
        pid: Option<u32>,
        window: u64,
    ) -> ForegroundApp {
        ForegroundApp {
            class: clean(class),
            instance: clean(instance),
            process: clean(process),
            pid,
            window,
        }
    }

    /// `class` argument for the policy functions (`""` when unknown).
    pub fn class_str(&self) -> &str {
        self.class.as_deref().unwrap_or("")
    }

    /// `process` argument for the policy functions: the comm name, else the
    /// class (Wayland has no pid), else `""`.
    pub fn process_str(&self) -> &str {
        self.process
            .as_deref()
            .or(self.class.as_deref())
            .unwrap_or("")
    }

    fn same(&self, other: &ForegroundApp) -> bool {
        self.window == other.window && self.class == other.class && self.pid == other.pid
    }
}

/// Splits a `WM_CLASS` value (`instance\0class\0`) into its two strings.
/// Non-UTF-8 strings are dropped (ICCCM says Latin-1; real apps use ASCII).
pub fn parse_wm_class(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let bytes = &bytes[..bytes.len().min(WM_CLASS_MAX_BYTES)];
    let mut parts = bytes
        .split(|&b| b == 0)
        .map(|p| std::str::from_utf8(p).ok().map(str::to_owned));
    let instance = parts.next().flatten();
    let class = parts.next().flatten();
    (clean(instance), clean(class))
}

/// Bounded activation history, oldest first.
#[derive(Debug, Default)]
pub struct ForegroundHistory {
    entries: VecDeque<(Instant, ForegroundApp)>,
}

/// Shared between the tracker thread and `pw-clip` / `pw-work`.
pub type SharedForeground = Arc<Mutex<ForegroundHistory>>;

impl ForegroundHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared() -> SharedForeground {
        Arc::new(Mutex::new(Self::new()))
    }

    /// Records that `app` came to the front at `at`. A repeat of the current
    /// window is ignored; times that go backwards are clamped.
    pub fn push(&mut self, app: ForegroundApp, at: Instant) {
        let at = match self.entries.back() {
            Some((last_at, last)) => {
                if last.same(&app) {
                    return;
                }
                at.max(*last_at)
            }
            None => at,
        };
        if self.entries.len() == FOREGROUND_HISTORY_LEN {
            self.entries.pop_front();
        }
        self.entries.push_back((at, app));
    }

    /// The window currently in front, as far as we have seen.
    pub fn current(&self) -> Option<&ForegroundApp> {
        self.entries.back().map(|(_, a)| a)
    }

    /// The window that was in front at time `t`.
    pub fn at(&self, t: Instant) -> Option<&ForegroundApp> {
        self.entries
            .iter()
            .rev()
            .find(|(at, _)| *at <= t)
            .map(|(_, a)| a)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn app(class: &str, window: u64) -> ForegroundApp {
        ForegroundApp::new(Some(class.into()), None, None, None, window)
    }

    #[test]
    fn wm_class_parsing() {
        assert_eq!(
            parse_wm_class(b"keepassxc\0KeePassXC\0"),
            (Some("keepassxc".into()), Some("KeePassXC".into()))
        );
        assert_eq!(
            parse_wm_class(b"xterm\0XTerm"),
            (Some("xterm".into()), Some("XTerm".into()))
        );
        assert_eq!(parse_wm_class(b""), (None, None));
        assert_eq!(parse_wm_class(b"\0\0"), (None, None));
        assert_eq!(parse_wm_class(b"a\xff\0B\0"), (None, Some("B".into())));
        let long = [b"i\0".as_slice(), &vec![b'c'; 5_000]].concat();
        let (_, c) = parse_wm_class(&long);
        assert_eq!(
            c.map(|c| c.len()),
            Some(APP_NAME_MAX_CHARS),
            "bounded read, capped name"
        );
    }

    #[test]
    fn policy_strings() {
        let a = ForegroundApp::new(Some("kitty".into()), None, None, None, 1);
        assert_eq!(a.class_str(), "kitty");
        assert_eq!(
            a.process_str(),
            "kitty",
            "Wayland: no pid, app_id stands in"
        );
        let b = ForegroundApp::new(
            Some("Gnome-terminal".into()),
            Some("gnome-terminal-server".into()),
            Some("gnome-terminal-".into()),
            Some(42),
            2,
        );
        assert_eq!(b.process_str(), "gnome-terminal-");
        let none = ForegroundApp::new(None, None, None, None, 0);
        assert_eq!((none.class_str(), none.process_str()), ("", ""));
    }

    #[test]
    fn lookup_by_time() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut h = ForegroundHistory::new();
        h.push(app("Firefox", 10), ms(100));
        h.push(app("kitty", 11), ms(200));
        assert!(h.at(ms(50)).is_none());
        assert_eq!(h.at(ms(150)).unwrap().window, 10);
        assert_eq!(h.at(ms(200)).unwrap().window, 11);
        assert_eq!(h.current().unwrap().window, 11);
    }

    #[test]
    fn repeats_ignored_bounded_and_monotonic() {
        let t0 = Instant::now();
        let mut h = ForegroundHistory::new();
        h.push(app("a", 1), t0);
        h.push(app("a", 1), t0 + Duration::from_millis(5));
        assert_eq!(h.len(), 1);
        h.push(app("a", 2), t0 + Duration::from_millis(6));
        assert_eq!(h.len(), 2, "another window of the same app");
        for i in 0..(FOREGROUND_HISTORY_LEN as u64 + 5) {
            h.push(app("x", 100 + i), t0 + Duration::from_millis(10 + i));
        }
        assert_eq!(h.len(), FOREGROUND_HISTORY_LEN);
        let mut h = ForegroundHistory::new();
        h.push(app("a", 1), t0 + Duration::from_millis(100));
        h.push(app("b", 2), t0);
        assert_eq!(h.at(t0 + Duration::from_millis(100)).unwrap().window, 2);
    }
}
