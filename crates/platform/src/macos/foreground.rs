//! Foreground app tracking (phase-4.md §4.9.1, S4 finding 2).
//!
//! The polled `frontmostApplication` at the time a copy is noticed is often
//! wrong (the user already switched away), so the observer keeps a short
//! history of activations and the monitor asks for the app that was in front
//! *before* the change.
//!
//! [`ForegroundHistory`] is pure (time is passed in). [`ForegroundObserver`]
//! subscribes to `NSWorkspaceDidActivateApplicationNotification`; it must be
//! registered on the main thread, whose run loop (Tauri's) delivers the
//! notifications.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{AllocAnyThread, DefinedClass, MainThreadMarker, define_class, msg_send, sel};
use objc2_app_kit::{
    NSRunningApplication, NSWorkspace, NSWorkspaceApplicationKey,
    NSWorkspaceDidActivateApplicationNotification,
};
use objc2_foundation::{NSNotification, NSNotificationCenter, NSObjectProtocol, NSString};

/// Activations remembered (phase-4.md §4.3).
pub const FOREGROUND_HISTORY_LEN: usize = 16;
/// Longest bundle id / app name kept, in chars; longer values are cut.
pub const APP_NAME_MAX_CHARS: usize = 256;

/// One app that came to the front.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundApp {
    /// `CFBundleIdentifier`; `None` for unbundled executables.
    pub bundle_id: Option<String>,
    pub name: Option<String>,
    /// -1 when AppKit reports none.
    pub pid: i32,
}

fn cap(s: String) -> String {
    match s.char_indices().nth(APP_NAME_MAX_CHARS) {
        Some((i, _)) => s[..i].to_owned(),
        None => s,
    }
}

impl ForegroundApp {
    /// Builds an entry, cutting overlong strings and dropping empty ones.
    pub fn new(bundle_id: Option<String>, name: Option<String>, pid: i32) -> ForegroundApp {
        let clean = |s: Option<String>| s.filter(|s| !s.trim().is_empty()).map(cap);
        ForegroundApp {
            bundle_id: clean(bundle_id),
            name: clean(name),
            pid,
        }
    }

    fn same_app(&self, other: &ForegroundApp) -> bool {
        self.pid == other.pid && self.bundle_id == other.bundle_id
    }
}

/// Bounded activation history, oldest first.
#[derive(Debug, Default)]
pub struct ForegroundHistory {
    entries: VecDeque<(Instant, ForegroundApp)>,
}

/// Shared between the main-thread observer and `pw-clip` / `pw-work`.
pub type SharedForeground = Arc<Mutex<ForegroundHistory>>;

impl ForegroundHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared() -> SharedForeground {
        Arc::new(Mutex::new(Self::new()))
    }

    /// Records that `app` came to the front at `at`. A repeat of the current
    /// app is ignored; times that go backwards are clamped to the last entry.
    pub fn push(&mut self, app: ForegroundApp, at: Instant) {
        let at = match self.entries.back() {
            Some((last_at, last)) => {
                if last.same_app(&app) {
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

    /// The app currently in front, as far as we have seen.
    pub fn current(&self) -> Option<&ForegroundApp> {
        self.entries.back().map(|(_, a)| a)
    }

    /// The app that was in front at time `t` (activated at or before `t`).
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

fn app_info(app: &NSRunningApplication) -> ForegroundApp {
    ForegroundApp::new(
        app.bundleIdentifier().map(|s| s.to_string()),
        app.localizedName().map(|s| s.to_string()),
        app.processIdentifier(),
    )
}

/// The frontmost app right now (`NSWorkspace.frontmostApplication`).
pub fn frontmost_app() -> Option<ForegroundApp> {
    objc2::rc::autoreleasepool(|_| {
        let app = NSWorkspace::sharedWorkspace().frontmostApplication()?;
        Some(app_info(&app))
    })
}

/// Ivars of the Objective-C observer object.
pub struct ObserverIvars {
    history: SharedForeground,
}

define_class!(
    // SAFETY:
    // - NSObject has no subclassing requirements.
    // - `PwForegroundObserver` does not implement `Drop`.
    #[unsafe(super(NSObject))]
    #[name = "PwForegroundObserver"]
    #[ivars = ObserverIvars]
    struct PwForegroundObserver;

    impl PwForegroundObserver {
        #[unsafe(method(appActivated:))]
        fn app_activated(&self, note: &NSNotification) {
            objc2::rc::autoreleasepool(|_| self.record(note));
        }
    }

    unsafe impl NSObjectProtocol for PwForegroundObserver {}
);

impl PwForegroundObserver {
    fn new(history: SharedForeground) -> Retained<Self> {
        let this = Self::alloc().set_ivars(ObserverIvars { history });
        // SAFETY: plain NSObject init on a freshly allocated object.
        unsafe { msg_send![super(this), init] }
    }

    fn record(&self, note: &NSNotification) {
        let Some(info) = note.userInfo() else { return };
        // SAFETY: reading an AppKit constant.
        let key: &NSString = unsafe { NSWorkspaceApplicationKey };
        let Some(obj) = info.objectForKey(key as &AnyObject) else {
            return;
        };
        let Ok(app) = obj.downcast::<NSRunningApplication>() else {
            return;
        };
        let app = app_info(&app);
        if let Ok(mut h) = self.ivars().history.lock() {
            h.push(app, Instant::now());
        }
    }
}

/// Keeps the notification subscription alive; dropping it unsubscribes.
/// Not `Send`: create and drop it on the main thread.
pub struct ForegroundObserver {
    observer: Retained<PwForegroundObserver>,
    center: Retained<NSNotificationCenter>,
}

impl ForegroundObserver {
    /// Subscribes on the main thread (`mtm` proves it) and seeds `history`
    /// with the current frontmost app.
    pub fn register(history: SharedForeground, _mtm: MainThreadMarker) -> ForegroundObserver {
        if let Some(app) = frontmost_app()
            && let Ok(mut h) = history.lock()
        {
            h.push(app, Instant::now());
        }
        let observer = PwForegroundObserver::new(history);
        let center = NSWorkspace::sharedWorkspace().notificationCenter();
        // SAFETY: `observer` implements `appActivated:` taking one
        // NSNotification; it is removed in `Drop` before it is released.
        unsafe {
            let name = NSWorkspaceDidActivateApplicationNotification;
            center.addObserver_selector_name_object(
                &observer,
                sel!(appActivated:),
                Some(name),
                None,
            );
        }
        ForegroundObserver { observer, center }
    }
}

impl Drop for ForegroundObserver {
    fn drop(&mut self) {
        // SAFETY: the observer was added to this center in `register`.
        unsafe { self.center.removeObserver(&self.observer) };
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn app(id: &str, pid: i32) -> ForegroundApp {
        ForegroundApp::new(Some(id.into()), Some(id.into()), pid)
    }

    #[test]
    fn lookup_by_time() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut h = ForegroundHistory::new();
        assert!(h.at(ms(0)).is_none());
        h.push(app("org.example.browser", 10), ms(100));
        h.push(app("org.example.term", 11), ms(200));
        assert!(h.at(ms(50)).is_none(), "before anything was seen");
        assert_eq!(h.at(ms(100)).unwrap().pid, 10);
        assert_eq!(h.at(ms(199)).unwrap().pid, 10);
        assert_eq!(h.at(ms(200)).unwrap().pid, 11);
        assert_eq!(h.current().unwrap().pid, 11);
    }

    #[test]
    fn repeats_ignored_and_bounded() {
        let t0 = Instant::now();
        let mut h = ForegroundHistory::new();
        h.push(app("a", 1), t0);
        h.push(app("a", 1), t0 + Duration::from_millis(5));
        assert_eq!(h.len(), 1);
        for i in 0..(FOREGROUND_HISTORY_LEN as i32 + 5) {
            h.push(app("x", 100 + i), t0 + Duration::from_millis(10 + i as u64));
        }
        assert_eq!(h.len(), FOREGROUND_HISTORY_LEN);
        assert_ne!(h.entries.front().unwrap().1.pid, 1, "oldest evicted");
    }

    #[test]
    fn time_never_goes_backwards() {
        let t0 = Instant::now();
        let mut h = ForegroundHistory::new();
        h.push(app("a", 1), t0 + Duration::from_millis(100));
        h.push(app("b", 2), t0);
        assert_eq!(h.at(t0 + Duration::from_millis(100)).unwrap().pid, 2);
    }

    #[test]
    fn names_are_capped_and_empty_dropped() {
        let a = ForegroundApp::new(Some("x".repeat(1000)), Some("  ".into()), 3);
        assert_eq!(
            a.bundle_id.as_deref().map(|s| s.chars().count()),
            Some(APP_NAME_MAX_CHARS)
        );
        assert_eq!(a.name, None);
        let b = ForegroundApp::new(Some("é".repeat(APP_NAME_MAX_CHARS + 1)), None, 3);
        assert_eq!(
            b.bundle_id.unwrap().chars().count(),
            APP_NAME_MAX_CHARS,
            "cut on a char boundary"
        );
    }
}
