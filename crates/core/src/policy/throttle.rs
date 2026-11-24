//! Notification throttle (legacy `NotificationThrottle`; detection-rules.md §2.1, P2).
//!
//! Windows queues notifications and shows them one after another, so a burst of
//! copies produces stale notifications for tens of seconds. This guarantees:
//! - at most one notification on screen: a new one replaces the old one;
//! - at least `min_interval_ms` between two notifications; while waiting only the
//!   latest one is kept, and a clipboard change drops it;
//! - "blocked, click to restore" notifications (`restorable`) show immediately and
//!   are never dropped; while one is visible only an `Error` may replace it, a
//!   `Warning` waits for `visible_for_ms` to pass.
//!
//! Pure logic: time is passed in as milliseconds.

/// Default minimum interval between two notifications (legacy 1 s).
pub const DEFAULT_MIN_INTERVAL_MS: u64 = 1_000;
/// Default time a notification is considered visible (legacy 6 s; Windows shows 5 s).
pub const DEFAULT_VISIBLE_FOR_MS: u64 = 6_000;

/// Notification severity; `Warning < Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NotificationLevel {
    Warning,
    Error,
}

/// A notification with an app-defined payload (title, body messages…).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification<T> {
    pub level: NotificationLevel,
    /// The "blocked, click to restore" notification.
    pub restorable: bool,
    pub payload: T,
}

/// What to do now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationDecision<T> {
    /// Show this now (`None` = show nothing).
    pub show: Option<Notification<T>>,
    /// The previous notification may still be on screen or queued: remove it first.
    pub replace_visible: bool,
    /// A notification is waiting: call [`NotificationThrottle::flush`] after this long.
    pub retry_in_ms: Option<u64>,
}

impl<T> NotificationDecision<T> {
    fn nothing() -> Self {
        NotificationDecision {
            show: None,
            replace_visible: false,
            retry_in_ms: None,
        }
    }
}

/// See the module docs.
#[derive(Debug, Clone)]
pub struct NotificationThrottle<T> {
    min_interval_ms: u64,
    visible_for_ms: u64,
    last_shown_at: Option<u64>,
    last_shown_restorable: bool,
    pending: Option<Notification<T>>,
}

impl<T: Clone> Default for NotificationThrottle<T> {
    fn default() -> Self {
        Self::new(DEFAULT_MIN_INTERVAL_MS, DEFAULT_VISIBLE_FOR_MS)
    }
}

impl<T: Clone> NotificationThrottle<T> {
    pub fn new(min_interval_ms: u64, visible_for_ms: u64) -> Self {
        NotificationThrottle {
            min_interval_ms,
            visible_for_ms,
            last_shown_at: None,
            last_shown_restorable: false,
            pending: None,
        }
    }

    /// The notification waiting to be shown.
    pub fn pending(&self) -> Option<&Notification<T>> {
        self.pending.as_ref()
    }

    /// The clipboard changed: a waiting notification describes old content; drop it.
    pub fn on_clipboard_changed(&mut self) {
        self.pending = None;
    }

    pub fn submit(&mut self, n: Notification<T>, now_ms: u64) -> NotificationDecision<T> {
        if n.restorable {
            return self.show_now(n, now_ms);
        }
        // One slot, latest wins; but a waiting Error is not replaced by a Warning.
        if self.pending.as_ref().is_none_or(|p| p.level <= n.level) {
            self.pending = Some(n);
        }
        self.flush(now_ms)
    }

    /// Timer callback: shows the waiting notification if it is due.
    pub fn flush(&mut self, now_ms: u64) -> NotificationDecision<T> {
        let Some(level) = self.pending.as_ref().map(|p| p.level) else {
            return NotificationDecision::nothing();
        };
        let due = self.due_at(level);
        if due <= now_ms {
            match self.pending.take() {
                Some(p) => self.show_now(p, now_ms),
                None => NotificationDecision::nothing(),
            }
        } else {
            NotificationDecision {
                show: None,
                replace_visible: false,
                retry_in_ms: Some(due - now_ms),
            }
        }
    }

    fn due_at(&self, level: NotificationLevel) -> u64 {
        let Some(last) = self.last_shown_at else {
            return 0;
        };
        // While a "click to restore" notification is visible, a Warning waits for it.
        if self.last_shown_restorable && level == NotificationLevel::Warning {
            last.saturating_add(self.visible_for_ms)
        } else {
            last.saturating_add(self.min_interval_ms)
        }
    }

    fn show_now(&mut self, n: Notification<T>, now_ms: u64) -> NotificationDecision<T> {
        let replace = self
            .last_shown_at
            .is_some_and(|last| now_ms.saturating_sub(last) < self.visible_for_ms);
        self.last_shown_at = Some(now_ms);
        self.last_shown_restorable = n.restorable;
        self.pending = None;
        NotificationDecision {
            show: Some(n),
            replace_visible: replace,
            retry_in_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(level: NotificationLevel, title: &str, restorable: bool) -> Notification<String> {
        Notification {
            level,
            restorable,
            payload: title.into(),
        }
    }

    #[test]
    fn waits_then_replaces() {
        let mut t = NotificationThrottle::default();
        let d = t.submit(n(NotificationLevel::Warning, "a", false), 0);
        assert!(d.show.is_some() && !d.replace_visible);
        let d = t.submit(n(NotificationLevel::Warning, "b", false), 300);
        assert_eq!(d.retry_in_ms, Some(700));
        assert!(t.flush(999).show.is_none());
        let d = t.flush(1000);
        assert_eq!(d.show.map(|s| s.payload), Some("b".into()));
        assert!(d.replace_visible);
        assert!(t.pending().is_none());
    }

    #[test]
    fn error_not_overwritten_and_restorable_delays_warning() {
        let mut t = NotificationThrottle::default();
        t.submit(n(NotificationLevel::Error, "blocked", true), 0);
        let d = t.submit(n(NotificationLevel::Warning, "w", false), 1500);
        assert_eq!(d.retry_in_ms, Some(4500));
        let d = t.submit(n(NotificationLevel::Error, "e", false), 1600);
        assert_eq!(d.show.map(|s| s.payload), Some("e".into()));
    }
}
