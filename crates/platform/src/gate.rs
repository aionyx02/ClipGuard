//! `PasteGate` (docs/plan/phase-4.md §4.2): the atomics the paste hook (Windows
//! `WH_KEYBOARD_LL`) or event tap (macOS `CGEventTap`) reads. Platform
//! independent; every field is an atomic, so the callbacks never lock or
//! allocate.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

/// No key is being swallowed.
pub(crate) const NO_KEY: u32 = u32::MAX;

/// What `pw-work` decided for the analyzed clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    /// Not analyzed yet (or the analysis timed out).
    Unknown = 0,
    Allow = 1,
    /// Secret or registered secret: ask the user first.
    Intercept = 2,
}

impl Decision {
    pub(crate) fn from_u8(v: u8) -> Decision {
        match v {
            1 => Decision::Allow,
            2 => Decision::Intercept,
            _ => Decision::Unknown,
        }
    }
}

/// The only state shared across threads (§4.2): written by `pw-work` and
/// `pw-clip`, read by the hook / tap callback (no locks, no allocation).
///
/// `analyzed_seq` and `decision` are packed into one atomic so the callback
/// never sees a new sequence with an old decision.
#[derive(Debug)]
pub struct PasteGate {
    /// `(analyzed_seq << 8) | decision`.
    pub(crate) verdict: AtomicU64,
    /// Latest clipboard sequence seen by `pw-clip` (macOS polls it; Windows
    /// callbacks call `GetClipboardSequenceNumber` instead).
    pub(crate) clipboard_seq: AtomicU32,
    /// The frontmost app is on the paste allowlist (computed by `pw-work`).
    pub(crate) fg_allowed: AtomicBool,
    /// Keycode whose key-down we swallowed, until its key-up.
    // Read by the macOS tap and the Windows hook; Linux has no interception.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(crate) swallowed_key: AtomicU32,
    /// Event time of that key-down or its last auto-repeat (Windows tick
    /// milliseconds), to notice a key-up that never arrived.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) swallowed_at: AtomicU32,
    /// Root window of the foreground at the last change (Windows HWND as
    /// i64; 0 = unknown). Written by `pw-work`.
    pub(crate) fg_root: AtomicI64,
    /// Window the open paste confirmation belongs to (0 = none, §4.4).
    pub(crate) pending_target: AtomicI64,
}

impl Default for PasteGate {
    fn default() -> Self {
        PasteGate {
            verdict: AtomicU64::new(Decision::Unknown as u64),
            clipboard_seq: AtomicU32::new(0),
            fg_allowed: AtomicBool::new(false),
            swallowed_key: AtomicU32::new(NO_KEY),
            swallowed_at: AtomicU32::new(0),
            fg_root: AtomicI64::new(0),
            pending_target: AtomicI64::new(0),
        }
    }
}

impl PasteGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// `pw-work`: the clipboard at `seq` was analyzed with `decision`.
    pub fn publish(&self, seq: u32, decision: Decision) {
        let packed = (u64::from(seq) << 8) | decision as u64;
        self.verdict.store(packed, Ordering::Release);
    }

    /// `(analyzed_seq, decision)`.
    pub fn verdict(&self) -> (u32, Decision) {
        let v = self.verdict.load(Ordering::Acquire);
        ((v >> 8) as u32, Decision::from_u8(v as u8))
    }

    /// `pw-clip`: the pasteboard's current sequence number.
    pub fn set_clipboard_seq(&self, seq: u32) {
        self.clipboard_seq.store(seq, Ordering::Release);
    }

    pub fn clipboard_seq(&self) -> u32 {
        self.clipboard_seq.load(Ordering::Acquire)
    }

    /// `pw-work`, on every foreground change.
    pub fn set_fg_allowed(&self, allowed: bool) {
        self.fg_allowed.store(allowed, Ordering::Release);
    }

    pub fn fg_allowed(&self) -> bool {
        self.fg_allowed.load(Ordering::Acquire)
    }

    /// `pw-work`, on every foreground change (with [`Self::set_fg_allowed`]).
    pub fn set_fg_root(&self, root: i64) {
        self.fg_root.store(root, Ordering::Release);
    }

    pub fn fg_root(&self) -> i64 {
        self.fg_root.load(Ordering::Acquire)
    }

    /// `pw-work`: a confirmation for `target` is open (0 clears it).
    pub fn set_pending_target(&self, target: i64) {
        self.pending_target.store(target, Ordering::Release);
    }

    pub fn pending_target(&self) -> i64 {
        self.pending_target.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_round_trips() {
        let g = PasteGate::new();
        assert_eq!(g.verdict(), (0, Decision::Unknown));
        g.publish(u32::MAX, Decision::Intercept);
        assert_eq!(g.verdict(), (u32::MAX, Decision::Intercept));
        g.publish(3, Decision::Allow);
        assert_eq!(g.verdict(), (3, Decision::Allow));
        assert_eq!(Decision::from_u8(9), Decision::Unknown);
        g.set_fg_root(-5);
        g.set_pending_target(42);
        assert_eq!((g.fg_root(), g.pending_target()), (-5, 42));
    }
}
