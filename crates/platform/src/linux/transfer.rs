//! X11 selection transfer bookkeeping (S5 pitfall 6): dropping replies that
//! belong to an older owner, and reassembling INCR transfers under a cap.
//! Pure; the X11 thread feeds it.

use zeroize::Zeroizing;

/// One selection owner as announced by XFixes `SelectionNotify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation {
    /// The owner window (0 = no owner).
    pub owner: u32,
    /// `selection_timestamp` of the change; conversions are requested with it.
    pub timestamp: u32,
    /// Our sequence number for this change.
    pub sequence: u32,
}

/// Tracks the conversion in flight so a reply that arrives after the owner
/// changed again is dropped instead of being attributed to the new change.
#[derive(Debug, Default)]
pub struct ConversionTracker {
    current: Option<Generation>,
    /// Target atom of the conversion in flight, for `current`.
    pending_target: Option<u32>,
}

impl ConversionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// A new owner was announced; anything in flight is now stale.
    pub fn on_owner_change(&mut self, generation: Generation) {
        self.current = Some(generation);
        self.pending_target = None;
    }

    pub fn current(&self) -> Option<Generation> {
        self.current
    }

    /// We sent `ConvertSelection(target)` for the current generation.
    pub fn begin(&mut self, target: u32) {
        self.pending_target = self.current.map(|_| target);
    }

    /// `true` when a `SelectionNotify` reply with `time` / `target` answers
    /// the conversion in flight. Accepting it ends that conversion.
    pub fn accept(&mut self, time: u32, target: u32) -> bool {
        let ok = matches!(
            (self.current, self.pending_target),
            (Some(g), Some(t)) if t == target && (time == g.timestamp || time == 0)
        );
        if ok {
            self.pending_target = None;
        }
        ok
    }
}

/// What to do after one chunk of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Wait for the next chunk.
    More,
    /// The transfer is complete.
    Done,
    /// The cap was reached; stop reading.
    Capped,
}

/// Collects chunks (INCR, or `GetProperty` pieces) up to `cap` bytes.
pub struct Assembler {
    buf: Zeroizing<Vec<u8>>,
    cap: usize,
}

impl std::fmt::Debug for Assembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Assembler")
            .field("len", &self.buf.len())
            .field("cap", &self.cap)
            .finish()
    }
}

/// Initial allocation at most (custom): a size hint from a peer is not trusted.
pub const ASSEMBLER_INITIAL_CAPACITY: usize = 64 * 1024;

impl Assembler {
    /// `size_hint` is the INCR lower bound the owner announced (untrusted).
    pub fn new(cap: usize, size_hint: usize) -> Self {
        let initial = size_hint.min(cap).min(ASSEMBLER_INITIAL_CAPACITY);
        Assembler {
            buf: Zeroizing::new(Vec::with_capacity(initial)),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Bytes still accepted before the cap.
    pub fn room(&self) -> usize {
        self.cap - self.buf.len()
    }

    /// Appends one INCR chunk; an empty chunk ends the transfer.
    pub fn push_incr(&mut self, chunk: &[u8]) -> Step {
        if chunk.is_empty() {
            return Step::Done;
        }
        self.append(chunk)
    }

    /// Appends bytes; returns [`Step::Capped`] once the cap is reached.
    pub fn append(&mut self, chunk: &[u8]) -> Step {
        let take = chunk.len().min(self.room());
        extend_zeroizing(&mut self.buf, &chunk[..take], self.cap);
        if take < chunk.len() || self.room() == 0 {
            Step::Capped
        } else {
            Step::More
        }
    }

    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

/// Append to a zeroized buffer without leaving old copies behind on growth.
pub fn extend_zeroizing(buf: &mut Zeroizing<Vec<u8>>, bytes: &[u8], cap: usize) {
    let needed = buf.len() + bytes.len();
    if needed > buf.capacity() {
        let new_cap = needed.max(buf.capacity() * 2).min(cap.max(needed));
        let mut grown = Zeroizing::new(Vec::with_capacity(new_cap));
        grown.extend_from_slice(buf);
        *buf = grown;
    }
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(owner: u32, timestamp: u32, sequence: u32) -> Generation {
        Generation {
            owner,
            timestamp,
            sequence,
        }
    }

    #[test]
    fn stale_replies_are_dropped() {
        let mut t = ConversionTracker::new();
        assert!(!t.accept(10, 1), "nothing in flight");
        t.on_owner_change(g(5, 10, 1));
        t.begin(100);
        assert!(!t.accept(10, 101), "other target");
        // The owner changes before the reply arrives (S5: 300 xclip runs).
        t.on_owner_change(g(6, 11, 2));
        assert!(!t.accept(10, 100), "reply for the old owner");
        t.begin(100);
        assert!(!t.accept(10, 100), "old timestamp");
        assert!(t.accept(11, 100));
        assert!(!t.accept(11, 100), "only once");
        assert_eq!(t.current().map(|g| g.sequence), Some(2));
    }

    #[test]
    fn current_time_replies_accepted() {
        // Some owners answer with CurrentTime (0).
        let mut t = ConversionTracker::new();
        t.on_owner_change(g(5, 10, 1));
        t.begin(7);
        assert!(t.accept(0, 7));
    }

    #[test]
    fn incr_reassembly() {
        let mut a = Assembler::new(10, 1 << 30);
        assert_eq!(a.push_incr(b"abc"), Step::More);
        assert_eq!(a.push_incr(b"def"), Step::More);
        assert_eq!(a.push_incr(b""), Step::Done);
        assert_eq!(&a.into_bytes()[..], b"abcdef");
    }

    #[test]
    fn incr_is_capped() {
        let mut a = Assembler::new(5, 0);
        assert_eq!(a.push_incr(b"abc"), Step::More);
        assert_eq!(a.push_incr(b"defgh"), Step::Capped);
        assert_eq!(a.len(), 5);
        assert_eq!(a.room(), 0);
        let mut b = Assembler::new(3, 0);
        assert_eq!(b.append(b"abc"), Step::Capped, "exactly full");
        assert_eq!(&b.into_bytes()[..], b"abc");
    }

    #[test]
    fn huge_size_hint_is_not_trusted() {
        let a = Assembler::new(usize::MAX, usize::MAX);
        assert!(a.buf.capacity() <= ASSEMBLER_INITIAL_CAPACITY);
        assert!(a.is_empty());
    }

    #[test]
    fn zeroizing_extend() {
        let mut v = Zeroizing::new(Vec::new());
        extend_zeroizing(&mut v, b"ab", 4);
        extend_zeroizing(&mut v, b"cd", 4);
        assert_eq!(&v[..], b"abcd");
    }
}
