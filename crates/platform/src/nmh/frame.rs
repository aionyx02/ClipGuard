//! Native Messaging framing: a 4-byte native-endian length, then that many
//! bytes of UTF-8 JSON (S9). The same framing carries the IPC between
//! `paste-warden-nmh` and the desktop app.
//!
//! The length is checked against [`NMH_MAX_MESSAGE_BYTES`] **before** any
//! buffer is allocated, so a hostile prefix can't make us reserve memory.
//! Nothing here panics on any input.

use std::fmt;
use std::io::{self, Read, Write};

use super::NMH_MAX_MESSAGE_BYTES;

/// Why a frame couldn't be read or written.
#[derive(Debug)]
pub enum FrameError {
    /// The length prefix is larger than [`NMH_MAX_MESSAGE_BYTES`]. The rest
    /// of the stream is not read: the caller must stop.
    TooLarge(u32),
    /// The stream ended in the middle of a frame.
    Truncated,
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, "frame of {n} bytes exceeds the limit"),
            Self::Truncated => f.write_str("stream ended inside a frame"),
            // io::Error never carries message bytes.
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Checks a length prefix. Pure: the allocation decision is made here.
pub fn check_len(prefix: [u8; 4]) -> Result<usize, FrameError> {
    let n = u32::from_ne_bytes(prefix);
    match usize::try_from(n) {
        Ok(len) if len <= NMH_MAX_MESSAGE_BYTES => Ok(len),
        _ => Err(FrameError::TooLarge(n)),
    }
}

/// `(payload, rest)` from [`split_frame`].
pub type Split<'a> = (&'a [u8], &'a [u8]);

/// Splits one frame off the front of `bytes`: `(payload, rest)`.
/// `Ok(None)` when `bytes` doesn't hold a whole frame yet.
pub fn split_frame(bytes: &[u8]) -> Result<Option<Split<'_>>, FrameError> {
    let Some((prefix, rest)) = bytes.split_first_chunk::<4>() else {
        return Ok(None);
    };
    let len = check_len(*prefix)?;
    Ok(rest.split_at_checked(len))
}

/// Reads one frame. `Ok(None)` on a clean EOF before the first prefix byte.
pub fn read_frame<R: Read + ?Sized>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut prefix = [0u8; 4];
    let mut got = 0;
    while got < prefix.len() {
        match r.read(&mut prefix[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let len = check_len(prefix)?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })?;
    Ok(Some(buf))
}

/// Encodes one frame. Refuses payloads over [`NMH_MAX_MESSAGE_BYTES`].
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|&n| n as usize <= NMH_MAX_MESSAGE_BYTES)
        .ok_or(FrameError::TooLarge(u32::MAX))?;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Writes one frame and flushes (one `write_all`, so the prefix and payload
/// reach a pipe together).
pub fn write_frame<W: Write + ?Sized>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    let frame = encode_frame(payload)?;
    w.write_all(&frame).map_err(FrameError::Io)?;
    w.flush().map_err(FrameError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let frame = encode_frame(b"{\"op\":\"hello\"}").unwrap();
        let mut r = &frame[..];
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"{\"op\":\"hello\"}");
        assert!(read_frame(&mut r).unwrap().is_none());
    }

    #[test]
    fn length_bytes_that_look_like_text_mode_characters() {
        // S9 Windows: 0x0A / 0x0D / 0x1A in the prefix must survive.
        for len in [10usize, 13, 26, 266, 3338] {
            let payload = vec![b'x'; len];
            let frame = encode_frame(&payload).unwrap();
            assert_eq!(split_frame(&frame).unwrap().unwrap().0.len(), len);
        }
    }

    /// A reader that fails the test if more than the prefix is requested.
    struct PrefixOnly([u8; 4], usize);
    impl Read for PrefixOnly {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(self.1 < 4, "read past the prefix of an oversize frame");
            let n = buf.len().min(4 - self.1);
            buf[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
            self.1 += n;
            Ok(n)
        }
    }

    #[test]
    fn oversize_rejected_before_allocation() {
        let too_big = (NMH_MAX_MESSAGE_BYTES as u32 + 1).to_ne_bytes();
        assert!(matches!(
            read_frame(&mut PrefixOnly(too_big, 0)),
            Err(FrameError::TooLarge(_))
        ));
        assert!(matches!(
            read_frame(&mut PrefixOnly(u32::MAX.to_ne_bytes(), 0)),
            Err(FrameError::TooLarge(u32::MAX))
        ));
        assert!(matches!(
            split_frame(&too_big),
            Err(FrameError::TooLarge(_))
        ));
        assert!(encode_frame(&vec![0; NMH_MAX_MESSAGE_BYTES + 1]).is_err());
        assert!(encode_frame(&vec![0; NMH_MAX_MESSAGE_BYTES]).is_ok());
    }

    #[test]
    fn truncated() {
        let mut r: &[u8] = &[5, 0];
        assert!(matches!(read_frame(&mut r), Err(FrameError::Truncated)));
        let mut frame = encode_frame(b"hello").unwrap();
        frame.pop();
        let mut r = &frame[..];
        assert!(matches!(read_frame(&mut r), Err(FrameError::Truncated)));
        assert!(split_frame(&frame).unwrap().is_none());
        assert!(split_frame(&[1, 2]).unwrap().is_none());
    }
}
