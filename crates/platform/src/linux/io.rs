//! Pipe and poll helpers for the Wayland / X11 threads (Linux only). Safe
//! code via `rustix`; nothing here formats data into errors.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;
use rustix::pipe::{PipeFlags, pipe_with};
use zeroize::Zeroizing;

use super::text::{ReadEnd, ReadResult};
use super::transfer::extend_zeroizing;

/// Bytes read per `read(2)` call.
pub const READ_CHUNK_BYTES: usize = 64 * 1024;

/// A close-on-exec pipe: `(read end, write end)`. Both ends block: the
/// write end goes to another client, and `O_NONBLOCK` would be shared with
/// it. [`read_capped`] switches the read end itself.
pub fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    Ok(pipe_with(PipeFlags::CLOEXEC)?)
}

/// Waits until one of `fds` is readable or `timeout` passes. Returns the
/// readiness of each fd (`true` = readable / hung up). `None` waits forever.
pub fn wait_readable(fds: &[BorrowedFd<'_>], timeout: Option<Duration>) -> Vec<bool> {
    let mut pfds: Vec<PollFd<'_>> = fds
        .iter()
        .map(|fd| PollFd::new(fd, PollFlags::IN))
        .collect();
    let ts = timeout.map(|t| {
        Timespec::try_from(t).unwrap_or(Timespec {
            tv_sec: i64::MAX,
            tv_nsec: 0,
        })
    });
    match poll(&mut pfds, ts.as_ref()) {
        Ok(_) => pfds
            .iter()
            .map(|p| {
                p.revents()
                    .intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            })
            .collect(),
        Err(_) => vec![false; fds.len()],
    }
}

fn set_nonblocking(fd: BorrowedFd<'_>) -> bool {
    match fcntl_getfl(fd) {
        Ok(flags) => fcntl_setfl(fd, flags | OFlags::NONBLOCK).is_ok(),
        Err(_) => false,
    }
}

/// Reads `fd` until EOF, `max_bytes`, or `timeout` (S5 pitfall 4: a source
/// can stream forever). The bytes go straight into a zeroized buffer.
pub fn read_capped(fd: BorrowedFd<'_>, max_bytes: usize, timeout: Duration) -> ReadResult {
    let deadline = Instant::now() + timeout;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new(vec![0u8; READ_CHUNK_BYTES]);
    if !set_nonblocking(fd) {
        return ReadResult {
            bytes,
            end: ReadEnd::Failed,
        };
    }
    loop {
        let room = max_bytes - bytes.len();
        if room == 0 {
            return ReadResult {
                bytes,
                end: ReadEnd::Capped,
            };
        }
        let want = room.min(chunk.len());
        match rustix::io::read(fd, &mut chunk[..want]) {
            Ok(0) => {
                return ReadResult {
                    bytes,
                    end: ReadEnd::Complete,
                };
            }
            Ok(n) => extend_zeroizing(&mut bytes, &chunk[..n], max_bytes),
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() || !wait_readable(&[fd], Some(left))[0] {
                    let end = if Instant::now() >= deadline {
                        ReadEnd::TimedOut
                    } else {
                        ReadEnd::Failed
                    };
                    return ReadResult { bytes, end };
                }
            }
            Err(_) => {
                return ReadResult {
                    bytes,
                    end: ReadEnd::Failed,
                };
            }
        }
    }
}

/// Writes all of `data` to `fd` within `timeout`; `false` when the reader
/// went away or was too slow. The fd is switched to non-blocking.
pub fn write_all_timeout(fd: BorrowedFd<'_>, data: &[u8], timeout: Duration) -> bool {
    if !set_nonblocking(fd) {
        return false;
    }
    let deadline = Instant::now() + timeout;
    let mut off = 0;
    while off < data.len() {
        match rustix::io::write(fd, &data[off..]) {
            Ok(n) => off += n,
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return false;
                }
                let mut p = [PollFd::new(&fd, PollFlags::OUT)];
                let ts = Timespec::try_from(left).ok();
                if poll(&mut p, ts.as_ref()).is_err() {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

/// Wakes a thread blocked in [`wait_readable`] (command queue).
#[derive(Debug)]
pub struct Waker {
    write: OwnedFd,
}

/// The read side of a [`Waker`].
#[derive(Debug)]
pub struct WakeReceiver {
    read: OwnedFd,
}

/// A connected waker pair.
pub fn waker() -> std::io::Result<(Waker, WakeReceiver)> {
    let (read, write) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
    Ok((Waker { write }, WakeReceiver { read }))
}

impl Waker {
    pub fn wake(&self) {
        // A full pipe already means "awake"; errors are ignored.
        let _ = rustix::io::write(&self.write, &[1]);
    }
}

impl WakeReceiver {
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }

    /// Empties the pipe.
    pub fn drain(&self) {
        let mut buf = [0u8; 64];
        while matches!(rustix::io::read(&self.read, &mut buf), Ok(n) if n > 0) {}
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn reads_until_eof() {
        let (r, w) = pipe().unwrap();
        let mut f = std::fs::File::from(w);
        f.write_all(b"placeholder").unwrap();
        drop(f);
        let res = read_capped(r.as_fd(), 1024, Duration::from_millis(200));
        assert_eq!(res.end, ReadEnd::Complete);
        assert_eq!(&res.bytes[..], b"placeholder");
    }

    #[test]
    fn cap_stops_a_streaming_source() {
        let (r, w) = pipe().unwrap();
        let t = std::thread::spawn(move || {
            let chunk = [b'*'; 4096];
            let _ = write_all_timeout(w.as_fd(), &chunk, Duration::from_millis(50));
            // Keep the write end open: the source "streams forever".
            std::thread::sleep(Duration::from_millis(300));
            drop(w);
        });
        let res = read_capped(r.as_fd(), 1000, Duration::from_secs(2));
        assert_eq!(res.end, ReadEnd::Capped);
        assert_eq!(res.bytes.len(), 1000);
        t.join().unwrap();
    }

    #[test]
    fn silent_source_times_out() {
        let (r, w) = pipe().unwrap();
        let start = Instant::now();
        let res = read_capped(r.as_fd(), 1000, Duration::from_millis(100));
        assert_eq!(res.end, ReadEnd::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(w);
    }

    #[test]
    fn writer_gives_up_on_a_stuck_reader() {
        let (r, w) = pipe().unwrap();
        let big = vec![b'*'; 4 * 1024 * 1024];
        let start = Instant::now();
        assert!(!write_all_timeout(
            w.as_fd(),
            &big,
            Duration::from_millis(100)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(r);
    }

    #[test]
    fn waker_wakes() {
        let (w, r) = waker().unwrap();
        assert!(!wait_readable(&[r.fd()], Some(Duration::from_millis(10)))[0]);
        w.wake();
        assert!(wait_readable(&[r.fd()], Some(Duration::from_millis(10)))[0]);
        r.drain();
        assert!(!wait_readable(&[r.fd()], Some(Duration::from_millis(10)))[0]);
    }
}
