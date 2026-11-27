//! A hand-rolled HTTP/1.1 mock server for the Tier 2 tests (no extra deps).
//! It counts connections, records request bodies and answers each request
//! with the next canned reply.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone)]
pub enum Reply {
    Json(u16, String),
    /// Read the request, then never answer.
    Hang,
}

pub struct Request {
    pub head: String,
    pub body: String,
}

pub struct MockServer {
    pub port: u16,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub fn start(replies: Vec<Reply>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (c, r, s) = (connections.clone(), requests.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        c.fetch_add(1, Ordering::SeqCst);
                        let reply = replies
                            .next()
                            .unwrap_or_else(|| Reply::Json(500, "{}".into()));
                        serve(stream, reply, &r, &s);
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        MockServer {
            port,
            connections,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }

    pub fn root_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn bodies(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.body.clone())
            .collect()
    }

    pub fn heads(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.head.clone())
            .collect()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn serve(mut s: TcpStream, reply: Reply, log: &Mutex<Vec<Request>>, stop: &AtomicBool) {
    let _ = s.set_nonblocking(false);
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
    log.lock().unwrap().push(Request { head, body });
    match reply {
        Reply::Json(status, body) => {
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
        Reply::Hang => {
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// An OpenAI-compatible chat completion whose message content is `content`.
pub fn openai(content: &str) -> String {
    serde_json::json!({
        "id": "x", "object": "chat.completion",
        "choices": [ { "index": 0, "finish_reason": "stop",
            "message": { "role": "assistant", "content": content } } ]
    })
    .to_string()
}

/// An Anthropic Messages response with one text block.
pub fn anthropic(content: &str) -> String {
    serde_json::json!({
        "id": "x", "type": "message", "role": "assistant", "stop_reason": "end_turn",
        "content": [ { "type": "text", "text": content } ]
    })
    .to_string()
}

pub const GOOD_MALICIOUS: &str = r#"{"level":"malicious","explanation":"Downloads a script and runs it in a hidden window.","techniques":["download_execute","hidden_window"]}"#;
pub const GOOD_NONE: &str =
    r#"{"level":"none","explanation":"Shows the repository status.","techniques":[]}"#;
