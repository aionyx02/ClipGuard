//! The HTTP seam. [`Transport`] is a trait so the guardrails can be tested
//! without a network; [`UreqTransport`] (feature `net`) is the real client.

use std::time::Duration;

use zeroize::Zeroizing;

/// One POST request. The body holds masked text only; it is zeroized on drop.
pub struct HttpRequest {
    pub url: String,
    /// Header name and value (the value may be the API key: zeroized on drop).
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
    pub body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}

/// Transport failures. Carry no request or response content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    Connect,
    /// The response body is larger than the cap.
    TooLarge,
    /// A redirect was returned; redirects are never followed (a local
    /// endpoint must not be able to bounce the request to a cloud host).
    Redirect,
    Other,
}

/// Sends one POST and returns the status and at most `max_body` bytes.
///
/// Implementations must not follow redirects, must not use a proxy taken
/// from the environment, and must stop after `timeout` (connect + read).
pub trait Transport {
    fn post(
        &self,
        req: &HttpRequest,
        timeout: Duration,
        max_body: usize,
    ) -> Result<HttpResponse, TransportError>;
}

/// `ureq` with rustls: no redirects, no proxy, connect and global timeouts.
#[cfg(feature = "net")]
#[derive(Debug, Default, Clone, Copy)]
pub struct UreqTransport;

#[cfg(feature = "net")]
impl Transport for UreqTransport {
    fn post(
        &self,
        req: &HttpRequest,
        timeout: Duration,
        max_body: usize,
    ) -> Result<HttpResponse, TransportError> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(timeout))
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .proxy(None)
            .user_agent(concat!("paste-warden/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let mut r = agent.post(&req.url);
        for (k, v) in &req.headers {
            r = r.header(*k, v.as_str());
        }
        let mut resp = r.send(&req.body[..]).map_err(map_err)?;
        let status = resp.status().as_u16();
        if (300..400).contains(&status) {
            return Err(TransportError::Redirect);
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(max_body as u64)
            .read_to_vec()
            .map_err(map_err)?;
        Ok(HttpResponse {
            status,
            body: Zeroizing::new(body),
        })
    }
}

#[cfg(feature = "net")]
fn map_err(e: ureq::Error) -> TransportError {
    use std::io::ErrorKind;
    match e {
        ureq::Error::Timeout(_) => TransportError::Timeout,
        ureq::Error::BodyExceedsLimit(_) => TransportError::TooLarge,
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => TransportError::Connect,
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => TransportError::Redirect,
        ureq::Error::Io(io) => match io.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => TransportError::Timeout,
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::AddrNotAvailable => TransportError::Connect,
            _ => TransportError::Other,
        },
        _ => TransportError::Other,
    }
}
