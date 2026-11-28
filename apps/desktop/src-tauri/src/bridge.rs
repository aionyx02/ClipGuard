//! The Native Messaging side of the desktop app (phase-4.md §4.3, §4.4):
//! the state `pw-work` publishes and the [`DesktopHandler`] that answers
//! `paste-warden-nmh` from it on the IPC server's own threads, so the worker
//! never waits on the bridge.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use paste_warden_core::policy::paste::PasteGuardSettings;
use paste_warden_core::policy::registered::RegisteredSecretStore;
use paste_warden_platform::nmh::protocol::HMAC_LEN;
use paste_warden_platform::nmh::{
    DesktopHandler, HOST_CAPS, Policy, RegisteredHmac, Request, Response,
};

/// HMACs of the registered secrets, by id. Never printed (`Debug` shows the
/// count only).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RegisteredHmacs(pub Vec<(u64, [u8; HMAC_LEN])>);

impl fmt::Debug for RegisteredHmacs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegisteredHmacs({})", self.0.len())
    }
}

/// What the desktop app tells `paste-warden-nmh` (via the named pipe / Unix
/// socket). Only policy and counts leave the process: no clipboard text, no
/// secrets, no HMAC key and no HMAC (T16); the HMACs stay here to answer
/// `match_registered`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmhState {
    pub intercept_registered: bool,
    pub intercept_detected: bool,
    pub allowlist: Vec<String>,
    pub registered_count: usize,
    pub registered: RegisteredHmacs,
}

impl NmhState {
    pub fn new(paste: &PasteGuardSettings, registered: Option<&RegisteredSecretStore>) -> Self {
        let hmacs = registered
            .map(|s| s.entries().iter().map(|e| (e.id, e.hmac)).collect())
            .unwrap_or_default();
        NmhState {
            intercept_registered: paste.intercept_registered,
            intercept_detected: paste.intercept_detected,
            allowlist: paste.allowed_apps.clone(),
            registered_count: registered.map_or(0, |s| s.entries().len()),
            registered: RegisteredHmacs(hmacs),
        }
    }
}

/// Where the worker publishes [`NmhState`].
pub trait NmhBridge: Send {
    /// Called at start and whenever the published state changes.
    fn publish(&mut self, state: &NmhState);
}

/// Constant-time equality (the extension's candidate against each entry).
fn ct_eq(a: &[u8; HMAC_LEN], b: &[u8; HMAC_LEN]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The last [`NmhState`], shared between `pw-work` (writer) and the IPC
/// server threads (readers).
#[derive(Clone)]
pub struct SharedNmh {
    state: Arc<Mutex<Option<NmhState>>>,
    version: &'static str,
}

impl SharedNmh {
    /// `version`: the desktop app version sent in `hello`.
    pub fn new(version: &'static str) -> Self {
        SharedNmh {
            state: Arc::new(Mutex::new(None)),
            version,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<NmhState>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn matches(&self, candidate: &RegisteredHmac) -> Option<u64> {
        let state = self.lock();
        let mut found = None;
        // Compare against every entry so the time does not depend on which
        // one (if any) matched.
        for (id, h) in &state.as_ref()?.registered.0 {
            if ct_eq(h, &candidate.0) && found.is_none() {
                found = Some(*id);
            }
        }
        found
    }
}

impl NmhBridge for SharedNmh {
    fn publish(&mut self, state: &NmhState) {
        *self.lock() = Some(state.clone());
    }
}

impl DesktopHandler for SharedNmh {
    fn handle(&self, req: Request) -> Response {
        match req {
            Request::Hello(_) => Response::Hello {
                ver: self.version.to_owned(),
                caps: HOST_CAPS.iter().map(|c| (*c).to_owned()).collect(),
            },
            Request::PolicyGet => {
                let policy = self.lock().as_ref().map_or(Policy::default(), |s| Policy {
                    paste_guard_registered: s.intercept_registered,
                    paste_guard_detected: s.intercept_detected,
                });
                Response::Policy { policy }
            }
            // Shown by the extension in the page; logged only, no
            // notification (§4.5). Rule id and severity only, never the host.
            Request::Verdict(v) => {
                crate::diag!(
                    "nmh verdict kind={} severity={} action={}",
                    v.kind,
                    v.severity.as_str(),
                    v.action.as_str()
                );
                Response::Logged
            }
            Request::MatchRegistered(h) => match self.matches(&h) {
                Some(id) => Response::Match {
                    matched: true,
                    label_id: Some(format!("reg-{id}")),
                },
                None => Response::Match {
                    matched: false,
                    label_id: None,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use paste_warden_core::policy::registered::{KEY_LENGTH, RegisteredSecretStore};
    use paste_warden_platform::nmh::{ExtInfo, Op};

    use super::*;

    fn store() -> RegisteredSecretStore {
        let mut s = RegisteredSecretStore::with_entries(&[9u8; KEY_LENGTH], Vec::new()).unwrap();
        s.add(Some("a"), "fake-Secret-0001-aaa", 1).unwrap();
        s.add(Some("b"), "fake-Secret-0002-bbb", 2).unwrap();
        s
    }

    #[test]
    fn answers_every_op_validly() {
        let mut h = SharedNmh::new("1.2.3");
        // Before the worker published anything: a safe default policy.
        let r = h.handle(Request::PolicyGet);
        assert_eq!(
            r,
            Response::Policy {
                policy: Policy::default()
            }
        );
        let s = store();
        let pg = PasteGuardSettings {
            intercept_detected: true,
            ..Default::default()
        };
        h.publish(&NmhState::new(&pg, Some(&s)));

        let hello = h.handle(Request::Hello(ExtInfo {
            ver: "1".into(),
            caps: vec![],
        }));
        assert!(hello.is_valid_for(Op::Hello));
        assert!(matches!(&hello, Response::Hello { ver, .. } if ver == "1.2.3"));

        let p = h.handle(Request::PolicyGet);
        assert!(p.is_valid_for(Op::PolicyGet));
        assert_eq!(
            p,
            Response::Policy {
                policy: Policy {
                    paste_guard_registered: pg.intercept_registered,
                    paste_guard_detected: true,
                }
            }
        );

        let second = &s.entries()[1];
        let m = h.handle(Request::MatchRegistered(RegisteredHmac(second.hmac)));
        assert!(m.is_valid_for(Op::MatchRegistered));
        assert_eq!(
            m,
            Response::Match {
                matched: true,
                label_id: Some(format!("reg-{}", second.id)),
            }
        );
        let miss = h.handle(Request::MatchRegistered(RegisteredHmac([0; HMAC_LEN])));
        assert!(miss.is_valid_for(Op::MatchRegistered));
        assert_eq!(
            miss,
            Response::Match {
                matched: false,
                label_id: None
            }
        );
    }

    #[test]
    fn state_debug_hides_hmacs() {
        let s = store();
        let st = NmhState::new(&PasteGuardSettings::default(), Some(&s));
        assert_eq!(st.registered_count, 2);
        let dbg = format!("{st:?}");
        assert!(dbg.contains("RegisteredHmacs(2)"));
        assert!(!dbg.contains(&format!("{:?}", s.entries()[0].hmac)));
    }
}
