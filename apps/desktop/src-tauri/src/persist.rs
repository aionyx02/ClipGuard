//! Storage seen by the worker (docs/plan/phase-4.md §4.3 `store.rs`).
//!
//! INTEGRATION POINT: the main session implements [`Persistence`] with
//! `paste_warden_platform::store` (JSON files + OS keyring) and passes it to
//! `app::run`. Until then the app runs on [`MemoryPersistence`], which keeps
//! nothing across restarts.

use paste_warden_core::policy::paste::PasteGuardSettings;
use paste_warden_core::policy::registered::{KEY_LENGTH, RegisteredSecret, RegisteredSecretStore};
use zeroize::Zeroizing;

use crate::model::AppSettings;

/// Most registered secrets kept (phase-4.md §4.3; mirrors
/// `store::MAX_REGISTERED_SECRETS`).
pub const MAX_REGISTERED_SECRETS: usize = 100;

/// A storage failure. Never carries file contents or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistError {
    /// Reading or writing a file failed.
    Io,
    /// A file was corrupt or too large; defaults are used.
    Corrupt,
    /// The HMAC key could not be read from the keyring (it is never re-created
    /// silently, §5.1).
    KeyUnavailable,
    /// Linux without Secret Service: registered secrets are disabled (§4.9.2).
    NoSecretService,
}

impl PersistError {
    /// Fluent id shown to the user.
    pub fn message_id(self) -> &'static str {
        match self {
            PersistError::Io => "ui-desktop-error-save-failed",
            PersistError::Corrupt => "ui-desktop-error-store-corrupt",
            PersistError::KeyUnavailable => "ui-desktop-error-key-unavailable",
            // Shared with the status reason (frontend `ui-desktop-status-*`).
            PersistError::NoSecretService => "ui-desktop-status-no-secret-service",
        }
    }
}

/// The worker's storage. Loading returns defaults plus the problem, so a
/// corrupt file never stops protection.
pub trait Persistence: Send {
    fn load_settings(&mut self) -> (AppSettings, Option<PersistError>);
    fn save_settings(&mut self, settings: &AppSettings) -> Result<(), PersistError>;
    fn load_paste_guard(&mut self) -> (PasteGuardSettings, Option<PersistError>);
    fn save_paste_guard(&mut self, settings: &PasteGuardSettings) -> Result<(), PersistError>;
    /// The registered-secret store with its keyring key. Creating the key the
    /// first time is the implementation's job; a key that exists but cannot be
    /// read is an error.
    fn load_registered(&mut self) -> Result<RegisteredSecretStore, PersistError>;
    fn save_registered(&mut self, entries: &[RegisteredSecret]) -> Result<(), PersistError>;
}

/// In-memory storage (tests, and the app until the store is wired in).
pub struct MemoryPersistence {
    pub settings: AppSettings,
    pub paste_guard: PasteGuardSettings,
    pub key: Zeroizing<[u8; KEY_LENGTH]>,
    pub registered: Vec<RegisteredSecret>,
    /// Make every save fail (tests).
    pub fail_saves: bool,
}

impl MemoryPersistence {
    /// `key` must be random in real use; tests pass a fixed one.
    pub fn new(key: [u8; KEY_LENGTH]) -> Self {
        MemoryPersistence {
            settings: AppSettings::default(),
            paste_guard: PasteGuardSettings::default(),
            key: Zeroizing::new(key),
            registered: Vec::new(),
            fail_saves: false,
        }
    }

    fn check(&self) -> Result<(), PersistError> {
        if self.fail_saves {
            Err(PersistError::Io)
        } else {
            Ok(())
        }
    }
}

impl Persistence for MemoryPersistence {
    fn load_settings(&mut self) -> (AppSettings, Option<PersistError>) {
        (self.settings.clone(), None)
    }

    fn save_settings(&mut self, settings: &AppSettings) -> Result<(), PersistError> {
        self.check()?;
        self.settings = settings.clone();
        Ok(())
    }

    fn load_paste_guard(&mut self) -> (PasteGuardSettings, Option<PersistError>) {
        (self.paste_guard.sanitized(), None)
    }

    fn save_paste_guard(&mut self, settings: &PasteGuardSettings) -> Result<(), PersistError> {
        self.check()?;
        self.paste_guard = settings.sanitized();
        Ok(())
    }

    fn load_registered(&mut self) -> Result<RegisteredSecretStore, PersistError> {
        RegisteredSecretStore::with_entries(&self.key[..], self.registered.clone())
            .map_err(|_| PersistError::KeyUnavailable)
    }

    fn save_registered(&mut self, entries: &[RegisteredSecret]) -> Result<(), PersistError> {
        self.check()?;
        self.registered = entries.to_vec();
        Ok(())
    }
}
