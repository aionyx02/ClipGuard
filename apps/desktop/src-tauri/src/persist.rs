//! Storage seen by the worker (docs/plan/phase-4.md §4.3 `store.rs`).
//!
//! [`StorePersistence`] is the real one: `paste_warden_platform::store`
//! (JSON files in the data directory + the HMAC key in the OS keyring).
//! [`MemoryPersistence`] keeps nothing across restarts (tests, and the
//! fallback when no data directory can be resolved).

use paste_warden_core::Message;
use paste_warden_core::policy::paste::PasteGuardSettings;
use paste_warden_core::policy::registered::{KEY_LENGTH, RegisteredSecret, RegisteredSecretStore};
use paste_warden_platform::status::Reason;
use paste_warden_platform::store::{self, KeyBackend, KeyringBackend, Store, StoreError};
use zeroize::Zeroizing;

use crate::model::{AppSettings, CommandError, LocalePref, ThemePref};

pub use paste_warden_platform::store::MAX_REGISTERED_SECRETS;

/// A storage failure. Never carries file contents or secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistError {
    /// Reading or writing a file failed ([`MemoryPersistence`]).
    Io,
    /// A file was corrupt or too large; defaults are used.
    Corrupt,
    /// The HMAC key could not be read from the keyring (it is never re-created
    /// silently, §5.1).
    KeyUnavailable,
    /// Linux without Secret Service: registered secrets are disabled (§4.9.2).
    NoSecretService,
    /// The keyring lost the HMAC key while `secrets.json` has entries. The
    /// way out is the `forget_secrets` command (then register again).
    KeyMissing,
    /// Anything else the platform store reported (message id + arguments).
    Store(StoreError),
}

impl From<StoreError> for PersistError {
    fn from(e: StoreError) -> Self {
        if e.status_reason() == Some(Reason::NoSecretService) {
            PersistError::NoSecretService
        } else if e == StoreError::KeyMissing {
            PersistError::KeyMissing
        } else {
            PersistError::Store(e)
        }
    }
}

impl PersistError {
    /// Fluent id shown to the user.
    pub fn message_id(&self) -> &'static str {
        match self {
            PersistError::Io => "ui-desktop-error-save-failed",
            PersistError::Corrupt => "ui-desktop-error-store-corrupt",
            PersistError::KeyUnavailable => "ui-desktop-error-key-unavailable",
            // Shared with the status reason (frontend `ui-desktop-status-*`).
            PersistError::NoSecretService => "ui-desktop-status-no-secret-service",
            PersistError::KeyMissing => StoreError::KeyMissing.message_id(),
            PersistError::Store(e) => e.message_id(),
        }
    }

    /// The localizable message (store errors carry `file` / `field` / `max`).
    pub fn message(&self) -> Message {
        match self {
            PersistError::Store(e) => e.message(),
            other => Message::new(other.message_id()),
        }
    }

    /// The command error contract `{messageId, field?, args?}`. `field` is
    /// never set: store problems are not about a form field.
    pub fn to_command_error(&self) -> CommandError {
        CommandError::from_message(&self.message(), None)
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
    /// Deletes every registered secret (the key stays, or is created on the
    /// next [`Self::load_registered`]): the way out of
    /// [`PersistError::KeyMissing`] or a corrupt `secrets.json`.
    fn forget_registered(&mut self) -> Result<(), PersistError>;
}

/// In-memory storage (tests, and the fallback without a data directory).
pub struct MemoryPersistence {
    pub settings: AppSettings,
    pub paste_guard: PasteGuardSettings,
    pub key: Zeroizing<[u8; KEY_LENGTH]>,
    pub registered: Vec<RegisteredSecret>,
    /// Make every save fail (tests).
    pub fail_saves: bool,
    /// `load_registered` fails with this (tests).
    pub registered_error: Option<PersistError>,
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
            registered_error: None,
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
        if let Some(e) = &self.registered_error {
            return Err(e.clone());
        }
        RegisteredSecretStore::with_entries(&self.key[..], self.registered.clone())
            .map_err(|_| PersistError::KeyUnavailable)
    }

    fn save_registered(&mut self, entries: &[RegisteredSecret]) -> Result<(), PersistError> {
        self.check()?;
        self.registered = entries.to_vec();
        Ok(())
    }

    fn forget_registered(&mut self) -> Result<(), PersistError> {
        self.check()?;
        self.registered.clear();
        self.registered_error = None;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The platform store

fn locale_from(l: store::Locale) -> LocalePref {
    match l {
        store::Locale::System => LocalePref::System,
        store::Locale::ZhTw => LocalePref::ZhTw,
        store::Locale::En => LocalePref::En,
    }
}

fn locale_to(l: LocalePref) -> store::Locale {
    match l {
        LocalePref::System => store::Locale::System,
        LocalePref::ZhTw => store::Locale::ZhTw,
        LocalePref::En => store::Locale::En,
    }
}

fn theme_from(t: store::Theme) -> ThemePref {
    match t {
        store::Theme::System => ThemePref::System,
        store::Theme::Light => ThemePref::Light,
        store::Theme::Dark => ThemePref::Dark,
    }
}

fn theme_to(t: ThemePref) -> store::Theme {
    match t {
        ThemePref::System => store::Theme::System,
        ThemePref::Light => store::Theme::Light,
        ThemePref::Dark => store::Theme::Dark,
    }
}

/// [`Persistence`] on `paste_warden_platform::store`. `settings.json` holds
/// the store's `Settings` (locale, theme, onboarding, last version); the
/// engine settings in [`AppSettings::engine`] are not persisted and always
/// start at core's defaults (nothing in the UI changes them yet).
pub struct StorePersistence<K: KeyBackend = KeyringBackend> {
    store: Store<K>,
}

impl StorePersistence<KeyringBackend> {
    /// The real data directory and OS keyring.
    pub fn open_default() -> Result<Self, PersistError> {
        Ok(StorePersistence {
            store: Store::open_default()?,
        })
    }
}

impl<K: KeyBackend> StorePersistence<K> {
    pub fn new(store: Store<K>) -> Self {
        StorePersistence { store }
    }
}

impl<K: KeyBackend + Send> Persistence for StorePersistence<K> {
    fn load_settings(&mut self) -> (AppSettings, Option<PersistError>) {
        let (s, e) = self.store.load_settings();
        let app = AppSettings {
            locale: locale_from(s.locale),
            theme: theme_from(s.theme),
            onboarding_done: s.onboarding_done,
            last_version: s.last_version,
            engine: paste_warden_core::Settings::default(),
        };
        (app, e.map(PersistError::from))
    }

    fn save_settings(&mut self, settings: &AppSettings) -> Result<(), PersistError> {
        let s = store::Settings {
            locale: locale_to(settings.locale),
            theme: theme_to(settings.theme),
            onboarding_done: settings.onboarding_done,
            last_version: settings.last_version.clone(),
        };
        Ok(self.store.save_settings(&s)?)
    }

    fn load_paste_guard(&mut self) -> (PasteGuardSettings, Option<PersistError>) {
        let (s, e) = self.store.load_paste_guard();
        (s, e.map(PersistError::from))
    }

    fn save_paste_guard(&mut self, settings: &PasteGuardSettings) -> Result<(), PersistError> {
        Ok(self.store.save_paste_guard(settings)?)
    }

    fn load_registered(&mut self) -> Result<RegisteredSecretStore, PersistError> {
        Ok(self.store.load_secrets()?)
    }

    fn save_registered(&mut self, entries: &[RegisteredSecret]) -> Result<(), PersistError> {
        Ok(self.store.save_entries(entries)?)
    }

    fn forget_registered(&mut self) -> Result<(), PersistError> {
        Ok(self.store.forget_secrets()?)
    }
}

#[cfg(test)]
mod tests {
    use paste_warden_platform::store::{KeyBackendError, MemoryKeyBackend, StoreFile};

    use super::*;

    const FAKE_SECRET: &str = "fake-Secret-0042-xyz";

    fn add(p: &mut dyn Persistence) {
        let mut s = p.load_registered().unwrap();
        s.add(Some("bank"), FAKE_SECRET, 1).unwrap();
        p.save_registered(s.entries()).unwrap();
    }

    #[test]
    fn round_trips_through_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let keys = MemoryKeyBackend::new();
        let mut p = StorePersistence::new(Store::new(dir.path(), &keys));
        assert_eq!(p.load_settings(), (AppSettings::default(), None));

        let next = AppSettings {
            locale: LocalePref::ZhTw,
            theme: ThemePref::Dark,
            onboarding_done: true,
            last_version: Some("1.2.3".into()),
            ..Default::default()
        };
        p.save_settings(&next).unwrap();
        assert_eq!(p.load_settings(), (next, None));

        let pg = PasteGuardSettings {
            intercept_detected: true,
            allowed_apps: vec!["KeePass".into()],
            ..Default::default()
        };
        p.save_paste_guard(&pg).unwrap();
        assert_eq!(p.load_paste_guard().0, pg.sanitized());

        add(&mut p);
        let s = p.load_registered().unwrap();
        assert_eq!(s.entries().len(), 1);
        assert_eq!(s.find(FAKE_SECRET).len(), 1);
        // Only the HMAC is on disk.
        let on_disk = std::fs::read_to_string(dir.path().join(StoreFile::Secrets.name())).unwrap();
        assert!(!on_disk.contains(FAKE_SECRET));
    }

    #[test]
    fn key_missing_is_surfaced_and_forget_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let keys = MemoryKeyBackend::new();
        let mut p = StorePersistence::new(Store::new(dir.path(), &keys));
        add(&mut p);
        keys.clear();
        let e = p.load_registered().unwrap_err();
        assert_eq!(e, PersistError::KeyMissing);
        let ce = e.to_command_error();
        assert_eq!(ce.message_id, "store-error-key-missing");
        assert_eq!(ce.field, None);

        p.forget_registered().unwrap();
        let s = p.load_registered().unwrap();
        assert!(s.entries().is_empty());
        assert!(keys.has_key(), "a fresh key was created");
    }

    #[test]
    fn errors_map_to_the_command_contract() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(StoreFile::Settings.name()), "{not json").unwrap();
        let keys = MemoryKeyBackend::failing(KeyBackendError::Unavailable);
        let mut p = StorePersistence::new(Store::new(dir.path(), &keys));
        let (s, e) = p.load_settings();
        assert_eq!(s, AppSettings::default());
        let ce = e.unwrap().to_command_error();
        assert_eq!(ce.message_id, "store-error-corrupt");
        assert_eq!(ce.args["file"], "settings.json");

        let e = p.load_registered().unwrap_err();
        if cfg!(target_os = "linux") {
            assert_eq!(e, PersistError::NoSecretService);
            assert_eq!(e.message_id(), "ui-desktop-status-no-secret-service");
        } else {
            assert_eq!(e.message_id(), "store-error-key-unavailable");
        }

        let too_many = PersistError::from(StoreError::TooManySecrets).to_command_error();
        assert_eq!(too_many.message_id, "store-error-too-many-secrets");
        assert_eq!(too_many.args["max"], MAX_REGISTERED_SECRETS);
    }
}
