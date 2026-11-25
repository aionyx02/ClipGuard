//! Settings and registered-secret persistence (docs/plan/phase-4.md §4.3
//! "設定與登記機密", §4.5, §4.9.1, §4.9.2; detection-rules.md §5.1).
//!
//! - Files live in one data directory ([`data_dir`]): `settings.json`,
//!   `paste-guard.json` and `secrets.json`. Every file is capped at
//!   [`STORE_FILE_MAX_BYTES`] (bigger = corrupt) and written atomically
//!   (temp file + rename).
//! - Registered secrets are stored only as `(id, label, length,
//!   HMAC-SHA256, created_at_ms)` (core's [`RegisteredSecret`]). The 32-byte
//!   HMAC key lives in the OS keyring ([`KeyBackend`], [`KeyringBackend`]),
//!   never in a file. "Not found" on first use creates the key; any other
//!   keyring error is an error, and a key that is missing while secrets
//!   exist is [`StoreError::KeyMissing`] — the key is never regenerated
//!   behind the user's back (§5.1). On Linux an unavailable keyring maps to
//!   [`Reason::NoSecretService`] ([`StoreError::status_reason`]); there is
//!   no key-file fallback.
//! - Errors carry only kinds, file names, field names and message ids, never
//!   file contents, secrets or labels (P3/P4).
//!
//! This crate may read env vars and do IO; detection stays in core (P7).
//! Single writer: `pw-work` owns the [`Store`]; register / remove are
//! load-modify-save and not safe against concurrent writers.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use paste_warden_core::Message;
use paste_warden_core::policy::paste::PasteGuardSettings;
use paste_warden_core::policy::registered::{
    AddError, HMAC_LENGTH, MAX_LABEL_LENGTH, MAX_LENGTH, MIN_LENGTH, RegisteredSecret,
    RegisteredSecretStore, RegistrationError, validate_registration,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::status::Reason;

pub use paste_warden_core::policy::registered::{KEY_LENGTH, MAX_SCAN_LENGTH};

/// Settings file name.
pub const SETTINGS_FILE: &str = "settings.json";
/// Paste-guard settings file name (detection-rules.md §5.3).
pub const PASTE_GUARD_FILE: &str = "paste-guard.json";
/// Registered secrets file name (§5.1).
pub const SECRETS_FILE: &str = "secrets.json";
/// Any store file bigger than this is treated as corrupt.
pub const STORE_FILE_MAX_BYTES: usize = 65_536;
/// OS keyring service of the HMAC key.
pub const KEYRING_SERVICE: &str = "PasteWarden";
/// OS keyring account of the HMAC key.
pub const KEYRING_ACCOUNT: &str = "registered-secrets-hmac-key";
/// At most this many registered secrets.
pub const MAX_REGISTERED_SECRETS: usize = 100;
/// `Settings::last_version` longer than this (chars) is dropped as corrupt.
pub const LAST_VERSION_MAX_CHARS: usize = 64;
/// Files the legacy (C#) app left in `%LOCALAPPDATA%\ClipGuard` (§4.5). Only
/// these are deleted; the legacy key was DPAPI-protected and is not migrated.
pub const LEGACY_FILES: [&str; 3] = ["secrets.json", "key.bin", "paste-guard.json"];
/// Version of the `secrets.json` layout.
const SECRETS_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Which store file an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFile {
    /// The data directory itself.
    DataDir,
    Settings,
    PasteGuard,
    Secrets,
}

impl StoreFile {
    /// File name (`""` for the directory). Safe to log.
    pub fn name(self) -> &'static str {
        match self {
            StoreFile::DataDir => "",
            StoreFile::Settings => SETTINGS_FILE,
            StoreFile::PasteGuard => PASTE_GUARD_FILE,
            StoreFile::Secrets => SECRETS_FILE,
        }
    }
}

/// Why the OS keyring could not deliver or keep the HMAC key. Carries no key
/// material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBackendError {
    /// No usable credential store (e.g. no Secret Service on Linux).
    Unavailable,
    /// The store exists but refused access (locked, denied).
    AccessDenied,
    /// The stored item is not a usable key.
    Corrupt,
    /// Any other platform failure.
    Platform,
}

/// A store failure. Never contains file contents, secrets or labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// No data directory could be resolved from the environment.
    NoDataDir,
    Io {
        file: StoreFile,
        kind: io::ErrorKind,
    },
    /// Bigger than [`STORE_FILE_MAX_BYTES`].
    TooLarge { file: StoreFile },
    /// Unparsable, or a field has an invalid value (`field` names it).
    Corrupt {
        file: StoreFile,
        field: Option<&'static str>,
    },
    /// No usable OS keyring (on Linux: no Secret Service). Registered secrets
    /// are disabled.
    KeyUnavailable,
    /// The keyring refused access to the key.
    KeyAccessDenied,
    /// The keyring holds something that is not a [`KEY_LENGTH`]-byte key.
    KeyCorrupt,
    /// The key is gone while `secrets.json` has entries. Not regenerated
    /// (§5.1); the user can [`Store::forget_secrets`] and register again.
    KeyMissing,
    /// Other keyring failure.
    KeyPlatform,
    /// The OS random number generator failed.
    Random,
    /// Already [`MAX_REGISTERED_SECRETS`] secrets.
    TooManySecrets,
    /// The registration dialog input is invalid (field + message, no value).
    Registration(RegistrationError),
    /// Core refused the secret (length, duplicate).
    Add(AddError),
}

impl From<KeyBackendError> for StoreError {
    fn from(e: KeyBackendError) -> Self {
        match e {
            KeyBackendError::Unavailable => StoreError::KeyUnavailable,
            KeyBackendError::AccessDenied => StoreError::KeyAccessDenied,
            KeyBackendError::Corrupt => StoreError::KeyCorrupt,
            KeyBackendError::Platform => StoreError::KeyPlatform,
        }
    }
}

impl StoreError {
    /// Fluent message id.
    pub fn message_id(&self) -> &'static str {
        match self {
            StoreError::NoDataDir => "store-error-no-data-dir",
            StoreError::Io { .. } => "store-error-io",
            StoreError::TooLarge { .. } => "store-error-too-large",
            StoreError::Corrupt { .. } => "store-error-corrupt",
            StoreError::KeyUnavailable => "store-error-key-unavailable",
            StoreError::KeyAccessDenied => "store-error-key-access-denied",
            StoreError::KeyCorrupt => "store-error-key-corrupt",
            StoreError::KeyMissing => "store-error-key-missing",
            StoreError::KeyPlatform => "store-error-key-platform",
            StoreError::Random => "store-error-random",
            StoreError::TooManySecrets => "store-error-too-many-secrets",
            StoreError::Registration(_) | StoreError::Add(_) => "store-error-registration",
        }
    }

    /// Localizable message. Registration problems reuse core's messages; the
    /// rest get `file` / `field` / `max` arguments where they apply.
    pub fn message(&self) -> Message {
        match self {
            StoreError::Registration(e) => e.message.clone(),
            StoreError::Add(e) => e.message(),
            StoreError::Io { file, .. } | StoreError::TooLarge { file } => {
                Message::new(self.message_id()).arg("file", file.name())
            }
            StoreError::Corrupt { file, field } => Message::new(self.message_id())
                .arg("file", file.name())
                .arg("field", field.unwrap_or("")),
            StoreError::TooManySecrets => {
                Message::new(self.message_id()).arg("max", MAX_REGISTERED_SECRETS)
            }
            _ => Message::new(self.message_id()),
        }
    }

    /// The protection-status reason this error implies, if any: an
    /// unavailable keyring on Linux is [`Reason::NoSecretService`] (§4.9.2).
    pub fn status_reason(&self) -> Option<Reason> {
        match self {
            StoreError::KeyUnavailable if cfg!(target_os = "linux") => {
                Some(Reason::NoSecretService)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io { file, kind } => {
                write!(f, "{} ({}: {kind:?})", self.message_id(), file.name())
            }
            StoreError::TooLarge { file } => write!(f, "{} ({})", self.message_id(), file.name()),
            StoreError::Corrupt { file, field } => write!(
                f,
                "{} ({}{}{})",
                self.message_id(),
                file.name(),
                if field.is_some() { ": " } else { "" },
                field.unwrap_or("")
            ),
            StoreError::Registration(e) => write!(f, "{} ({})", e.message.id, e.field.as_str()),
            StoreError::Add(e) => write!(f, "{} ({})", self.message_id(), e.as_str()),
            _ => f.write_str(self.message_id()),
        }
    }
}

impl std::error::Error for StoreError {}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// UI language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Locale {
    #[default]
    #[serde(rename = "system")]
    System,
    #[serde(rename = "zh-TW")]
    ZhTw,
    #[serde(rename = "en")]
    En,
}

impl Locale {
    pub fn as_str(self) -> &'static str {
        match self {
            Locale::System => "system",
            Locale::ZhTw => "zh-TW",
            Locale::En => "en",
        }
    }

    /// `"system"`, `"zh-TW"` or `"en"` (exact).
    pub fn parse(s: &str) -> Option<Self> {
        [Locale::System, Locale::ZhTw, Locale::En]
            .into_iter()
            .find(|l| l.as_str() == s)
    }
}

/// UI theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Theme {
    #[default]
    #[serde(rename = "system")]
    System,
    #[serde(rename = "light")]
    Light,
    #[serde(rename = "dark")]
    Dark,
}

impl Theme {
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    /// `"system"`, `"light"` or `"dark"` (exact).
    pub fn parse(s: &str) -> Option<Self> {
        [Theme::System, Theme::Light, Theme::Dark]
            .into_iter()
            .find(|t| t.as_str() == s)
    }
}

/// App settings (`settings.json`). Holds no secret and no clipboard content.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Settings {
    pub locale: Locale,
    pub theme: Theme,
    pub onboarding_done: bool,
    /// App version that last ran (for "what's new" / re-grant prompts).
    pub last_version: Option<String>,
}

impl Settings {
    /// Parses `settings.json`. Missing fields and unknown keys take defaults
    /// silently; a field with an invalid value takes its default and is
    /// reported (first one only); unparsable text gives all defaults plus an
    /// error.
    pub fn from_json(text: &str) -> (Settings, Option<StoreError>) {
        let corrupt = |field| {
            Some(StoreError::Corrupt {
                file: StoreFile::Settings,
                field,
            })
        };
        let mut s = Settings::default();
        let obj = match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(obj)) => obj,
            _ => return (s, corrupt(None)),
        };
        let mut err = None;
        if let Some(v) = obj.get("locale") {
            match v.as_str().and_then(Locale::parse) {
                Some(l) => s.locale = l,
                None => err = err.or(corrupt(Some("locale"))),
            }
        }
        if let Some(v) = obj.get("theme") {
            match v.as_str().and_then(Theme::parse) {
                Some(t) => s.theme = t,
                None => err = err.or(corrupt(Some("theme"))),
            }
        }
        if let Some(v) = obj.get("onboarding_done") {
            match v.as_bool() {
                Some(b) => s.onboarding_done = b,
                None => err = err.or(corrupt(Some("onboarding_done"))),
            }
        }
        match obj.get("last_version") {
            None | Some(Value::Null) => {}
            Some(Value::String(v))
                if !v.is_empty()
                    && v.chars().count() <= LAST_VERSION_MAX_CHARS
                    && !v.chars().any(char::is_control) =>
            {
                s.last_version = Some(v.clone());
            }
            Some(_) => err = err.or(corrupt(Some("last_version"))),
        }
        (s, err)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_owned())
    }
}

// ---------------------------------------------------------------------------
// Key backend
// ---------------------------------------------------------------------------

/// Where the 32-byte HMAC key lives ([`KEYRING_SERVICE`] /
/// [`KEYRING_ACCOUNT`]).
pub trait KeyBackend {
    /// The stored key; `Ok(None)` only when there is no entry at all.
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyBackendError>;
    /// Stores a new key (called only after `get` returned `Ok(None)`).
    fn create(&self, key: &[u8]) -> Result<(), KeyBackendError>;
}

/// The OS keyring through the `keyring` crate: Windows Credential Manager,
/// macOS Keychain, Linux Secret Service.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringBackend;

impl KeyringBackend {
    fn entry() -> Result<keyring::Entry, KeyBackendError> {
        keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).map_err(map_keyring_error)
    }
}

impl KeyBackend for KeyringBackend {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyBackendError> {
        match Self::entry()?.get_secret() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring_error(e)),
        }
    }

    fn create(&self, key: &[u8]) -> Result<(), KeyBackendError> {
        Self::entry()?.set_secret(key).map_err(map_keyring_error)
    }
}

/// Maps a keyring error to a kind, wiping any secret bytes it carries.
fn map_keyring_error(e: keyring::Error) -> KeyBackendError {
    match e {
        keyring::Error::NoDefaultStore | keyring::Error::NotSupportedByStore(_) => {
            KeyBackendError::Unavailable
        }
        keyring::Error::NoStorageAccess(_) => KeyBackendError::AccessDenied,
        keyring::Error::BadEncoding(mut v) | keyring::Error::BadDataFormat(mut v, _) => {
            v.zeroize();
            KeyBackendError::Corrupt
        }
        keyring::Error::Ambiguous(_) | keyring::Error::BadStoreFormat(_) => {
            KeyBackendError::Corrupt
        }
        _ => KeyBackendError::Platform,
    }
}

/// In-memory [`KeyBackend`] for tests (never touches the OS keyring).
#[derive(Debug, Default)]
pub struct MemoryKeyBackend {
    key: Mutex<Option<Zeroizing<Vec<u8>>>>,
    fail: Option<KeyBackendError>,
}

impl MemoryKeyBackend {
    /// Empty: the first [`Store::load_secrets`] creates a key.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-filled with `key` (any length, to test corrupt keys).
    pub fn with_key(key: &[u8]) -> Self {
        MemoryKeyBackend {
            key: Mutex::new(Some(Zeroizing::new(key.to_vec()))),
            fail: None,
        }
    }

    /// Every call fails with `e`.
    pub fn failing(e: KeyBackendError) -> Self {
        MemoryKeyBackend {
            key: Mutex::new(None),
            fail: Some(e),
        }
    }

    /// Whether a key is stored.
    pub fn has_key(&self) -> bool {
        self.key.lock().map(|k| k.is_some()).unwrap_or(false)
    }

    /// Drops the stored key (simulates a wiped keyring).
    pub fn clear(&self) {
        if let Ok(mut k) = self.key.lock() {
            *k = None;
        }
    }
}

impl KeyBackend for MemoryKeyBackend {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyBackendError> {
        if let Some(e) = self.fail {
            return Err(e);
        }
        let k = self.key.lock().map_err(|_| KeyBackendError::Platform)?;
        Ok(k.clone())
    }

    fn create(&self, key: &[u8]) -> Result<(), KeyBackendError> {
        if let Some(e) = self.fail {
            return Err(e);
        }
        let mut k = self.key.lock().map_err(|_| KeyBackendError::Platform)?;
        *k = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }
}

impl<T: KeyBackend + ?Sized> KeyBackend for &T {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyBackendError> {
        (**self).get()
    }
    fn create(&self, key: &[u8]) -> Result<(), KeyBackendError> {
        (**self).create(key)
    }
}

// ---------------------------------------------------------------------------
// Directories
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirOs {
    Windows,
    MacOs,
    /// Linux and other XDG systems.
    Xdg,
}

const CURRENT_OS: DirOs = if cfg!(windows) {
    DirOs::Windows
} else if cfg!(target_os = "macos") {
    DirOs::MacOs
} else {
    DirOs::Xdg
};

fn non_empty(v: Option<OsString>) -> Option<PathBuf> {
    v.filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn data_dir_for(os: DirOs, env: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    match os {
        DirOs::Windows => non_empty(env("LOCALAPPDATA")).map(|d| d.join("PasteWarden")),
        DirOs::MacOs => non_empty(env("HOME")).map(|h| {
            h.join("Library")
                .join("Application Support")
                .join("PasteWarden")
        }),
        DirOs::Xdg => non_empty(env("XDG_DATA_HOME"))
            // The XDG spec says relative paths are invalid and must be ignored.
            .filter(|d| d.is_absolute())
            .or_else(|| non_empty(env("HOME")).map(|h| h.join(".local").join("share")))
            .map(|d| d.join("paste-warden")),
    }
}

/// The data directory: `%LOCALAPPDATA%\PasteWarden` (Windows),
/// `~/Library/Application Support/PasteWarden` (macOS),
/// `$XDG_DATA_HOME/paste-warden` or `~/.local/share/paste-warden` (others).
pub fn data_dir() -> Result<PathBuf, StoreError> {
    data_dir_for(CURRENT_OS, |k| std::env::var_os(k)).ok_or(StoreError::NoDataDir)
}

/// The legacy (C#) data directory `%LOCALAPPDATA%\ClipGuard`; `None` off
/// Windows (the legacy app was Windows-only) or without `LOCALAPPDATA`.
pub fn legacy_data_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        non_empty(std::env::var_os("LOCALAPPDATA")).map(|d| d.join("ClipGuard"))
    } else {
        None
    }
}

/// Deletes the [`LEGACY_FILES`] in `dir` (nothing else) and then `dir`
/// itself if it is empty (§4.5). Returns `true` when at least one legacy file
/// was deleted: show the "please register your secrets again" notice. A
/// second call returns `false`, so the notice shows once.
pub fn cleanup_legacy(dir: &Path) -> bool {
    let mut removed = false;
    for name in LEGACY_FILES {
        let path = dir.join(name);
        let is_file_like = fs::symlink_metadata(&path).is_ok_and(|m| !m.is_dir());
        if is_file_like && fs::remove_file(&path).is_ok() {
            removed = true;
        }
    }
    // `remove_dir` refuses a non-empty directory, which is what we want.
    let _ = fs::remove_dir(dir);
    removed
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// On-disk layout of `secrets.json`. `hmac` is lowercase hex.
#[derive(Serialize, Deserialize)]
struct SecretsFile {
    version: u32,
    entries: Vec<SecretRecord>,
}

#[derive(Serialize, Deserialize)]
struct SecretRecord {
    id: u64,
    label: String,
    length: usize,
    hmac: String,
    created_at_ms: u64,
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0xf)]));
    }
    s
}

fn from_hex(s: &str) -> Option<[u8; HMAC_LENGTH]> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let bytes = s.as_bytes();
    if bytes.len() != HMAC_LENGTH * 2 {
        return None;
    }
    let mut out = [0u8; HMAC_LENGTH];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (o, &[hi, lo]) in out.iter_mut().zip(pairs) {
        *o = (digit(hi)? << 4) | digit(lo)?;
    }
    Some(out)
}

fn parse_secrets(text: &str) -> Result<Vec<RegisteredSecret>, StoreError> {
    let corrupt = |field| StoreError::Corrupt {
        file: StoreFile::Secrets,
        field,
    };
    // serde's error text can quote values; it is dropped.
    let file: SecretsFile = serde_json::from_str(text).map_err(|_| corrupt(None))?;
    if file.version != SECRETS_VERSION {
        return Err(corrupt(Some("version")));
    }
    if file.entries.len() > MAX_REGISTERED_SECRETS {
        return Err(corrupt(Some("entries")));
    }
    let mut out: Vec<RegisteredSecret> = Vec::with_capacity(file.entries.len());
    for r in file.entries {
        if r.id == 0 || out.iter().any(|e| e.id == r.id) {
            return Err(corrupt(Some("id")));
        }
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&r.length) {
            return Err(corrupt(Some("length")));
        }
        if r.label.chars().count() > MAX_LABEL_LENGTH {
            return Err(corrupt(Some("label")));
        }
        let hmac = from_hex(&r.hmac).ok_or(corrupt(Some("hmac")))?;
        out.push(RegisteredSecret {
            id: r.id,
            label: r.label,
            length: r.length,
            hmac,
            created_at_ms: r.created_at_ms,
        });
    }
    Ok(out)
}

fn secrets_to_json(entries: &[RegisteredSecret]) -> String {
    let file = SecretsFile {
        version: SECRETS_VERSION,
        entries: entries
            .iter()
            .map(|e| SecretRecord {
                id: e.id,
                label: e.label.clone(),
                length: e.length,
                hmac: to_hex(&e.hmac),
                created_at_ms: e.created_at_ms,
            })
            .collect(),
    };
    // Compact: 100 entries with worst-case labels must stay under the cap.
    serde_json::to_string(&file).unwrap_or_default()
}

/// Settings and registered secrets in one data directory, with the HMAC key
/// in a [`KeyBackend`].
#[derive(Debug)]
pub struct Store<K: KeyBackend = KeyringBackend> {
    dir: PathBuf,
    keys: K,
}

impl Store<KeyringBackend> {
    /// The real store: [`data_dir`] and the OS keyring. Creates nothing yet.
    pub fn open_default() -> Result<Self, StoreError> {
        Ok(Store::new(data_dir()?, KeyringBackend))
    }
}

impl<K: KeyBackend> Store<K> {
    /// A store in `dir` (created on the first save) using `keys`.
    pub fn new(dir: impl Into<PathBuf>, keys: K) -> Self {
        Store {
            dir: dir.into(),
            keys,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, file: StoreFile) -> PathBuf {
        match file {
            StoreFile::DataDir => self.dir.clone(),
            f => self.dir.join(f.name()),
        }
    }

    /// `Ok(None)` when the file does not exist.
    fn read(&self, file: StoreFile) -> Result<Option<String>, StoreError> {
        let io_err = |e: io::Error| StoreError::Io {
            file,
            kind: e.kind(),
        };
        let f = match fs::File::open(self.path(file)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(e)),
        };
        let mut buf = Vec::new();
        f.take(STORE_FILE_MAX_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(io_err)?;
        if buf.len() > STORE_FILE_MAX_BYTES {
            return Err(StoreError::TooLarge { file });
        }
        String::from_utf8(buf)
            .map(Some)
            .map_err(|_| StoreError::Corrupt { file, field: None })
    }

    /// Writes `contents` to a temp file in the data directory, syncs it and
    /// renames it over `file`.
    fn write_atomic(&self, file: StoreFile, contents: &[u8]) -> Result<(), StoreError> {
        if contents.len() > STORE_FILE_MAX_BYTES {
            return Err(StoreError::TooLarge { file });
        }
        create_private_dir(&self.dir).map_err(|e| StoreError::Io {
            file: StoreFile::DataDir,
            kind: e.kind(),
        })?;
        let io_err = |e: io::Error| StoreError::Io {
            file,
            kind: e.kind(),
        };
        let target = self.path(file);
        let tmp = self
            .dir
            .join(format!(".{}.{}.tmp", file.name(), std::process::id()));
        let result = (|| {
            let mut f = open_private_file(&tmp)?;
            f.write_all(contents)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &target)
        })();
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp);
            return Err(io_err(e));
        }
        Ok(())
    }

    /// `settings.json`. Missing file: defaults, no error. Unreadable,
    /// oversize or corrupt: defaults (or per-field defaults) plus the error.
    pub fn load_settings(&self) -> (Settings, Option<StoreError>) {
        match self.read(StoreFile::Settings) {
            Ok(None) => (Settings::default(), None),
            Ok(Some(text)) => Settings::from_json(&text),
            Err(e) => (Settings::default(), Some(e)),
        }
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<(), StoreError> {
        self.write_atomic(StoreFile::Settings, settings.to_json().as_bytes())
    }

    /// `paste-guard.json` through core's [`PasteGuardSettings::from_json`]
    /// (result is sanitized). Same error policy as [`Self::load_settings`];
    /// the parser detail is dropped (it can quote values).
    pub fn load_paste_guard(&self) -> (PasteGuardSettings, Option<StoreError>) {
        match self.read(StoreFile::PasteGuard) {
            Ok(text) => {
                let (s, err) = PasteGuardSettings::from_json(text.as_deref());
                (
                    s,
                    err.map(|_| StoreError::Corrupt {
                        file: StoreFile::PasteGuard,
                        field: None,
                    }),
                )
            }
            Err(e) => (PasteGuardSettings::default(), Some(e)),
        }
    }

    /// Saves the sanitized settings.
    pub fn save_paste_guard(&self, settings: &PasteGuardSettings) -> Result<(), StoreError> {
        self.write_atomic(StoreFile::PasteGuard, settings.to_json().as_bytes())
    }

    /// The HMAC key: the stored one, or a fresh one when the keyring has no
    /// entry and there are no saved secrets that would need the old key.
    fn hmac_key(&self, have_entries: bool) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        match self.keys.get()? {
            Some(key) if key.len() == KEY_LENGTH => Ok(key),
            Some(_) => Err(StoreError::KeyCorrupt),
            None if have_entries => Err(StoreError::KeyMissing),
            None => {
                let mut key = Zeroizing::new(vec![0u8; KEY_LENGTH]);
                getrandom::fill(&mut key).map_err(|_| StoreError::Random)?;
                self.keys.create(&key)?;
                Ok(key)
            }
        }
    }

    /// The registered secrets with their HMAC key. Creates the key on first
    /// use (no `secrets.json` entries and no keyring entry). Corrupt or
    /// oversize `secrets.json` is an error (nothing is dropped silently).
    pub fn load_secrets(&self) -> Result<RegisteredSecretStore, StoreError> {
        let entries = match self.read(StoreFile::Secrets)? {
            None => Vec::new(),
            Some(text) => parse_secrets(&text)?,
        };
        let key = self.hmac_key(!entries.is_empty())?;
        RegisteredSecretStore::with_entries(&key, entries).map_err(|_| StoreError::KeyCorrupt)
    }

    pub fn save_secrets(&self, store: &RegisteredSecretStore) -> Result<(), StoreError> {
        self.save_entries(store.entries())
    }

    /// Saves `entries` as `secrets.json` (the desktop worker keeps its own
    /// [`RegisteredSecretStore`] and saves before committing a change).
    pub fn save_entries(&self, entries: &[RegisteredSecret]) -> Result<(), StoreError> {
        if entries.len() > MAX_REGISTERED_SECRETS {
            return Err(StoreError::TooManySecrets);
        }
        self.write_atomic(StoreFile::Secrets, secrets_to_json(entries).as_bytes())
    }

    /// Validates the dialog input (core's `validate_registration`), adds the
    /// secret (core's [`RegisteredSecretStore::add`]) and saves. Keep
    /// `secret` / `confirm` in `Zeroizing` on the caller side. Returns the
    /// new entry (no secret material besides its HMAC).
    pub fn register_secret(
        &self,
        label: Option<&str>,
        secret: &str,
        confirm: &str,
        now_ms: u64,
    ) -> Result<RegisteredSecret, StoreError> {
        validate_registration(secret, confirm).map_err(StoreError::Registration)?;
        let mut store = self.load_secrets()?;
        if store.entries().len() >= MAX_REGISTERED_SECRETS {
            return Err(StoreError::TooManySecrets);
        }
        let entry = store
            .add(label, secret, now_ms)
            .map_err(StoreError::Add)?
            .clone();
        self.save_secrets(&store)?;
        Ok(entry)
    }

    /// Removes one entry; `Ok(false)` when there is no such id.
    pub fn remove_secret(&self, id: u64) -> Result<bool, StoreError> {
        let mut store = self.load_secrets()?;
        if !store.remove(id) {
            return Ok(false);
        }
        self.save_secrets(&store)?;
        Ok(true)
    }

    /// Deletes `secrets.json` (the key stays). The way out of
    /// [`StoreError::KeyMissing`] or a corrupt file: the user registers again.
    pub fn forget_secrets(&self) -> Result<(), StoreError> {
        match fs::remove_file(self.path(StoreFile::Secrets)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io {
                file: StoreFile::Secrets,
                kind: e.kind(),
            }),
        }
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(unix)]
fn open_private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use paste_warden_core::policy::registered::RegistrationField;

    const SECRET: &str = "TestOnly-Secret-424242";

    fn store(keys: &MemoryKeyBackend) -> (tempfile::TempDir, Store<&MemoryKeyBackend>) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::new(dir.path().join("data"), keys);
        (dir, s)
    }

    fn write(s: &Store<&MemoryKeyBackend>, file: StoreFile, contents: &[u8]) {
        fs::create_dir_all(s.dir()).unwrap();
        fs::write(s.path(file), contents).unwrap();
    }

    #[test]
    fn settings_round_trip_and_defaults() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        assert_eq!(s.load_settings(), (Settings::default(), None));
        let v = Settings {
            locale: Locale::ZhTw,
            theme: Theme::Dark,
            onboarding_done: true,
            last_version: Some("0.4.0".into()),
        };
        s.save_settings(&v).unwrap();
        assert_eq!(s.load_settings(), (v.clone(), None));
        let text = fs::read_to_string(s.path(StoreFile::Settings)).unwrap();
        assert!(text.contains("\"zh-TW\"") && text.contains("\"dark\""));
        // No temp file is left behind.
        let names: Vec<_> = fs::read_dir(s.dir()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn settings_corrupt_and_invalid_fields() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        write(&s, StoreFile::Settings, b"{not json");
        let (v, e) = s.load_settings();
        assert_eq!(v, Settings::default());
        assert_eq!(
            e,
            Some(StoreError::Corrupt {
                file: StoreFile::Settings,
                field: None
            })
        );

        write(
            &s,
            StoreFile::Settings,
            br#"{"locale":"fr","theme":"light","onboarding_done":true,"extra":1}"#,
        );
        let (v, e) = s.load_settings();
        assert_eq!(v.locale, Locale::System);
        assert_eq!(v.theme, Theme::Light);
        assert!(v.onboarding_done);
        assert_eq!(
            e,
            Some(StoreError::Corrupt {
                file: StoreFile::Settings,
                field: Some("locale")
            })
        );

        let long = "9".repeat(LAST_VERSION_MAX_CHARS + 1);
        let (v, e) = Settings::from_json(&format!(r#"{{"last_version":"{long}"}}"#));
        assert_eq!(v.last_version, None);
        assert!(e.is_some());
        assert_eq!(Settings::from_json("[]").0, Settings::default());
        assert!(Settings::from_json("{}").1.is_none());
    }

    #[test]
    fn oversize_file_is_corrupt() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        let big = vec![b' '; STORE_FILE_MAX_BYTES + 1];
        for file in [
            StoreFile::Settings,
            StoreFile::PasteGuard,
            StoreFile::Secrets,
        ] {
            write(&s, file, &big);
        }
        assert_eq!(
            s.load_settings().1,
            Some(StoreError::TooLarge {
                file: StoreFile::Settings
            })
        );
        let (pg, e) = s.load_paste_guard();
        assert_eq!(pg, PasteGuardSettings::default());
        assert_eq!(
            e,
            Some(StoreError::TooLarge {
                file: StoreFile::PasteGuard
            })
        );
        assert_eq!(
            s.load_secrets().unwrap_err(),
            StoreError::TooLarge {
                file: StoreFile::Secrets
            }
        );
        // A corrupt secrets file never creates a key.
        assert!(!keys.has_key());
        // Exactly at the cap is fine.
        write(&s, StoreFile::Settings, &vec![b' '; STORE_FILE_MAX_BYTES]);
        assert!(matches!(
            s.load_settings().1,
            Some(StoreError::Corrupt { field: None, .. })
        ));
    }

    #[test]
    fn non_utf8_is_corrupt() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        write(&s, StoreFile::Settings, &[0xff, 0xfe, b'{']);
        assert!(matches!(
            s.load_settings().1,
            Some(StoreError::Corrupt {
                file: StoreFile::Settings,
                ..
            })
        ));
    }

    #[test]
    fn paste_guard_round_trip_and_corrupt() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        assert_eq!(s.load_paste_guard(), (PasteGuardSettings::default(), None));
        let v = PasteGuardSettings {
            intercept_registered: false,
            intercept_detected: true,
            allowed_apps: vec!["KeePassXC.exe".into(), "keepassxc".into()],
        };
        s.save_paste_guard(&v).unwrap();
        let (loaded, e) = s.load_paste_guard();
        assert!(e.is_none());
        assert_eq!(loaded, v.sanitized());

        write(
            &s,
            StoreFile::PasteGuard,
            br#"{"intercept_detected":"yes-please"}"#,
        );
        let (loaded, e) = s.load_paste_guard();
        assert_eq!(loaded, PasteGuardSettings::default());
        let e = e.unwrap();
        assert_eq!(
            e,
            StoreError::Corrupt {
                file: StoreFile::PasteGuard,
                field: None
            }
        );
        // The parser detail (which quotes the value) is not carried.
        assert!(!format!("{e:?}{e}").contains("yes-please"));
    }

    #[test]
    fn first_run_creates_key_and_secrets_persist() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        assert!(s.load_secrets().unwrap().entries().is_empty());
        assert!(keys.has_key());

        let e = s
            .register_secret(Some(" pin "), SECRET, SECRET, 1_000)
            .unwrap();
        assert_eq!((e.id, e.label.as_str(), e.created_at_ms), (1, "pin", 1_000));

        // Another Store over the same dir and keyring sees and matches it.
        let s2 = Store::new(s.dir().to_path_buf(), &keys);
        let loaded = s2.load_secrets().unwrap();
        assert_eq!(loaded.entries(), std::slice::from_ref(&e));
        assert_eq!(loaded.find(&format!("x {SECRET} y")).len(), 1);

        // Only the HMAC is on disk.
        let text = fs::read_to_string(s.path(StoreFile::Secrets)).unwrap();
        assert!(!text.contains(SECRET));
        assert!(text.contains(&to_hex(&e.hmac)));

        assert_eq!(
            s.register_secret(None, SECRET, SECRET, 0),
            Err(StoreError::Add(AddError::AlreadyRegistered))
        );
        assert_eq!(s.remove_secret(e.id), Ok(true));
        assert_eq!(s.remove_secret(e.id), Ok(false));
        assert!(s.load_secrets().unwrap().entries().is_empty());
    }

    #[test]
    fn registration_errors_carry_no_value() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        let err = s
            .register_secret(None, SECRET, "TestOnly-Secret-000000", 0)
            .unwrap_err();
        match &err {
            StoreError::Registration(r) => assert_eq!(r.field, RegistrationField::Confirm),
            other => panic!("unexpected {other:?}"),
        }
        let shown = format!("{err:?} {err} {:?}", err.message());
        assert!(!shown.contains("TestOnly"));
        assert!(!s.path(StoreFile::Secrets).exists());
    }

    #[test]
    fn missing_key_with_entries_is_not_regenerated() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        s.register_secret(None, SECRET, SECRET, 0).unwrap();
        keys.clear();
        assert_eq!(s.load_secrets().unwrap_err(), StoreError::KeyMissing);
        assert!(!keys.has_key());
        assert_eq!(
            s.register_secret(None, "another-secret", "another-secret", 0),
            Err(StoreError::KeyMissing)
        );
        // The way out: forget the secrets, then a new key is created.
        s.forget_secrets().unwrap();
        s.forget_secrets().unwrap();
        assert!(s.load_secrets().unwrap().entries().is_empty());
        assert!(keys.has_key());
    }

    #[test]
    fn keyring_errors_are_errors() {
        let keys = MemoryKeyBackend::with_key(&[1u8; 16]);
        let (_t, s) = store(&keys);
        assert_eq!(s.load_secrets().unwrap_err(), StoreError::KeyCorrupt);

        for (backend, expected) in [
            (KeyBackendError::Unavailable, StoreError::KeyUnavailable),
            (KeyBackendError::AccessDenied, StoreError::KeyAccessDenied),
            (KeyBackendError::Corrupt, StoreError::KeyCorrupt),
            (KeyBackendError::Platform, StoreError::KeyPlatform),
        ] {
            let keys = MemoryKeyBackend::failing(backend);
            let (_t, s) = store(&keys);
            assert_eq!(s.load_secrets().unwrap_err(), expected);
            assert!(!keys.has_key());
        }

        let reason = StoreError::KeyUnavailable.status_reason();
        if cfg!(target_os = "linux") {
            assert_eq!(reason, Some(Reason::NoSecretService));
        } else {
            assert_eq!(reason, None);
        }
        assert_eq!(StoreError::KeyPlatform.status_reason(), None);
    }

    #[test]
    fn corrupt_secrets_file() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        let hmac = "ab".repeat(HMAC_LENGTH);
        let entry = |id: u64, length: usize, hmac: &str| {
            format!(
                r#"{{"id":{id},"label":"","length":{length},"hmac":"{hmac}","created_at_ms":0}}"#
            )
        };
        let cases: [(String, Option<&str>); 6] = [
            ("nope".into(), None),
            (r#"{"version":2,"entries":[]}"#.into(), Some("version")),
            (
                format!(r#"{{"version":1,"entries":[{}]}}"#, entry(1, 3, &hmac)),
                Some("length"),
            ),
            (
                format!(r#"{{"version":1,"entries":[{}]}}"#, entry(1, 8, "zz")),
                Some("hmac"),
            ),
            (
                format!(
                    r#"{{"version":1,"entries":[{},{}]}}"#,
                    entry(1, 8, &hmac),
                    entry(1, 9, &hmac)
                ),
                Some("id"),
            ),
            (
                format!(r#"{{"version":1,"entries":[{}]}}"#, entry(0, 8, &hmac)),
                Some("id"),
            ),
        ];
        for (text, field) in cases {
            write(&s, StoreFile::Secrets, text.as_bytes());
            assert_eq!(
                s.load_secrets().unwrap_err(),
                StoreError::Corrupt {
                    file: StoreFile::Secrets,
                    field
                },
                "{text}"
            );
        }
        assert!(!keys.has_key());
    }

    #[test]
    fn registration_limit_and_worst_case_size() {
        let keys = MemoryKeyBackend::new();
        let (_t, s) = store(&keys);
        let mut reg = s.load_secrets().unwrap();
        // Worst-case labels: control chars JSON-escape to 6 bytes each.
        let label: String = std::iter::repeat_n('\u{1}', MAX_LABEL_LENGTH).collect();
        for i in 0..MAX_REGISTERED_SECRETS {
            reg.add(Some(&label), &format!("secret-{i:04}"), u64::MAX)
                .unwrap();
        }
        let json = secrets_to_json(reg.entries());
        assert!(json.len() <= STORE_FILE_MAX_BYTES, "{}", json.len());
        s.save_secrets(&reg).unwrap();
        assert_eq!(s.load_secrets().unwrap().entries().len(), 100);
        assert_eq!(
            s.register_secret(None, "one-too-many", "one-too-many", 0),
            Err(StoreError::TooManySecrets)
        );
    }

    #[test]
    fn hex_round_trip() {
        let bytes: [u8; HMAC_LENGTH] = std::array::from_fn(|i| (i * 8) as u8);
        assert_eq!(from_hex(&to_hex(&bytes)), Some(bytes));
        assert_eq!(from_hex(&to_hex(&bytes).to_uppercase()), Some(bytes));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex(&"g0".repeat(HMAC_LENGTH)), None);
        assert_eq!(from_hex(&"é".repeat(HMAC_LENGTH)), None);
    }

    #[test]
    fn legacy_cleanup_deletes_only_listed_files() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("ClipGuard");
        fs::create_dir_all(dir.join("paste-guard.json")).unwrap(); // a dir, kept
        for f in ["secrets.json", "key.bin", "notes.txt"] {
            fs::write(dir.join(f), b"x").unwrap();
        }
        assert!(cleanup_legacy(&dir));
        assert!(!dir.join("secrets.json").exists());
        assert!(!dir.join("key.bin").exists());
        assert!(dir.join("notes.txt").exists());
        assert!(dir.join("paste-guard.json").is_dir());
        // Notice once: nothing left to delete.
        assert!(!cleanup_legacy(&dir));
        assert!(dir.exists());

        // Only listed files: the directory goes too.
        let dir2 = t.path().join("ClipGuard2");
        fs::create_dir_all(&dir2).unwrap();
        for f in LEGACY_FILES {
            fs::write(dir2.join(f), b"x").unwrap();
        }
        assert!(cleanup_legacy(&dir2));
        assert!(!dir2.exists());
        assert!(!cleanup_legacy(&dir2));
        assert!(t.path().exists());
    }

    #[test]
    fn data_dir_per_os() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(*v))
            }
        };
        let p = |s: &str| PathBuf::from(s);
        assert_eq!(
            data_dir_for(DirOs::Windows, env(&[("LOCALAPPDATA", "L")])),
            Some(p("L").join("PasteWarden"))
        );
        assert_eq!(data_dir_for(DirOs::Windows, env(&[("HOME", "H")])), None);
        assert_eq!(
            data_dir_for(DirOs::MacOs, env(&[("HOME", "H")])),
            Some(p("H").join("Library/Application Support/PasteWarden"))
        );
        assert_eq!(data_dir_for(DirOs::MacOs, env(&[("HOME", "")])), None);
        // Relative XDG_DATA_HOME is ignored.
        assert_eq!(
            data_dir_for(DirOs::Xdg, env(&[("XDG_DATA_HOME", "rel"), ("HOME", "H")])),
            Some(p("H").join(".local/share/paste-warden"))
        );
        #[cfg(unix)]
        assert_eq!(
            data_dir_for(
                DirOs::Xdg,
                env(&[("XDG_DATA_HOME", "/xdg"), ("HOME", "/h")])
            ),
            Some(p("/xdg/paste-warden"))
        );
        assert_eq!(data_dir_for(DirOs::Xdg, env(&[])), None);
    }

    #[test]
    fn error_messages() {
        let e = StoreError::Corrupt {
            file: StoreFile::Settings,
            field: Some("theme"),
        };
        assert_eq!(e.to_string(), "store-error-corrupt (settings.json: theme)");
        assert_eq!(e.message().id, "store-error-corrupt");
        assert_eq!(
            StoreError::Add(AddError::LengthOutOfRange).message().id,
            "registered-length-out-of-range"
        );
    }

    /// Touches the real OS keyring; run by hand only.
    #[test]
    #[ignore]
    fn real_keyring_get() {
        let _ = KeyringBackend.get();
    }
}
