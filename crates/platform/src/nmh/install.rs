//! Native Messaging host manifests: generation, install, uninstall
//! (S9 "安裝位置", phase-4.md §4.3).
//!
//! User-level only, never system-wide:
//! - macOS / Linux: `<name>.json` in each detected browser's user
//!   `NativeMessagingHosts` directory.
//! - Windows: two manifest files (Chromium family, Firefox) under
//!   `%LOCALAPPDATA%\PasteWarden\NativeMessagingHosts\`, plus the four
//!   `HKCU\Software\{Google\Chrome,Microsoft\Edge,Chromium,Mozilla}\NativeMessagingHosts\org.pastewarden.nmh`
//!   keys whose default value is the manifest path.
//!
//! Install is idempotent: the desktop app can call it on every start, which
//! also picks up browsers installed later. Uninstall removes everything
//! install could have written.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::{ALLOWED_CHROMIUM_EXTENSION_IDS, ALLOWED_GECKO_IDS, NMH_NAME};

/// Manifest `description`.
pub const MANIFEST_DESCRIPTION: &str = "PasteWarden desktop bridge";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Browser {
    Chrome,
    Chromium,
    Edge,
    Brave,
    Firefox,
}

impl Browser {
    pub const ALL: [Self; 5] = [
        Self::Chrome,
        Self::Chromium,
        Self::Edge,
        Self::Brave,
        Self::Firefox,
    ];

    pub fn is_firefox(self) -> bool {
        self == Self::Firefox
    }
}

/// Which user-level layout to use (a parameter so both are testable on any
/// host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    MacOs,
    Linux,
}

impl Layout {
    /// The layout of the OS we run on, if it has one.
    pub fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum InstallError {
    /// The host path must be absolute (browsers require it).
    RelativeHostPath,
    /// `HOME` / `LOCALAPPDATA` unset or not absolute.
    NoHome,
    /// Not supported on this OS.
    Unsupported,
    Io(io::Error),
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeHostPath => f.write_str("native messaging host path must be absolute"),
            Self::NoHome => f.write_str("user home directory not found"),
            Self::Unsupported => f.write_str("native messaging install not supported here"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for InstallError {}

impl From<io::Error> for InstallError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Manifest file name (must equal the host `name`, S9).
pub fn manifest_file_name() -> String {
    format!("{NMH_NAME}.json")
}

/// The manifest for one browser family.
pub fn manifest_json(firefox: bool, host_path: &Path) -> Result<String, InstallError> {
    if !host_path.is_absolute() {
        return Err(InstallError::RelativeHostPath);
    }
    let path = host_path.to_string_lossy();
    let v = if firefox {
        json!({
            "name": NMH_NAME,
            "description": MANIFEST_DESCRIPTION,
            "path": path,
            "type": "stdio",
            "allowed_extensions": ALLOWED_GECKO_IDS,
        })
    } else {
        let origins: Vec<String> = ALLOWED_CHROMIUM_EXTENSION_IDS
            .iter()
            .map(|id| format!("chrome-extension://{id}/"))
            .collect();
        json!({
            "name": NMH_NAME,
            "description": MANIFEST_DESCRIPTION,
            "path": path,
            "type": "stdio",
            "allowed_origins": origins,
        })
    };
    Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
}

/// The browser's user data directory, whose existence means "installed".
pub fn browser_data_dir(browser: Browser, layout: Layout, home: &Path) -> PathBuf {
    let rel = match (layout, browser) {
        (Layout::MacOs, Browser::Chrome) => "Library/Application Support/Google/Chrome",
        (Layout::MacOs, Browser::Chromium) => "Library/Application Support/Chromium",
        (Layout::MacOs, Browser::Edge) => "Library/Application Support/Microsoft Edge",
        (Layout::MacOs, Browser::Brave) => {
            "Library/Application Support/BraveSoftware/Brave-Browser"
        }
        (Layout::MacOs, Browser::Firefox) => "Library/Application Support/Firefox",
        (Layout::Linux, Browser::Chrome) => ".config/google-chrome",
        (Layout::Linux, Browser::Chromium) => ".config/chromium",
        (Layout::Linux, Browser::Edge) => ".config/microsoft-edge",
        (Layout::Linux, Browser::Brave) => ".config/BraveSoftware/Brave-Browser",
        (Layout::Linux, Browser::Firefox) => ".mozilla",
    };
    home.join(rel)
}

/// User-level manifest directory (S9 table).
pub fn manifest_dir(browser: Browser, layout: Layout, home: &Path) -> PathBuf {
    match (layout, browser) {
        (Layout::MacOs, Browser::Firefox) => {
            home.join("Library/Application Support/Mozilla/NativeMessagingHosts")
        }
        (Layout::Linux, Browser::Firefox) => home.join(".mozilla/native-messaging-hosts"),
        _ => browser_data_dir(browser, layout, home).join("NativeMessagingHosts"),
    }
}

/// Writes the manifest for every detected browser under `home`; returns the
/// browsers written.
pub fn install_in(
    home: &Path,
    layout: Layout,
    host_path: &Path,
) -> Result<Vec<Browser>, InstallError> {
    let chromium = manifest_json(false, host_path)?;
    let firefox = manifest_json(true, host_path)?;
    let mut done = Vec::new();
    for b in Browser::ALL {
        if !browser_data_dir(b, layout, home).is_dir() {
            continue;
        }
        let dir = manifest_dir(b, layout, home);
        fs::create_dir_all(&dir)?;
        let body = if b.is_firefox() { &firefox } else { &chromium };
        fs::write(dir.join(manifest_file_name()), body)?;
        done.push(b);
    }
    Ok(done)
}

/// Removes our manifest from every browser's directory under `home`.
pub fn uninstall_in(home: &Path, layout: Layout) -> Result<(), InstallError> {
    for b in Browser::ALL {
        let file = manifest_dir(b, layout, home).join(manifest_file_name());
        match fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// The four HKCU keys (phase-4.md §4.3), relative to `HKEY_CURRENT_USER`.
pub fn windows_registry_keys() -> [(Browser, String); 4] {
    let key = |vendor: &str| format!(r"Software\{vendor}\NativeMessagingHosts\{NMH_NAME}");
    [
        (Browser::Chrome, key(r"Google\Chrome")),
        (Browser::Edge, key(r"Microsoft\Edge")),
        (Browser::Chromium, key("Chromium")),
        (Browser::Firefox, key("Mozilla")),
    ]
}

/// Windows manifest file for one family, inside `dir`.
pub fn windows_manifest_path(dir: &Path, firefox: bool) -> PathBuf {
    let family = if firefox { "firefox" } else { "chromium" };
    dir.join(format!("{NMH_NAME}.{family}.json"))
}

/// `%LOCALAPPDATA%\PasteWarden\NativeMessagingHosts`.
pub fn windows_manifest_dir(local_app_data: &Path) -> PathBuf {
    local_app_data
        .join("PasteWarden")
        .join("NativeMessagingHosts")
}

#[cfg(not(windows))]
fn home_dir() -> Result<PathBuf, InstallError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or(InstallError::NoHome)
}

/// Installs for the current user. Returns the browsers configured.
pub fn install(host_path: &Path) -> Result<Vec<Browser>, InstallError> {
    #[cfg(windows)]
    {
        win::install(host_path)
    }
    #[cfg(not(windows))]
    {
        let layout = Layout::current().ok_or(InstallError::Unsupported)?;
        install_in(&home_dir()?, layout, host_path)
    }
}

/// Removes everything [`install`] may have written for the current user.
pub fn uninstall() -> Result<(), InstallError> {
    #[cfg(windows)]
    {
        win::uninstall()
    }
    #[cfg(not(windows))]
    {
        let layout = Layout::current().ok_or(InstallError::Unsupported)?;
        uninstall_in(&home_dir()?, layout)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod win {
    use super::*;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
        RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW,
    };
    use windows::core::HSTRING;

    fn local_app_data() -> Result<PathBuf, InstallError> {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or(InstallError::NoHome)
    }

    fn check(e: WIN32_ERROR) -> Result<(), InstallError> {
        if e == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(InstallError::Io(io::Error::from_raw_os_error(e.0 as i32)))
        }
    }

    /// Sets the default value of `HKCU\<subkey>` to `value`.
    pub(super) fn set_default_value(subkey: &str, value: &Path) -> Result<(), InstallError> {
        let mut key = HKEY::default();
        // SAFETY: valid NUL-terminated strings; `key` receives an open key we
        // close below.
        check(unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                &HSTRING::from(subkey),
                None,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut key,
                None,
            )
        })?;
        let wide: Vec<u16> = value
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|u| u.to_le_bytes()).collect();
        // SAFETY: `key` is open; `bytes` is a NUL-terminated UTF-16 string.
        let r = check(unsafe { RegSetValueExW(key, None, None, REG_SZ, Some(&bytes)) });
        // SAFETY: `key` was opened above.
        let _ = unsafe { RegCloseKey(key) };
        r
    }

    pub(super) fn delete_key(subkey: &str) -> Result<(), InstallError> {
        // SAFETY: valid NUL-terminated string; our key has no subkeys.
        let e = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, &HSTRING::from(subkey)) };
        if e == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        check(e)
    }

    pub(super) fn install(host_path: &Path) -> Result<Vec<Browser>, InstallError> {
        let chromium = manifest_json(false, host_path)?;
        let firefox = manifest_json(true, host_path)?;
        let dir = windows_manifest_dir(&local_app_data()?);
        fs::create_dir_all(&dir)?;
        let chromium_path = windows_manifest_path(&dir, false);
        let firefox_path = windows_manifest_path(&dir, true);
        fs::write(&chromium_path, chromium)?;
        fs::write(&firefox_path, firefox)?;
        let mut done = Vec::new();
        for (b, key) in windows_registry_keys() {
            let path = if b.is_firefox() {
                &firefox_path
            } else {
                &chromium_path
            };
            set_default_value(&key, path)?;
            done.push(b);
        }
        Ok(done)
    }

    pub(super) fn uninstall() -> Result<(), InstallError> {
        for (_, key) in windows_registry_keys() {
            delete_key(&key)?;
        }
        let dir = windows_manifest_dir(&local_app_data()?);
        for firefox in [false, true] {
            match fs::remove_file(windows_manifest_path(&dir, firefox)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let _ = fs::remove_dir(&dir);
        Ok(())
    }
}

/// Registry helpers for the `#[ignore]` Windows integration test.
#[cfg(windows)]
#[doc(hidden)]
pub fn windows_set_default_value(subkey: &str, value: &Path) -> Result<(), InstallError> {
    win::set_default_value(subkey, value)
}

#[cfg(windows)]
#[doc(hidden)]
pub fn windows_delete_key(subkey: &str) -> Result<(), InstallError> {
    win::delete_key(subkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests() {
        let host = if cfg!(windows) {
            Path::new(r"C:\pw\paste-warden-nmh.exe")
        } else {
            Path::new("/Applications/PasteWarden.app/Contents/MacOS/paste-warden-nmh")
        };
        let c: serde_json::Value =
            serde_json::from_str(&manifest_json(false, host).unwrap()).unwrap();
        assert_eq!(c["name"], NMH_NAME);
        assert_eq!(c["type"], "stdio");
        assert_eq!(
            c["allowed_origins"][0],
            format!("chrome-extension://{}/", ALLOWED_CHROMIUM_EXTENSION_IDS[0])
        );
        assert!(c.get("allowed_extensions").is_none());
        let f: serde_json::Value =
            serde_json::from_str(&manifest_json(true, host).unwrap()).unwrap();
        assert_eq!(f["allowed_extensions"][0], ALLOWED_GECKO_IDS[0]);
        assert!(f.get("allowed_origins").is_none());
        assert!(matches!(
            manifest_json(false, Path::new("relative/host")),
            Err(InstallError::RelativeHostPath)
        ));
    }

    #[test]
    fn paths() {
        let home = Path::new("/home/u");
        assert_eq!(
            manifest_dir(Browser::Firefox, Layout::Linux, home),
            Path::new("/home/u/.mozilla/native-messaging-hosts")
        );
        assert_eq!(
            manifest_dir(Browser::Chrome, Layout::Linux, home),
            Path::new("/home/u/.config/google-chrome/NativeMessagingHosts")
        );
        assert_eq!(
            manifest_dir(Browser::Edge, Layout::MacOs, home),
            Path::new("/home/u/Library/Application Support/Microsoft Edge/NativeMessagingHosts")
        );
        assert_eq!(
            manifest_dir(Browser::Firefox, Layout::MacOs, home),
            Path::new("/home/u/Library/Application Support/Mozilla/NativeMessagingHosts")
        );
        let keys = windows_registry_keys();
        assert_eq!(
            keys[0].1,
            r"Software\Google\Chrome\NativeMessagingHosts\org.pastewarden.nmh"
        );
        assert_eq!(
            keys[3].1,
            r"Software\Mozilla\NativeMessagingHosts\org.pastewarden.nmh"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_only_detected_browsers_then_uninstall() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        for layout in [Layout::MacOs, Layout::Linux] {
            fs::create_dir_all(browser_data_dir(Browser::Chromium, layout, home)).unwrap();
            fs::create_dir_all(browser_data_dir(Browser::Firefox, layout, home)).unwrap();
            let host = Path::new("/opt/pw/paste-warden-nmh");
            let done = install_in(home, layout, host).unwrap();
            assert_eq!(done, vec![Browser::Chromium, Browser::Firefox]);
            // Idempotent.
            assert_eq!(install_in(home, layout, host).unwrap(), done);
            let file = manifest_dir(Browser::Chromium, layout, home).join(manifest_file_name());
            let body: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(body["path"], "/opt/pw/paste-warden-nmh");
            assert!(!manifest_dir(Browser::Chrome, layout, home).exists());
            uninstall_in(home, layout).unwrap();
            assert!(!file.exists());
            assert!(
                !manifest_dir(Browser::Firefox, layout, home)
                    .join(manifest_file_name())
                    .exists()
            );
            uninstall_in(home, layout).unwrap();
        }
    }
}
