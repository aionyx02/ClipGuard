//! Where a piece of clipboard text came from and where it is going.
//!
//! Supplied by the platform layer (foreground-app tracking, `org.chromium.source-url`
//! pasteboard metadata, the extension's page URL). The engine uses it only to
//! weigh risk and choose notification noise — never to downgrade a Malicious
//! verdict (P1, phase-1.md §1.5). URLs are private data: never log them.

/// Broad category of the app the text was copied from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SourceKind {
    #[default]
    Unknown,
    /// Chrome, Edge, Firefox, Safari, Arc, …
    Browser,
    /// Terminal emulators and shells.
    Terminal,
    /// Code editors and IDEs.
    Ide,
    /// Chat / messaging apps (LINE, Discord, Slack, Teams, …).
    Chat,
    /// Password managers (their copies are normally skipped entirely).
    PasswordManager,
    Other,
}

/// The app (and page) the text came from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Source {
    pub kind: SourceKind,
    /// Display name, e.g. "Google Chrome".
    pub app: Option<String>,
    /// macOS bundle id / Windows process name / Android package.
    pub app_id: Option<String>,
    /// Page URL when known (extension, pasteboard metadata).
    pub url: Option<String>,
}

/// Platform the engine runs for (affects which command dialects are likely).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Platform {
    #[default]
    Unknown,
    Windows,
    MacOs,
    Linux,
    Android,
    Ios,
    /// Browser extension / userscript / web page.
    Web,
}

/// Analysis context. `Context::default()` means "nothing known".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Context {
    pub source: Option<Source>,
    pub platform: Platform,
}
