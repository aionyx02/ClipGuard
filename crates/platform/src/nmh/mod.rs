//! Native Messaging bridge between the browser extension and the desktop app
//! (docs/plan/phase-4.md §4.3, §4.4; docs/spikes/s9-native-messaging.md).
//!
//! ```text
//! extension ──stdio──▶ paste-warden-nmh ──IPC──▶ desktop app (DesktopHandler)
//! ```
//!
//! - [`frame`]: 4-byte native-endian length + JSON, size-checked before
//!   allocating
//! - [`protocol`]: the ops (`hello`, `policy.get`, `verdict`,
//!   `match_registered`), validation, desktop [`protocol::Response`]
//! - [`host`]: the `paste-warden-nmh` loop and argv caller check
//! - [`ipc`]: Unix socket / named pipe client and server ([`ipc::serve`])
//! - [`install`]: manifests and their user-level install / uninstall
//!
//! The extension and the desktop app each work fully alone; this bridge only
//! adds to them. No op reads the clipboard or a secret, and no message
//! carries clipboard text, unmasked secrets, URLs (host only) or the HMAC key
//! (T16).

pub mod frame;
pub mod host;
pub mod install;
pub mod ipc;
pub mod protocol;

pub use ipc::{DesktopHandler, IPC_TIMEOUT_MS, IpcClient, IpcError, IpcServer, serve};
pub use protocol::{
    Envelope, ErrorCode, ExtInfo, NMH_OPS, Op, Policy, RegisteredHmac, Request, Response, Severity,
    Verdict, VerdictAction,
};

/// Host name in manifests and `connectNative` / `sendNativeMessage`.
pub const NMH_NAME: &str = "org.pastewarden.nmh";
/// Protocol version carried as `v` in every message.
pub const NMH_PROTOCOL_VERSION: u32 = 1;
/// Oldest extension protocol the host accepts (`hello` → `host.min_ext`).
pub const NMH_MIN_EXT_PROTOCOL: u32 = 1;
/// Largest message either way; a bigger length prefix ends the host before
/// anything is allocated.
pub const NMH_MAX_MESSAGE_BYTES: usize = 65_536;
/// The browsers' own host → extension limit (documentation only, S9).
pub const BROWSER_HOST_MESSAGE_LIMIT_BYTES: usize = 1_048_576;
/// Capabilities the host advertises in `hello`.
pub const HOST_CAPS: [&str; 3] = ["policy", "verdict", "match_registered"];

/// Chrome / Edge / Chromium extension ids, fixed by the manifest `key` in
/// `apps/extension/wxt.config.ts` (phase-4.md §4.5). No wildcards.
pub const ALLOWED_CHROMIUM_EXTENSION_IDS: [&str; 1] = ["nlbcepabhjkfeklnkbnjiibkfepmmmba"];
/// Firefox add-on ids (`browser_specific_settings.gecko.id`).
pub const ALLOWED_GECKO_IDS: [&str; 1] = ["paste-warden@aionyx02.github.io"];
