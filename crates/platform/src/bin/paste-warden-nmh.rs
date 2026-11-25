//! `paste-warden-nmh`: the Native Messaging host the browser starts
//! (docs/plan/phase-4.md §4.3). A small binary on purpose (S9: spawning the
//! large desktop executable is too slow); it only relays validated requests
//! to the running desktop app and never starts the GUI.
//!
//! stdout carries only framed messages. Diagnostics go to stderr as one
//! fixed line, never message content. On Windows, Rust's std stdin / stdout
//! already do raw `ReadFile` / `WriteFile` with no newline or `0x1A`
//! translation (S9 Windows measurement), so no binary-mode switch is needed.

use std::io::{self, BufReader};
use std::process::ExitCode;

use paste_warden_platform::nmh::host::{self, DesktopLink, NoDesktop};
use paste_warden_platform::nmh::ipc::IpcClient;

/// Exit code when argv doesn't name an allowed extension.
const EXIT_BAD_CALLER: u8 = 3;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    if host::check_caller(&args).is_none() {
        eprintln!("paste-warden-nmh: caller not allowed");
        return ExitCode::from(EXIT_BAD_CALLER);
    }
    let client = IpcClient::new().ok();
    let desktop: &dyn DesktopLink = match &client {
        Some(c) => c,
        None => &NoDesktop,
    };
    let mut input = BufReader::new(io::stdin().lock());
    // Unbuffered: `write_frame` writes each frame in one call and flushes.
    let mut output = io::stdout().lock();
    let exit = host::run(&mut input, &mut output, desktop);
    if !matches!(exit, host::HostExit::Eof) {
        eprintln!("paste-warden-nmh: stopped ({})", exit.code());
    }
    ExitCode::from(exit.code())
}
