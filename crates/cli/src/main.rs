//! `paste-warden` executable; see the library crate `paste_warden_cli`.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    paste_warden_cli::install_quiet_panic_hook();
    ExitCode::from(paste_warden_cli::cli::main_with_args(std::env::args_os()))
}
