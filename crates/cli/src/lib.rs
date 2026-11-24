//! `paste-warden` command line (phase-2.md §2.3–§2.5): scan, mask, agent
//! hooks, MCP server, bench.
//!
//! The binary (`src/main.rs`) is a thin wrapper around [`cli::main_with_args`];
//! the modules are a library so they can be tested directly.
//!
//! - [`report_json`]: the shared Report JSON (**reference for §2.2**)
//! - [`scan`]: `scan`, `mask`, `bench`
//! - [`hook`]: Claude Code / opencode hooks (fail-closed) and `hook install`
//! - [`mcp`]: stdio MCP server, `guard` profile
#![forbid(unsafe_code)]

pub mod cli;
pub mod hook;
pub mod l10n;
pub mod mcp;
pub mod report_json;
pub mod scan;

/// Replaces the default panic message (which could quote data) with a fixed
/// one. Hooks additionally turn panics into a deny.
pub fn install_quiet_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("paste-warden: internal error");
    }));
}
