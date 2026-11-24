//! Command-line definition and dispatch (phase-2.md §2.3).
//!
//! The CLI never reads the clipboard (it would be an exfiltration channel) and
//! error messages never contain the input (P3).

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use paste_warden_core::Context;
use paste_warden_i18n::Localizer;

use crate::hook::install::{self, Agent, InstallEnv, InstallOptions, Outcome, Scope};
use crate::l10n::{parse_locale, process_locale, t};
use crate::report_json::ReportJson;
use crate::scan::{self, Colors, EXIT_ERROR};
use crate::{hook, mcp};

#[derive(Debug, Parser)]
#[command(
    name = "paste-warden",
    version,
    about = "PasteWarden（剪貼簿守門員）: detect ClickFix commands, hidden characters and secrets; agent hooks and MCP server."
)]
pub struct Cli {
    /// Output language: zh-TW or en (default: from LC_ALL / LC_MESSAGES / LANG).
    #[arg(long, global = true)]
    pub locale: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyze a file or stdin. Exit code: 0 allow, 1 warn, 2 quarantine, 3 error.
    Scan {
        /// File to analyze; `-` or nothing reads stdin.
        file: Option<PathBuf>,
        /// Print the Report JSON (docs/plan/phase-2.md §2.2).
        #[arg(long)]
        json: bool,
        /// PII packs, comma separated (e.g. tw,us). Default: universal + tw.
        #[arg(long, value_delimiter = ',')]
        packs: Vec<String>,
    },
    /// Print the text with every detected secret masked.
    Mask {
        /// File to mask; `-` or nothing reads stdin.
        file: Option<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        packs: Vec<String>,
    },
    /// Agent hooks (enforcement).
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },
    /// Read-only stdio MCP server (analysis and explanation).
    Mcp {
        /// Tool profile. Only `guard` exists before Phase 5.
        #[arg(long, value_enum, default_value_t = Profile::Guard)]
        profile: Profile,
        /// Print the config snippet that registers this server with an agent, then exit.
        #[arg(long, value_enum)]
        print_config: Option<Agent>,
    },
    /// Evaluate a JSONL file of {"id", "text"} lines; prints one JSON result per
    /// line and a final {"summary": …} line.
    Bench {
        file: PathBuf,
        #[arg(long, value_delimiter = ',')]
        packs: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    Guard,
    Redteam,
}

#[derive(Debug, Subcommand)]
pub enum HookCommand {
    /// Claude Code PreToolUse / UserPromptSubmit hook (JSON on stdin).
    ClaudeCode {
        /// Internal timeout in milliseconds; exceeding it denies.
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
    },
    /// Called by the generated opencode plugin ({"tool", "args"} on stdin).
    Opencode {
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
    },
    /// Install the hook into the agent's settings (merges, backs up first).
    Install {
        #[arg(value_enum)]
        agent: Agent,
        #[arg(long, value_enum, default_value_t = Scope::User)]
        scope: Scope,
        /// Print the difference only; write nothing.
        #[arg(long)]
        dry_run: bool,
        /// Project directory for --scope project (default: current directory).
        #[arg(long)]
        project_dir: Option<PathBuf>,
        /// Do not install the Claude Code UserPromptSubmit secret check.
        #[arg(long)]
        no_prompt_guard: bool,
    },
    /// Remove what `hook install` added.
    Uninstall {
        #[arg(value_enum)]
        agent: Agent,
        #[arg(long, value_enum, default_value_t = Scope::User)]
        scope: Scope,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        project_dir: Option<PathBuf>,
    },
}

/// Parses `args` and runs; returns the process exit code. Usage errors exit
/// with 3 (2 means "quarantine" for `scan`).
pub fn main_with_args<I, T>(args: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
                _ => EXIT_ERROR,
            };
        }
    };
    run(cli)
}

fn out(s: &str) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(s.as_bytes());
    if !s.ends_with('\n') {
        let _ = o.write_all(b"\n");
    }
    let _ = o.flush();
}

fn err(s: &str) {
    let mut e = std::io::stderr().lock();
    let _ = writeln!(e, "{}", s.trim_end());
}

pub fn run(cli: Cli) -> u8 {
    let locale = cli
        .locale
        .as_deref()
        .map_or_else(process_locale, parse_locale);
    let l10n = Localizer::new(locale);
    match cli.command {
        Command::Scan { file, json, packs } => {
            let text = match scan::read_input(file.as_deref(), &l10n) {
                Ok(t) => t,
                Err(e) => {
                    err(&e);
                    return EXIT_ERROR;
                }
            };
            let report = scan::engine(&packs).analyze(&text, &Context::default());
            let rj = ReportJson::new(&report, &text, &l10n);
            if json {
                out(&serde_json::to_string_pretty(&rj).unwrap_or_default());
            } else {
                let colors = Colors {
                    on: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
                };
                out(&scan::render_human(&rj, &report, &l10n, colors));
            }
            scan::exit_code(report.action)
        }
        Command::Mask { file, packs } => {
            let text = match scan::read_input(file.as_deref(), &l10n) {
                Ok(t) => t,
                Err(e) => {
                    err(&e);
                    return EXIT_ERROR;
                }
            };
            let masked = mcp::mask_all(&text, &packs, &l10n);
            let mut o = std::io::stdout().lock();
            let _ = o.write_all(masked.as_bytes());
            let _ = o.flush();
            0
        }
        Command::Bench { file, packs } => {
            let text = match scan::read_input(Some(&file), &l10n) {
                Ok(t) => t,
                Err(e) => {
                    err(&e);
                    return EXIT_ERROR;
                }
            };
            let (lines, errors) = scan::bench(&text, &scan::engine(&packs), &l10n);
            for e in &errors {
                err(e);
            }
            out(&lines.join("\n"));
            0
        }
        Command::Mcp {
            profile,
            print_config,
        } => {
            if profile == Profile::Redteam {
                err(&t(&l10n, "cli-mcp-redteam-later", &[]));
                return EXIT_ERROR;
            }
            if let Some(agent) = print_config {
                let exe = install::exe_path().unwrap_or_else(|_| "paste-warden".into());
                out(&mcp::print_config(agent, &exe));
                return 0;
            }
            match mcp::serve(locale) {
                Ok(()) => 0,
                Err(e) => {
                    err(&format!("paste-warden mcp: {e}"));
                    EXIT_ERROR
                }
            }
        }
        Command::Hook { command } => run_hook(command, &l10n),
    }
}

fn emit(h: hook::HookOutput) -> u8 {
    if let Some(s) = &h.stdout {
        out(s);
    }
    if let Some(s) = &h.stderr {
        err(s);
    }
    u8::try_from(h.code).unwrap_or(EXIT_ERROR)
}

fn run_hook(command: HookCommand, l10n: &Localizer) -> u8 {
    let fault = || std::env::var(hook::FAULT_ENV).ok();
    match command {
        HookCommand::ClaudeCode { timeout_ms } => emit(hook::claude_code(
            Duration::from_millis(timeout_ms),
            fault(),
        )),
        HookCommand::Opencode { timeout_ms } => {
            emit(hook::opencode(Duration::from_millis(timeout_ms), fault()))
        }
        HookCommand::Install {
            agent,
            scope,
            dry_run,
            project_dir,
            no_prompt_guard,
        } => {
            let opts = InstallOptions {
                agent,
                scope,
                dry_run,
                prompt_guard: !no_prompt_guard,
            };
            if agent == Agent::Opencode {
                match std::process::Command::new("opencode")
                    .arg("--version")
                    .output()
                {
                    Ok(o) => {
                        let v = String::from_utf8_lossy(&o.stdout).trim().to_owned();
                        if install::opencode_major(&v).is_some_and(|m| m < 2) {
                            err(&t(
                                l10n,
                                "cli-install-opencode-too-old",
                                &[("version", v.into())],
                            ));
                            return EXIT_ERROR;
                        }
                    }
                    Err(_) => err(&t(l10n, "cli-install-opencode-unknown", &[])),
                }
            }
            if !hook::self_test() {
                err(&t(l10n, "cli-install-self-test-failed", &[]));
                return EXIT_ERROR;
            }
            install_like(&opts, project_dir, l10n, true)
        }
        HookCommand::Uninstall {
            agent,
            scope,
            dry_run,
            project_dir,
        } => {
            let opts = InstallOptions {
                agent,
                scope,
                dry_run,
                prompt_guard: true,
            };
            install_like(&opts, project_dir, l10n, false)
        }
    }
}

fn install_like(
    opts: &InstallOptions,
    project_dir: Option<PathBuf>,
    l10n: &Localizer,
    installing: bool,
) -> u8 {
    let env = match InstallEnv::from_process(project_dir) {
        Ok(e) => e,
        Err(e) => {
            err(&e.to_string());
            return EXIT_ERROR;
        }
    };
    let r = if installing {
        install::install(opts, &env, l10n)
    } else {
        install::uninstall(opts, &env, l10n)
    };
    match r {
        Ok((path, outcome)) => {
            if installing && !matches!(outcome, Outcome::DryRun(_)) {
                out(&t(l10n, "cli-install-self-test-ok", &[]));
            }
            for line in install::describe(opts, &path, &outcome, l10n, installing) {
                out(&line);
            }
            0
        }
        Err(e) => {
            err(&e.0);
            EXIT_ERROR
        }
    }
}
