//! `paste-warden hook install|uninstall <claude-code|opencode>` (phase-2.md §2.4).
//!
//! - Claude Code: merges a `PreToolUse` and a `UserPromptSubmit` entry into
//!   `settings.json` (user: `~/.claude/` or `$CLAUDE_CONFIG_DIR`; project:
//!   `<dir>/.claude/`). Other keys and hooks are kept in order; our entries are
//!   recognized by their command (`… paste-warden … hook claude-code`), so a
//!   reinstall replaces them and uninstall removes only them. The file is
//!   backed up before every change (`settings.json.pw-bak`, then `.pw-bak.1`, …)
//!   and written atomically. A file that is not a plain JSON object (JSONC
//!   comments, syntax errors) is never touched.
//! - opencode: writes the V2 plugin `plugins/paste-warden.ts` (user:
//!   `$XDG_CONFIG_HOME/opencode` or `~/.config/opencode`; project:
//!   `<dir>/.opencode`). The file starts with a marker; a file without it is
//!   never overwritten or removed.
//!
//! `--dry-run` prints a line diff and writes nothing. Commands use the absolute
//! path of the running executable (no PATH lookup at hook time).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use paste_warden_i18n::Localizer;
use serde_json::{Map, Value, json};

use crate::l10n::t;

/// Claude Code `PreToolUse` matcher. PasteWarden's own MCP tools are excluded
/// here (S7 pitfall) and again inside the hook ([`super::policy::claude_tool_kind`]).
pub const CLAUDE_MATCHER: &str =
    "^(Bash|WebFetch|WebSearch|Write|Edit|MultiEdit|NotebookEdit|mcp__(?!paste-warden__).*)$";
/// Claude Code hook timeout in seconds (the hook's own timeout is 2 s).
pub const CLAUDE_TIMEOUT_SECS: u64 = 10;
/// First line of the generated opencode plugin.
pub const OPENCODE_MARKER: &str = "// paste-warden-opencode-plugin";
const OPENCODE_TEMPLATE: &str = include_str!("opencode_plugin.ts");
/// Raw text and parsed object of a settings file.
type Settings = (String, Map<String, Value>);

const OPENCODE_BIN_PLACEHOLDER: &str = "__PASTE_WARDEN_BIN__";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Agent {
    ClaudeCode,
    Opencode,
}

impl Agent {
    fn name(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude-code",
            Agent::Opencode => "opencode",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Scope {
    #[default]
    User,
    Project,
}

impl Scope {
    fn name(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Project => "project",
        }
    }
}

/// Absolute path of the running executable for config files. Resolved on
/// Unix (`..`, symlinked build dirs); left as is on Windows, where
/// `canonicalize` would produce a `\\?\` path.
pub fn exe_path() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    if cfg!(windows) {
        Ok(exe)
    } else {
        Ok(exe.canonicalize().unwrap_or(exe))
    }
}

/// Where things live, taken from the process environment by the caller so
/// tests can point everything at a temp dir.
#[derive(Debug, Clone)]
pub struct InstallEnv {
    pub home: Option<PathBuf>,
    pub claude_config_dir: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    /// Project directory for `--scope project`.
    pub project_dir: PathBuf,
    /// Absolute path of the `paste-warden` executable.
    pub exe: PathBuf,
}

impl InstallEnv {
    /// From the process environment.
    pub fn from_process(project_dir: Option<PathBuf>) -> anyhow::Result<InstallEnv> {
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let home = var("HOME").or_else(|| var("USERPROFILE"));
        let project_dir = match project_dir {
            Some(p) => p,
            None => std::env::current_dir()?,
        };
        let exe = exe_path()?;
        Ok(InstallEnv {
            home,
            claude_config_dir: var("CLAUDE_CONFIG_DIR"),
            xdg_config_home: var("XDG_CONFIG_HOME"),
            project_dir: std::path::absolute(&project_dir).unwrap_or(project_dir),
            exe,
        })
    }

    fn home(&self) -> anyhow::Result<&Path> {
        self.home
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("HOME is not set"))
    }

    /// The file `install`/`uninstall` touches.
    pub fn target(&self, agent: Agent, scope: Scope) -> anyhow::Result<PathBuf> {
        Ok(match (agent, scope) {
            (Agent::ClaudeCode, Scope::User) => match &self.claude_config_dir {
                Some(d) => d.join("settings.json"),
                None => self.home()?.join(".claude").join("settings.json"),
            },
            (Agent::ClaudeCode, Scope::Project) => {
                self.project_dir.join(".claude").join("settings.json")
            }
            (Agent::Opencode, Scope::User) => match &self.xdg_config_home {
                Some(d) => d.join("opencode"),
                None => self.home()?.join(".config").join("opencode"),
            }
            .join("plugins")
            .join("paste-warden.ts"),
            (Agent::Opencode, Scope::Project) => self
                .project_dir
                .join(".opencode")
                .join("plugins")
                .join("paste-warden.ts"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub agent: Agent,
    pub scope: Scope,
    pub dry_run: bool,
    /// Also install the Claude Code `UserPromptSubmit` secret check.
    pub prompt_guard: bool,
}

/// What happened (for messages and tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Unchanged,
    /// Would write (dry run); the diff.
    DryRun(String),
    Written {
        backup: Option<PathBuf>,
    },
    Removed {
        backup: Option<PathBuf>,
    },
    NothingToRemove,
}

/// A localized error (the message never contains settings contents).
#[derive(Debug)]
pub struct InstallError(pub String);

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for InstallError {}

/// Shell-quotes the executable path for a hook command line.
pub fn quote_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    let safe = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+:\\".contains(c));
    if safe {
        return s.into_owned();
    }
    if cfg!(windows) {
        format!("\"{}\"", s.replace('"', ""))
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The hook command line written into Claude Code settings.
pub fn claude_command(exe: &Path) -> String {
    format!("{} hook claude-code", quote_path(exe))
}

fn is_our_command(cmd: &str) -> bool {
    cmd.contains("paste-warden") && cmd.trim_end().ends_with("hook claude-code")
}

fn hook_entry(command: &str, matcher: Option<&str>) -> Value {
    let mut group = Map::new();
    if let Some(m) = matcher {
        group.insert("matcher".into(), Value::String(m.into()));
    }
    group.insert(
        "hooks".into(),
        json!([{ "type": "command", "command": command, "timeout": CLAUDE_TIMEOUT_SECS }]),
    );
    Value::Object(group)
}

/// Removes our hook commands from `settings`, dropping groups / event arrays /
/// the `hooks` object only when our removal emptied them. Returns whether
/// anything was removed.
pub fn remove_claude_entries(settings: &mut Map<String, Value>) -> bool {
    let Some(Value::Object(hooks)) = settings.get_mut("hooks") else {
        return false;
    };
    let mut removed = false;
    let events: Vec<String> = hooks.keys().cloned().collect();
    for event in events {
        let Some(Value::Array(groups)) = hooks.get_mut(&event) else {
            continue;
        };
        let mut emptied_by_us = false;
        groups.retain_mut(|group| {
            let Some(Value::Array(list)) = group.get_mut("hooks") else {
                return true;
            };
            let before = list.len();
            list.retain(|h| {
                !h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(is_our_command)
            });
            if list.len() != before {
                removed = true;
                if list.is_empty() {
                    emptied_by_us = true;
                    return false;
                }
            }
            true
        });
        if emptied_by_us && groups.is_empty() {
            hooks.remove(&event);
        }
    }
    if removed && hooks.is_empty() {
        settings.remove("hooks");
    }
    removed
}

/// `settings` with our entries (re)installed.
pub fn add_claude_entries(settings: &mut Map<String, Value>, command: &str, prompt_guard: bool) {
    remove_claude_entries(settings);
    let hooks = settings
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    if !hooks.is_object() {
        *hooks = Value::Object(Map::new());
    }
    let hooks = hooks.as_object_mut().expect("object");
    let mut push = |event: &str, entry: Value| {
        let list = hooks
            .entry(event)
            .or_insert_with(|| Value::Array(Vec::new()));
        if !list.is_array() {
            *list = Value::Array(Vec::new());
        }
        list.as_array_mut().expect("array").push(entry);
    };
    push("PreToolUse", hook_entry(command, Some(CLAUDE_MATCHER)));
    if prompt_guard {
        push("UserPromptSubmit", hook_entry(command, None));
    }
}

fn read_settings(path: &Path, l10n: &Localizer) -> Result<Option<Settings>, InstallError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(InstallError(format!("{}: {e}", path.display()))),
    };
    if text.trim().is_empty() {
        return Ok(Some((text, Map::new())));
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(m)) => Ok(Some((text, m))),
        _ => Err(InstallError(t(
            l10n,
            "cli-install-not-json",
            &[("path", path.display().to_string().into())],
        ))),
    }
}

fn to_pretty(m: &Map<String, Value>) -> String {
    let mut s = serde_json::to_string_pretty(&Value::Object(m.clone())).unwrap_or_default();
    s.push('\n');
    s
}

/// First free backup name: `<file>.pw-bak`, `<file>.pw-bak.1`, …
fn backup_path(path: &Path) -> PathBuf {
    let base = format!("{}.pw-bak", path.display());
    let mut candidate = PathBuf::from(&base);
    let mut n = 1;
    while candidate.exists() {
        candidate = PathBuf::from(format!("{base}.{n}"));
        n += 1;
    }
    candidate
}

/// Backs up `path` (if it exists) and writes `contents` atomically.
fn write_with_backup(path: &Path, contents: &str) -> Result<Option<PathBuf>, InstallError> {
    let io = |e: std::io::Error| InstallError(format!("{}: {e}", path.display()));
    let backup = if path.exists() {
        let b = backup_path(path);
        std::fs::copy(path, &b).map_err(io)?;
        Some(b)
    } else {
        None
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let tmp = PathBuf::from(format!("{}.pw-tmp", path.display()));
    std::fs::write(&tmp, contents).map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)?;
    Ok(backup)
}

/// A minimal line diff (`-`/`+`/` ` prefixes) for `--dry-run`.
pub fn line_diff(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    // Settings files are small; plain LCS is fine. Cap to stay bounded.
    if a.len() * b.len() > 4_000_000 {
        let mut out = String::new();
        a.iter().for_each(|l| writeln!(out, "-{l}").unwrap_or(()));
        b.iter().for_each(|l| writeln!(out, "+{l}").unwrap_or(()));
        return out;
    }
    let mut lcs = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut out = String::new();
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            let _ = writeln!(out, " {}", a[i]);
            i += 1;
            j += 1;
        } else if i < a.len() && (j == b.len() || lcs[i + 1][j] >= lcs[i][j + 1]) {
            let _ = writeln!(out, "-{}", a[i]);
            i += 1;
        } else {
            let _ = writeln!(out, "+{}", b[j]);
            j += 1;
        }
    }
    out
}

/// The opencode plugin source for `exe`.
pub fn opencode_plugin(exe: &Path) -> String {
    let bin = serde_json::to_string(&exe.to_string_lossy()).unwrap_or_else(|_| "\"\"".into());
    OPENCODE_TEMPLATE.replace(OPENCODE_BIN_PLACEHOLDER, &bin)
}

fn is_our_plugin(text: &str) -> bool {
    text.starts_with(OPENCODE_MARKER)
}

/// Installs the hook. Returns what happened and the file path.
pub fn install(
    opts: &InstallOptions,
    env: &InstallEnv,
    l10n: &Localizer,
) -> Result<(PathBuf, Outcome), InstallError> {
    let path = env
        .target(opts.agent, opts.scope)
        .map_err(|e| InstallError(e.to_string()))?;
    let (old, new) = match opts.agent {
        Agent::ClaudeCode => {
            let (old, mut map) = read_settings(&path, l10n)?.unwrap_or_default();
            let before = map.clone();
            add_claude_entries(&mut map, &claude_command(&env.exe), opts.prompt_guard);
            if map == before {
                return Ok((path, Outcome::Unchanged));
            }
            (old, to_pretty(&map))
        }
        Agent::Opencode => {
            let old = match std::fs::read_to_string(&path) {
                Ok(t) if !is_our_plugin(&t) => {
                    return Err(InstallError(t_path(l10n, "cli-install-not-ours", &path)));
                }
                Ok(t) => t,
                Err(_) => String::new(),
            };
            (old, opencode_plugin(&env.exe))
        }
    };
    if old == new {
        return Ok((path, Outcome::Unchanged));
    }
    if opts.dry_run {
        return Ok((path, Outcome::DryRun(line_diff(&old, &new))));
    }
    let backup = write_with_backup(&path, &new)?;
    Ok((path, Outcome::Written { backup }))
}

/// Removes the hook.
pub fn uninstall(
    opts: &InstallOptions,
    env: &InstallEnv,
    l10n: &Localizer,
) -> Result<(PathBuf, Outcome), InstallError> {
    let path = env
        .target(opts.agent, opts.scope)
        .map_err(|e| InstallError(e.to_string()))?;
    match opts.agent {
        Agent::ClaudeCode => {
            let Some((old, mut map)) = read_settings(&path, l10n)? else {
                return Ok((path, Outcome::NothingToRemove));
            };
            if !remove_claude_entries(&mut map) {
                return Ok((path, Outcome::NothingToRemove));
            }
            let new = to_pretty(&map);
            if opts.dry_run {
                return Ok((path, Outcome::DryRun(line_diff(&old, &new))));
            }
            let backup = write_with_backup(&path, &new)?;
            Ok((path, Outcome::Removed { backup }))
        }
        Agent::Opencode => match std::fs::read_to_string(&path) {
            Ok(t) if is_our_plugin(&t) => {
                if opts.dry_run {
                    return Ok((path, Outcome::DryRun(line_diff(&t, ""))));
                }
                std::fs::remove_file(&path)
                    .map_err(|e| InstallError(format!("{}: {e}", path.display())))?;
                Ok((path, Outcome::Removed { backup: None }))
            }
            Ok(_) => Err(InstallError(t_path(l10n, "cli-install-not-ours", &path))),
            Err(_) => Ok((path, Outcome::NothingToRemove)),
        },
    }
}

fn t_path(l10n: &Localizer, id: &'static str, path: &Path) -> String {
    t(l10n, id, &[("path", path.display().to_string().into())])
}

/// opencode major version from `opencode --version` output (`opencode v2.2.0`).
pub fn opencode_major(version_output: &str) -> Option<u32> {
    version_output
        .split_whitespace()
        .rev()
        .find_map(|w| w.trim_start_matches('v').split('.').next()?.parse().ok())
}

/// Human-readable lines describing an outcome.
pub fn describe(
    opts: &InstallOptions,
    path: &Path,
    outcome: &Outcome,
    l10n: &Localizer,
    installing: bool,
) -> Vec<String> {
    let p = || path.display().to_string();
    let mut lines = Vec::new();
    match outcome {
        Outcome::Unchanged => lines.push(t(l10n, "cli-install-unchanged", &[("path", p().into())])),
        Outcome::DryRun(diff) => {
            lines.push(p());
            lines.push(diff.trim_end().to_owned());
            lines.push(t(l10n, "cli-install-dry-run", &[]));
        }
        Outcome::Written { backup } | Outcome::Removed { backup } => {
            let id = if installing {
                "cli-install-written"
            } else {
                "cli-uninstall-done"
            };
            lines.push(t(l10n, id, &[("path", p().into())]));
            if let Some(b) = backup {
                lines.push(t(
                    l10n,
                    "cli-install-backup",
                    &[("path", b.display().to_string().into())],
                ));
            }
        }
        Outcome::NothingToRemove => {
            lines.push(t(l10n, "cli-uninstall-none", &[("path", p().into())]));
        }
    }
    if installing && !matches!(outcome, Outcome::DryRun(_)) {
        let verify = match opts.agent {
            Agent::ClaudeCode => "cli-install-verify-claude",
            Agent::Opencode => "cli-install-verify-opencode",
        };
        lines.push(t(l10n, verify, &[]));
        lines.push(t(
            l10n,
            "cli-install-remove",
            &[
                ("agent", opts.agent.name().into()),
                ("scope", opts.scope.name().into()),
            ],
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(dir: &Path) -> InstallEnv {
        InstallEnv {
            home: Some(dir.join("home")),
            claude_config_dir: None,
            xdg_config_home: None,
            project_dir: dir.join("proj"),
            exe: PathBuf::from("/opt/pw/bin/paste-warden"),
        }
    }

    fn opts(agent: Agent, scope: Scope, dry_run: bool) -> InstallOptions {
        InstallOptions {
            agent,
            scope,
            dry_run,
            prompt_guard: true,
        }
    }

    #[test]
    fn claude_merge_keeps_user_settings_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        let l = Localizer::new("en");
        let path = env.target(Agent::ClaudeCode, Scope::User).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = r#"{"zeta":1,"model":"x","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-own-hook"}]}]},"permissions":{"allow":["Bash(ls)"]}}"#;
        std::fs::write(&path, original).unwrap();

        let o = opts(Agent::ClaudeCode, Scope::User, false);
        let (_, outcome) = install(&o, &env, &l).unwrap();
        let Outcome::Written { backup: Some(b) } = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(std::fs::read_to_string(b).unwrap(), original);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["model"], "x");
        assert_eq!(v["permissions"]["allow"][0], "Bash(ls)");
        let pre = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(pre[0]["hooks"][0]["command"], "my-own-hook");
        assert_eq!(pre[1]["matcher"], CLAUDE_MATCHER);
        assert_eq!(
            pre[1]["hooks"][0]["command"],
            "/opt/pw/bin/paste-warden hook claude-code"
        );
        assert_eq!(v["hooks"]["UserPromptSubmit"].as_array().unwrap().len(), 1);
        // Key order is preserved.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.find("\"zeta\"") < text.find("\"model\""));

        assert_eq!(install(&o, &env, &l).unwrap().1, Outcome::Unchanged);

        let (_, outcome) = uninstall(&o, &env, &l).unwrap();
        assert!(matches!(outcome, Outcome::Removed { .. }));
        let back: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let orig: Value = serde_json::from_str(original).unwrap();
        assert_eq!(back, orig);
        assert_eq!(uninstall(&o, &env, &l).unwrap().1, Outcome::NothingToRemove);
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        let l = Localizer::new("en");
        let (path, outcome) =
            install(&opts(Agent::ClaudeCode, Scope::Project, true), &env, &l).unwrap();
        assert!(path.starts_with(dir.path().join("proj")));
        let Outcome::DryRun(diff) = outcome else {
            panic!()
        };
        assert!(diff.contains("+") && diff.contains("hook claude-code"));
        assert!(!path.exists());
    }

    #[test]
    fn jsonc_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        let path = env.target(Agent::ClaudeCode, Scope::Project).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{ // comment\n}").unwrap();
        let r = install(
            &opts(Agent::ClaudeCode, Scope::Project, false),
            &env,
            &Localizer::new("en"),
        );
        assert!(r.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ // comment\n}");
    }

    #[test]
    fn opencode_plugin_install_and_uninstall() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(dir.path());
        let l = Localizer::new("en");
        let o = opts(Agent::Opencode, Scope::User, false);
        let (path, outcome) = install(&o, &env, &l).unwrap();
        assert!(path.ends_with(".config/opencode/plugins/paste-warden.ts"));
        assert!(matches!(outcome, Outcome::Written { backup: None }));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(OPENCODE_MARKER));
        assert!(text.contains(r#"const BIN = "/opt/pw/bin/paste-warden""#));
        assert!(text.contains(r#"ctx.tool.hook("execute.before""#));
        assert!(!text.contains("tool.execute.before\""), "no V1 form");
        assert_eq!(install(&o, &env, &l).unwrap().1, Outcome::Unchanged);
        assert!(matches!(
            uninstall(&o, &env, &l).unwrap().1,
            Outcome::Removed { .. }
        ));
        assert!(!path.exists());
        // Someone else's file is never touched.
        std::fs::write(&path, "export default {}").unwrap();
        assert!(install(&o, &env, &l).is_err());
        assert!(uninstall(&o, &env, &l).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "export default {}");
    }

    #[test]
    fn helpers() {
        assert_eq!(opencode_major("opencode v2.2.0"), Some(2));
        assert_eq!(opencode_major("1.19.3"), Some(1));
        let quoted = quote_path(Path::new("/a b/pw"));
        if cfg!(windows) {
            assert_eq!(quoted, "\"/a b/pw\"");
        } else {
            assert_eq!(quoted, "'/a b/pw'");
        }
        assert_eq!(line_diff("a\nb\n", "a\nc\n"), " a\n-b\n+c\n");
    }
}
