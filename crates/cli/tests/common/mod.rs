//! Shared helpers for the integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use paste_warden_corpus::{Case, read_jsonl, resolve_text};

pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

/// Input text of a corpus case (assembled from its `parts` at run time).
pub fn corpus_text(file: &str, id: &str) -> String {
    let cases = read_jsonl::<Case>(&corpus_dir().join("cases").join(file)).expect("corpus file");
    let case = cases
        .into_iter()
        .find(|c| c.value.id == id)
        .unwrap_or_else(|| panic!("no corpus case {id}"));
    resolve_text(case.value.input.as_ref().expect("input")).expect("text")
}

/// The ClickFix sample used by the hook tests and the real-agent checks
/// (docs/integrations/agent-hooks.md).
pub fn clickfix() -> String {
    corpus_text("command-detector.jsonl", "command.detector.clickfix-000")
}

/// A fake GitHub token, assembled at run time (push protection).
pub fn fake_token() -> String {
    format!("gh{}_{}", "p", "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8")
}

/// `paste-warden` with a clean, temp-only environment.
pub fn pw(home: &Path) -> Command {
    let mut c = Command::cargo_bin("paste-warden").expect("binary");
    for k in [
        "CLAUDE_CONFIG_DIR",
        "XDG_CONFIG_HOME",
        "LC_ALL",
        "LC_MESSAGES",
        "NO_COLOR",
        "PASTE_WARDEN_HOOK_FAULT",
    ] {
        c.env_remove(k);
    }
    c.env("HOME", home)
        .env("USERPROFILE", home)
        .env("LANG", "en_US.UTF-8");
    c
}
