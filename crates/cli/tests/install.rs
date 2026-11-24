//! `hook install` / `hook uninstall` end to end, only inside temp dirs.

mod common;

use common::pw;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn claude_user_scope_install_dry_run_uninstall() {
    let home = tempfile::tempdir().unwrap();
    let settings = home.path().join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(&settings, r#"{"theme":"dark","hooks":{"Stop":[{"hooks":[{"type":"command","command":"say done"}]}]}}"#).unwrap();

    pw(home.path())
        .args(["hook", "install", "claude-code", "--dry-run"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("+"))
        .stdout(predicate::str::contains("--dry-run"));
    assert!(
        !std::fs::read_to_string(&settings)
            .unwrap()
            .contains("paste-warden")
    );

    pw(home.path())
        .args(["hook", "install", "claude-code"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Self-test passed"))
        .stdout(predicate::str::contains(
            "hook uninstall claude-code --scope user",
        ));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(v["theme"], "dark");
    assert_eq!(v["hooks"]["Stop"][0]["hooks"][0]["command"], "say done");
    let cmd = v["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(
        cmd.ends_with("hook claude-code") && cmd.contains("paste-warden"),
        "{cmd}"
    );
    assert!(
        v["hooks"]["PreToolUse"][0]["matcher"]
            .as_str()
            .unwrap()
            .contains("(?!paste-warden__)")
    );
    assert!(settings.with_file_name("settings.json.pw-bak").exists());

    pw(home.path())
        .args(["hook", "install", "claude-code"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Already installed"));
    assert!(!settings.with_file_name("settings.json.pw-bak.1").exists());

    pw(home.path())
        .args(["hook", "uninstall", "claude-code"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Removed"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert!(v["hooks"].get("PreToolUse").is_none());
    assert!(v["hooks"].get("UserPromptSubmit").is_none());
    assert_eq!(v["hooks"]["Stop"][0]["hooks"][0]["command"], "say done");
}

#[test]
fn claude_project_scope_without_prompt_guard() {
    let home = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    pw(home.path())
        .args([
            "hook",
            "install",
            "claude-code",
            "--scope",
            "project",
            "--no-prompt-guard",
        ])
        .arg("--project-dir")
        .arg(proj.path())
        .assert()
        .code(0);
    let settings = proj.path().join(".claude").join("settings.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert!(v["hooks"]["PreToolUse"].is_array());
    assert!(v["hooks"].get("UserPromptSubmit").is_none());
    assert!(
        !home.path().join(".claude").exists(),
        "user scope untouched"
    );
}

#[test]
fn opencode_plugin_install_project_scope() {
    let home = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    pw(home.path())
        .args([
            "hook",
            "install",
            "opencode",
            "--scope",
            "project",
            "--project-dir",
        ])
        .arg(proj.path())
        .assert()
        .code(0);
    let plugin = proj
        .path()
        .join(".opencode")
        .join("plugins")
        .join("paste-warden.ts");
    let text = std::fs::read_to_string(&plugin).unwrap();
    assert!(text.contains("ctx.tool.hook(\"execute.before\""));
    assert!(text.contains("[\"hook\", \"opencode\"]"));
    pw(home.path())
        .args([
            "hook",
            "uninstall",
            "opencode",
            "--scope",
            "project",
            "--project-dir",
        ])
        .arg(proj.path())
        .assert()
        .code(0);
    assert!(!plugin.exists());
}

#[test]
fn mcp_print_config_names_the_server() {
    let home = tempfile::tempdir().unwrap();
    let out = pw(home.path())
        .args(["mcp", "--print-config", "claude-code"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["mcpServers"]["paste-warden"]["args"][0], "mcp");
    pw(home.path())
        .args(["mcp", "--profile", "redteam"])
        .assert()
        .code(3);
}
