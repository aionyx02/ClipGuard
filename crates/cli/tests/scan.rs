//! `scan`, `mask`, `bench` end to end (phase-2.md §2.3 exit codes).

mod common;

use common::{clickfix, fake_token, pw};
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn scan_exit_codes_follow_the_spec() {
    let home = tempfile::tempdir().unwrap();
    pw(home.path())
        .arg("scan")
        .write_stdin("明天下午三點開會")
        .assert()
        .code(0);
    pw(home.path())
        .arg("scan")
        .write_stdin(format!("token {}", fake_token()))
        .assert()
        .code(1);
    pw(home.path())
        .args(["scan", "-"])
        .write_stdin(clickfix())
        .assert()
        .code(2);
    pw(home.path())
        .args(["scan", "/definitely/not/here.txt"])
        .assert()
        .code(3);
    pw(home.path()).args(["scan", "--bogus"]).assert().code(3);
    pw(home.path()).arg("--help").assert().code(0);
}

#[test]
fn scan_json_has_the_report_shape_and_no_secret() {
    let home = tempfile::tempdir().unwrap();
    let token = fake_token();
    let input = format!("{}\nexport T={token}", clickfix());
    let out = pw(home.path())
        .args(["scan", "--json", "--locale", "zh-TW"])
        .write_stdin(input)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(!text.contains(&token));
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["schema"], 1);
    assert_eq!(v["action"], "quarantine");
    assert_eq!(v["command"]["level"], "malicious");
    assert!(
        v["command"]["reasons"][0]["id"]
            .as_str()
            .unwrap()
            .starts_with("cmd-")
    );
    assert_eq!(v["secrets"][0]["kind"], "api_key");
    assert!(v["secrets"][0]["span_utf16"].is_array());
}

#[test]
fn scan_human_output_is_localized_and_masks() {
    let home = tempfile::tempdir().unwrap();
    let token = fake_token();
    pw(home.path())
        .args(["scan", "--locale", "zh-TW"])
        .write_stdin(format!("token {token}"))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("偵測到機密"))
        .stdout(predicate::str::contains(token.as_str()).not());
    pw(home.path())
        .arg("scan")
        .env("LANG", "zh_TW.UTF-8")
        .write_stdin(clickfix())
        .assert()
        .stdout(predicate::str::contains("惡意"));
}

#[test]
fn scan_reads_files() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("x.txt");
    std::fs::write(&f, clickfix()).unwrap();
    pw(dir.path()).arg("scan").arg(&f).assert().code(2);
}

#[test]
fn mask_replaces_secrets_and_keeps_the_rest() {
    let home = tempfile::tempdir().unwrap();
    let token = fake_token();
    let out = pw(home.path())
        .arg("mask")
        .write_stdin(format!("before {token} after"))
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.starts_with("before ") && out.ends_with(" after"),
        "{out}"
    );
    assert!(!out.contains(&token));
}

#[test]
fn bench_reports_each_line_and_a_summary() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("b.jsonl");
    let lines = [
        serde_json::json!({ "id": "a", "text": clickfix() }).to_string(),
        serde_json::json!({ "id": "b", "text": "echo hello" }).to_string(),
        "not json".to_owned(),
    ];
    std::fs::write(&f, lines.join("\n")).unwrap();
    let out = pw(dir.path())
        .arg("bench")
        .arg(&f)
        .assert()
        .code(0)
        .stderr(predicate::str::contains("Line 3"))
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).unwrap();
    let rows: Vec<Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["id"], "a");
    assert_eq!(rows[0]["action"], "quarantine");
    assert_eq!(rows[1]["action"], "allow");
    let s = &rows[2]["summary"];
    assert_eq!(s["total"], 2);
    assert_eq!(s["quarantine"], 1);
    assert_eq!(s["errors"], 1);
}
