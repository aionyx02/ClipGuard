//! `paste-warden mcp --profile redteam` over real stdio (phase-5.md §5.7).

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use common::{clickfix, fake_token};
use serde_json::{Value, json};

struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Server {
    fn start(args: &[&str]) -> Server {
        let mut child = Command::new(assert_cmd::cargo::cargo_bin("paste-warden"))
            .args(["mcp", "--locale", "en"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut s = Server {
            child,
            stdin,
            stdout,
        };
        let init = s.request(
            1,
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" } }),
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "paste-warden");
        s.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        s
    }

    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "server closed"
            );
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    fn tools(&mut self) -> Vec<String> {
        let list = self.request(2, "tools/list", json!({}));
        let mut names: Vec<String> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect();
        names.sort();
        names
    }

    fn call(&mut self, id: u64, tool: &str, args: Value) -> Value {
        self.request(id, "tools/call", json!({ "name": tool, "arguments": args }))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn guard_profile_has_no_redteam_tools() {
    for args in [&[][..], &["--profile", "guard"][..]] {
        let names = Server::start(args).tools();
        assert!(!names.iter().any(|n| n == "run_benchmark"), "{names:?}");
        assert!(!names.iter().any(|n| n == "validate_syntax"), "{names:?}");
    }
}

#[test]
fn redteam_profile_adds_two_read_only_tools() {
    let mut s = Server::start(&["--profile", "redteam"]);
    assert_eq!(
        s.tools(),
        [
            "analyze",
            "deobfuscate_trace",
            "mask",
            "run_benchmark",
            "scan_secrets",
            "validate_syntax"
        ]
    );
    let list = s.request(3, "tools/list", json!({}));
    for t in list["result"]["tools"].as_array().unwrap() {
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{t}");
    }
}

#[test]
fn run_benchmark_never_echoes_inputs() {
    let mut s = Server::start(&["--profile", "redteam"]);
    let secret = format!("export GITHUB_TOKEN={}", fake_token());
    let marker = "zq-unique-marker-text";
    let r = s.call(
        4,
        "run_benchmark",
        json!({ "items": [
            { "id": "c1", "text": clickfix() },
            { "id": "c2", "text": secret },
            { "id": "c3", "text": format!("hello {marker}") },
        ] }),
    );
    assert_ne!(r["result"]["isError"], true, "{r}");
    let out = &r["result"]["structuredContent"];
    assert_eq!(out["summary"]["total"], 3);
    assert_eq!(out["summary"]["quarantine"], 1);
    assert_eq!(out["results"][0]["id"], "c1");
    assert_eq!(out["results"][0]["action"], "quarantine");
    assert_eq!(out["results"][1]["secrets"], 1);
    let text = r.to_string();
    assert!(!text.contains(&fake_token()) && !text.contains(marker));
    assert!(!text.contains("example.invalid"));

    let too_many: Vec<Value> = (0..1001)
        .map(|i| json!({ "id": i.to_string(), "text": "" }))
        .collect();
    let r = s.call(5, "run_benchmark", json!({ "items": too_many }));
    assert_eq!(r["result"]["isError"], true);
}

#[test]
fn validate_syntax_with_a_missing_validator_is_a_tool_error() {
    let mut s = Server::start(&[
        "--profile",
        "redteam",
        "--validator-cmd",
        "paste-warden-no-such-validator-xyz",
    ]);
    let marker = "zq-unique-marker-text";
    let r = s.call(
        6,
        "validate_syntax",
        json!({ "text": marker, "shell": "bash" }),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
    assert!(!r.to_string().contains(marker));
}

/// A fake validator (unix shell) that echoes the request id, says `invalid`
/// and tries to leak the payload through an error id and an extra field.
#[cfg(unix)]
#[test]
fn validate_syntax_speaks_jsonl_and_never_echoes_the_text() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("validator.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nread line\n\
         id=$(printf '%s' \"$line\" | sed 's/^{\"id\":\"\\([^\"]*\\)\".*/\\1/')\n\
         src=$(printf '%s' \"$line\" | sed 's/.*\"src\":\"\\([^\"]*\\)\".*/\\1/')\n\
         printf '{\"id\":\"%s\",\"shell\":\"bash\",\"status\":\"invalid\",\"payload\":\"%s\",\
\"errors\":[{\"id\":\"%s\",\"line\":1,\"column\":3},{\"id\":\"UnexpectedToken\",\"line\":2,\"column\":5}]}\\n' \
\"$id\" \"$src\" \"$src\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut s = Server::start(&[
        "--profile",
        "redteam",
        "--validator-cmd",
        script.to_str().unwrap(),
    ]);
    let marker = "zqmarkerpayload";
    let r = s.call(
        7,
        "validate_syntax",
        json!({ "text": marker, "shell": "bash" }),
    );
    assert_ne!(r["result"]["isError"], true, "{r}");
    let out = &r["result"]["structuredContent"];
    assert_eq!(out["status"], "invalid");
    assert_eq!(out["ok"], false);
    assert_eq!(out["shell"], "bash");
    assert_eq!(out["errors"][0]["id"], "redacted");
    assert_eq!(out["errors"][1]["id"], "UnexpectedToken");
    assert_eq!(out["errors"][1]["line"], 2);
    assert!(!r.to_string().contains(marker), "{r}");
}
