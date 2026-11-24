//! The MCP server over real stdio (JSON-RPC lines), guard profile.

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
    fn start() -> Server {
        let mut child = Command::new(assert_cmd::cargo::cargo_bin("paste-warden"))
            .args(["mcp", "--locale", "en"])
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
fn guard_profile_lists_exactly_four_read_only_tools() {
    let mut s = Server::start();
    let list = s.request(2, "tools/list", json!({}));
    let tools = list["result"]["tools"].as_array().unwrap();
    let mut names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(
        names,
        ["analyze", "deobfuscate_trace", "mask", "scan_secrets"]
    );
    for t in tools {
        assert_eq!(t["annotations"]["readOnlyHint"], true, "{t}");
        let text = t.to_string().to_lowercase();
        assert!(!text.contains("clipboard\":"), "no clipboard tool: {t}");
    }
}

#[test]
fn tools_work_and_never_return_a_planted_secret() {
    let mut s = Server::start();
    let token = fake_token();
    let text = format!("{}\nexport GITHUB_TOKEN={token}", clickfix());
    let analyze = s.call(3, "analyze", json!({ "text": text, "locale": "zh-TW" }));
    let r = &analyze["result"];
    assert_ne!(r["isError"], true, "{analyze}");
    assert_eq!(r["structuredContent"]["action"], "quarantine");
    assert_eq!(r["structuredContent"]["schema"], 1);
    let outputs = [
        analyze.to_string(),
        s.call(4, "deobfuscate_trace", json!({ "text": text }))
            .to_string(),
        s.call(5, "scan_secrets", json!({ "text": text, "packs": ["tw"] }))
            .to_string(),
        s.call(6, "mask", json!({ "text": text })).to_string(),
    ];
    for o in &outputs {
        assert!(!o.contains(&token), "{o}");
    }
    assert!(outputs[2].contains("api_key"));
}

#[test]
fn oversize_input_is_a_tool_error() {
    let mut s = Server::start();
    let big = "a".repeat((1 << 20) + 1);
    let r = s.call(7, "analyze", json!({ "text": big }));
    assert_eq!(
        r["result"]["isError"],
        true,
        "{}",
        &r.to_string()[..200.min(r.to_string().len())]
    );
    assert!(
        r.to_string().len() < 1000,
        "the error must not echo the input"
    );
}
