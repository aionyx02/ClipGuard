//! `corpus add-from-run`: copy a red-team variant into the corpus
//! (docs/plan/phase-5.md §5.5.1).
//!
//! ```text
//! cargo run -p xtask -- corpus add-from-run <run-store-dir> <variant-id> \
//!     --expect <none|suspicious|malicious> [--file <redteam-name>]
//! ```
//!
//! The payload is never assembled into a literal: the run store's `parts`
//! (`STORE_PART_CHARS` characters each) are copied verbatim into
//! `{"parts": [...]}`, so the new case passes `corpus lint` like any other.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use paste_warden_corpus::{Case, jsonl_files, read_jsonl, resolve_text};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;

const LEVELS: &[&str] = &["none", "suspicious", "malicious"];
pub const ID_PREFIX: &str = "command.redteam.";
pub const SOURCE_PREFIX: &str = "redteam:";

#[derive(Debug, PartialEq, Eq)]
pub struct Added {
    pub id: String,
    pub file: PathBuf,
}

#[derive(Serialize)]
struct Expect<'a> {
    level: &'a str,
}

#[derive(Serialize)]
struct Input<'a> {
    parts: &'a [String],
}

/// Field order matches the hand-written corpus files.
#[derive(Serialize)]
struct NewCase<'a> {
    id: &'a str,
    area: &'static str,
    op: &'static str,
    source: &'a str,
    input: Input<'a>,
    expect: Expect<'a>,
    tags: Vec<String>,
    note: String,
}

pub fn cli(args: &[&str], cases_dir: &Path) -> Result<bool> {
    let mut positional = Vec::new();
    let mut expect = None;
    let mut file = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--expect" => expect = it.next().copied(),
            "--file" => file = it.next().copied(),
            other if other.starts_with("--") => bail!("unknown option {other}"),
            other => positional.push(other),
        }
    }
    let ([run_dir, variant_id], Some(expect)) = (positional.as_slice(), expect) else {
        bail!(
            "usage: corpus add-from-run <run-store-dir> <variant-id> --expect <level> [--file <name>]"
        );
    };
    let added = add_from_run(cases_dir, Path::new(run_dir), variant_id, expect, file)?;
    println!("added {} to {}", added.id, added.file.display());
    Ok(true)
}

pub fn add_from_run(
    cases_dir: &Path,
    run_dir: &Path,
    variant_id: &str,
    expect: &str,
    file: Option<&str>,
) -> Result<Added> {
    if !LEVELS.contains(&expect) {
        bail!("--expect must be one of {LEVELS:?}");
    }
    let id_re = Regex::new(r"^[a-z0-9][a-z0-9_-]{0,63}$")?;
    if !id_re.is_match(variant_id) {
        bail!("variant id must match {}", id_re.as_str());
    }
    let run_id = run_dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("run store dir has no name")?;
    if !Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")?.is_match(run_id) {
        bail!("run id `{run_id}` has unexpected characters");
    }

    let record = find_variant(&run_dir.join("variants.jsonl"), variant_id)?;
    let parts: Vec<String> = match record.get("parts") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|p| p.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .context("`parts` must be strings")?,
        _ => bail!("variant {variant_id} has no `parts`"),
    };
    if parts.is_empty() {
        bail!("variant {variant_id} has an empty payload");
    }
    for p in &parts {
        if crate::looks_like_key(p).is_some() || crate::looks_like_malicious_command(p) {
            bail!("a part of {variant_id} fails the corpus leak scan; re-split the run store");
        }
    }
    let round = record.get("round").and_then(Value::as_u64);
    let file_name = match file {
        Some(name) => {
            let name = name.strip_suffix(".jsonl").unwrap_or(name);
            if !Regex::new(r"^redteam-[a-z0-9][a-z0-9_-]*$")?.is_match(name) {
                bail!("--file must look like `redteam-<round>`");
            }
            format!("{name}.jsonl")
        }
        None => format!("redteam-{}.jsonl", round.context("variant has no `round`")?),
    };

    let id = format!("{ID_PREFIX}{variant_id}");
    let text = parts.concat();
    check_duplicates(cases_dir, &id, &text)?;

    let mut tags = vec!["redteam".to_string()];
    if let Some(g) = record.get("generator").and_then(Value::as_str) {
        tags.push(g.to_string());
    }
    if let Some(Value::Array(ts)) = record.get("techniques") {
        tags.extend(ts.iter().filter_map(Value::as_str).map(str::to_string));
    }
    let seed = record.get("seed_id").and_then(Value::as_str).unwrap_or("?");
    let source = format!("{SOURCE_PREFIX}{run_id}/{variant_id}");
    let case = NewCase {
        id: &id,
        area: "command",
        op: "command.analyze",
        source: &source,
        input: Input { parts: &parts },
        expect: Expect { level: expect },
        tags,
        note: format!("seed {seed}"),
    };
    let line = ascii_json(&serde_json::to_string(&case)?);

    let path = cases_dir.join(&file_name);
    let needs_newline = fs::read(&path)
        .map(|b| !b.is_empty() && !b.ends_with(b"\n"))
        .unwrap_or(false);
    let mut fh = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    if needs_newline {
        fh.write_all(b"\n")?;
    }
    fh.write_all(line.as_bytes())?;
    fh.write_all(b"\n")?;
    Ok(Added { id, file: path })
}

fn find_variant(path: &Path, variant_id: &str) -> Result<serde_json::Map<String, Value>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .with_context(|| format!("{}:{}: invalid JSON", path.display(), n + 1))?;
        if let Value::Object(m) = v
            && m.get("id").and_then(Value::as_str) == Some(variant_id)
        {
            return Ok(m);
        }
    }
    bail!("variant {variant_id} not found in {}", path.display())
}

/// Refuses an id that exists anywhere in `cases/`, and a payload that is
/// already the input of another `command.analyze` case.
fn check_duplicates(cases_dir: &Path, id: &str, text: &str) -> Result<()> {
    let mut ids = HashSet::new();
    for f in jsonl_files(cases_dir)? {
        for c in read_jsonl::<Case>(&f)? {
            let c = c.value;
            if c.op == "command.analyze"
                && let Some(input) = &c.input
                && resolve_text(input).is_ok_and(|t| t == text)
            {
                bail!("duplicate: same input as `{}`", c.id);
            }
            ids.insert(c.id);
        }
    }
    if ids.contains(id) {
        bail!("duplicate: `{id}` already exists");
    }
    Ok(())
}

/// Escapes every non-ASCII character as `\uXXXX` (surrogate pairs above the
/// BMP), so invisible characters stay visible in the file. Non-ASCII only
/// occurs inside JSON strings, where the escape means the same thing.
fn ascii_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for ch in json.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let mut buf = [0u16; 2];
            for unit in ch.encode_utf16(&mut buf) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "pw-xtask-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
            ));
            let p = PathBuf::from(p.to_string_lossy().replace([' ', ':', '{', '}', ','], "_"));
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn split6(s: &str) -> Vec<String> {
        let chars: Vec<char> = s.chars().collect();
        chars.chunks(6).map(|c| c.iter().collect()).collect()
    }

    fn setup() -> (TempDir, PathBuf, PathBuf, String) {
        let tmp = TempDir::new("add");
        let cases = tmp.0.join("cases");
        let run = tmp.0.join("run-20261125");
        fs::create_dir_all(&cases).unwrap();
        fs::create_dir_all(&run).unwrap();
        let exec = ["ms", "hta"].concat();
        let payload = format!("{exec} https://example.invalid/a\u{200b}b");
        let record = serde_json::json!({
            "id": "g0abc123",
            "seed_id": "command.bypass.base-001",
            "round": 2,
            "generator": "g0",
            "techniques": ["cmd.caret", "common.padding"],
            "shell": "cmd",
            "parts": split6(&payload),
        });
        fs::write(run.join("variants.jsonl"), format!("{record}\n")).unwrap();
        fs::write(
            cases.join("command-x.jsonl"),
            "{\"id\":\"command.x.001\",\"area\":\"command\",\"op\":\"command.analyze\",\"source\":\"new\",\"input\":\"echo hi\",\"expect\":{\"level\":\"none\"}}\n",
        )
        .unwrap();
        (tmp, cases, run, payload)
    }

    #[test]
    fn copies_parts_verbatim_and_refuses_duplicates() {
        let (_tmp, cases, run, payload) = setup();
        let added = add_from_run(&cases, &run, "g0abc123", "malicious", None).unwrap();
        assert_eq!(added.id, "command.redteam.g0abc123");
        assert_eq!(added.file, cases.join("redteam-2.jsonl"));

        let text = fs::read_to_string(&added.file).unwrap();
        assert!(text.is_ascii(), "non-ASCII must be escaped");
        let [l] = read_jsonl::<Case>(&added.file).unwrap().try_into().unwrap();
        let c = l.value;
        assert_eq!(c.area, "command");
        assert_eq!(c.op, "command.analyze");
        assert_eq!(c.source, "redteam:run-20261125/g0abc123");
        assert_eq!(c.expect, serde_json::json!({"level": "malicious"}));
        assert_eq!(c.tags, ["redteam", "g0", "cmd.caret", "common.padding"]);
        let input = c.input.unwrap();
        assert_eq!(input["parts"], serde_json::json!(split6(&payload)));
        assert_eq!(resolve_text(&input).unwrap(), payload);
        // Every literal piece passes the corpus leak scan.
        for p in split6(&payload) {
            assert!(!crate::looks_like_malicious_command(&p));
        }

        let again = add_from_run(&cases, &run, "g0abc123", "malicious", None);
        assert!(again.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn refuses_same_payload_under_another_id() {
        let (_tmp, cases, run, payload) = setup();
        let other = serde_json::json!({"id": "g0other", "round": 2, "parts": split6(&payload)});
        let mut lines = fs::read_to_string(run.join("variants.jsonl")).unwrap();
        lines.push_str(&format!("{other}\n"));
        fs::write(run.join("variants.jsonl"), lines).unwrap();
        add_from_run(&cases, &run, "g0abc123", "malicious", Some("redteam-r1")).unwrap();
        assert!(cases.join("redteam-r1.jsonl").exists());
        let err = add_from_run(&cases, &run, "g0other", "malicious", None).unwrap_err();
        assert!(err.to_string().contains("same input"));
    }

    #[test]
    fn validates_arguments() {
        let (_tmp, cases, run, _) = setup();
        assert!(add_from_run(&cases, &run, "g0abc123", "evil", None).is_err());
        assert!(add_from_run(&cases, &run, "../x", "malicious", None).is_err());
        assert!(add_from_run(&cases, &run, "missing", "malicious", None).is_err());
        assert!(add_from_run(&cases, &run, "g0abc123", "malicious", Some("cases")).is_err());
        assert!(cli(&["only-one"], &cases).is_err());
    }

    #[test]
    fn ascii_json_escapes_astral_as_surrogates() {
        assert_eq!(
            ascii_json("\"a\u{200b}\u{e0041}\""),
            "\"a\\u200b\\udb40\\udc41\""
        );
    }
}
