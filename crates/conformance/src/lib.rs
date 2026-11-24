//! Runs the corpus against the Rust engine.
//!
//! - `corpus/cases/*.jsonl`: every case must pass, unless its id is listed in
//!   `corpus/divergences/*.toml` (Phase 1 §1.4).
//! - `corpus/benign/*.jsonl`: false-positive metrics only (never fails the run).
//!
//! Each area adapter in [`ops`] maps an `op` to engine calls and checks the case's
//! `expect` with [`Expect`]. Every `expect` key must be consumed by the adapter;
//! leftover keys are failures, so an unimplemented check can never pass silently.
#![forbid(unsafe_code)]

pub mod check;
pub mod ops;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context as _, Result};
use paste_warden_corpus::{Case, Located, jsonl_files, read_jsonl, resolve_all, resolve_text};
use paste_warden_i18n::Localizer;
use serde::Deserialize;
use serde_json::Value;

pub use check::Expect;

/// Repository root (two levels above this crate).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root")
        .to_path_buf()
}

/// Everything an adapter needs to run one case.
pub struct Ctx<'a> {
    pub case: &'a Case,
    /// Resolved `input` (`""` when absent: legacy `null`).
    pub input: String,
    /// Whether the case had an `input` at all (some ops distinguish legacy `null`).
    pub has_input: bool,
    /// Resolved `args` (`Value::Null` when absent).
    pub args: Value,
    /// Resolved `events`.
    pub events: Vec<Value>,
    /// UI locale for rendered messages: `zh-TW` unless wrapped by `i18n.localized`.
    pub locale: &'static str,
}

impl Ctx<'_> {
    /// Localizer for this case's locale.
    pub fn loc(&self) -> &'static Localizer {
        localizer(self.locale)
    }

    /// Renders an engine message in this case's locale.
    pub fn render(&self, msg: &paste_warden_core::Message) -> String {
        self.loc().format(msg)
    }

    /// `args.<name>`, if present and not null.
    pub fn arg(&self, name: &str) -> Option<&Value> {
        self.args.get(name).filter(|v| !v.is_null())
    }

    pub fn arg_str(&self, name: &str) -> Option<&str> {
        self.arg(name).and_then(Value::as_str)
    }

    pub fn arg_i64(&self, name: &str) -> Option<i64> {
        self.arg(name).and_then(Value::as_i64)
    }

    pub fn arg_bool(&self, name: &str) -> Option<bool> {
        self.arg(name).and_then(Value::as_bool)
    }

    /// `args.<name>` as a list of strings.
    pub fn arg_strings(&self, name: &str) -> Option<Vec<String>> {
        self.arg(name).and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
    }
}

/// Cached localizers (loading Fluent bundles is not free).
pub fn localizer(locale: &str) -> &'static Localizer {
    static EN: OnceLock<Localizer> = OnceLock::new();
    static ZH: OnceLock<Localizer> = OnceLock::new();
    if locale.eq_ignore_ascii_case("en") {
        EN.get_or_init(|| Localizer::new("en"))
    } else {
        ZH.get_or_init(|| Localizer::new("zh-TW"))
    }
}

/// Result of running one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail(Vec<String>),
    /// No adapter handles this op yet.
    Unimplemented,
    /// The adapter could not run the case (bad args, engine error).
    Error(String),
}

/// Builds the context for a case and runs it (in `locale`).
pub fn run_case_in(case: &Case, locale: &'static str) -> Outcome {
    let build = || -> Result<Ctx<'_>> {
        Ok(Ctx {
            case,
            input: match &case.input {
                Some(v) if !v.is_null() => resolve_text(v)?,
                _ => String::new(),
            },
            has_input: case.input.as_ref().is_some_and(|v| !v.is_null()),
            args: match &case.args {
                Some(v) => resolve_all(v)?,
                None => Value::Null,
            },
            events: case
                .events
                .iter()
                .flatten()
                .map(resolve_all)
                .collect::<Result<_>>()?,
            locale,
        })
    };
    let ctx = match build() {
        Ok(c) => c,
        Err(e) => return Outcome::Error(format!("{e:#}")),
    };
    run_ctx(&ctx, &case.op, &case.expect)
}

/// Runs `op` with an already-built context and checks `expect`.
pub fn run_ctx(ctx: &Ctx<'_>, op: &str, expect: &Value) -> Outcome {
    let mut exp = match Expect::new(expect) {
        Ok(e) => e,
        Err(e) => return Outcome::Error(e),
    };
    match ops::dispatch(op, ctx, &mut exp) {
        None => Outcome::Unimplemented,
        Some(Err(e)) => Outcome::Error(format!("{e:#}")),
        Some(Ok(())) => {
            let failures = exp.finish();
            if failures.is_empty() {
                Outcome::Pass
            } else {
                Outcome::Fail(failures)
            }
        }
    }
}

pub fn run_case(case: &Case) -> Outcome {
    run_case_in(case, "zh-TW")
}

/// Contents of one `corpus/divergences/*.toml` file.
#[derive(Debug, Default, Deserialize)]
pub struct Divergences {
    #[serde(default)]
    pub divergence: Vec<Divergence>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Divergence {
    pub id: String,
    pub kind: String,
    pub reason: String,
    #[serde(default)]
    pub issue: Option<String>,
}

pub const DIVERGENCE_KINDS: &[&str] = &["bugfix", "intentional", "legacy-js", "unicode-count"];

/// Loads `corpus/divergences/*.toml` (one file per area, merged).
pub fn load_divergences() -> Result<Divergences> {
    let dir = repo_root().join("corpus/divergences");
    let mut all = Divergences::default();
    if !dir.exists() {
        return Ok(all);
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    for path in files {
        let text = std::fs::read_to_string(&path)?;
        let d: Divergences =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        all.divergence.extend(d.divergence);
    }
    Ok(all)
}

/// Which cases to run.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub area: Option<String>,
    pub op: Option<String>,
    /// Case id prefix.
    pub id: Option<String>,
}

impl Filter {
    /// Reads `PW_CORPUS_AREA`, `PW_CORPUS_OP`, `PW_CORPUS_ID` (used by tests).
    pub fn from_env() -> Filter {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Filter {
            area: get("PW_CORPUS_AREA"),
            op: get("PW_CORPUS_OP"),
            id: get("PW_CORPUS_ID"),
        }
    }

    fn matches(&self, c: &Case) -> bool {
        self.area.as_ref().is_none_or(|a| &c.area == a)
            && self
                .op
                .as_ref()
                .is_none_or(|o| &c.op == o || c.op.starts_with(&format!("{o}.")))
            && self
                .id
                .as_ref()
                .is_none_or(|p| c.id.starts_with(p.as_str()))
    }
}

/// One case's result in a run.
#[derive(Debug, Clone)]
pub struct CaseResult {
    pub id: String,
    pub op: String,
    pub file: PathBuf,
    pub line: usize,
    pub outcome: Outcome,
    pub divergence: Option<Divergence>,
}

impl CaseResult {
    /// Counts against the run: a non-pass that is not covered by a divergence.
    pub fn is_failure(&self) -> bool {
        self.outcome != Outcome::Pass && self.divergence.is_none()
    }
}

/// Summary of a corpus run.
#[derive(Debug, Default)]
pub struct Summary {
    pub results: Vec<CaseResult>,
    /// Divergence ids that are listed but now pass (should be removed).
    pub stale_divergences: Vec<String>,
    /// Divergence ids not found in the corpus or with an unknown kind.
    pub bad_divergences: Vec<String>,
}

impl Summary {
    pub fn failures(&self) -> impl Iterator<Item = &CaseResult> {
        self.results.iter().filter(|r| r.is_failure())
    }

    /// (pass, fail, unimplemented, error, diverged) per op.
    pub fn per_op(&self) -> BTreeMap<String, [usize; 5]> {
        let mut m: BTreeMap<String, [usize; 5]> = BTreeMap::new();
        for r in &self.results {
            let e = m.entry(r.op.clone()).or_default();
            let slot = if r.divergence.is_some() && r.outcome != Outcome::Pass {
                4
            } else {
                match r.outcome {
                    Outcome::Pass => 0,
                    Outcome::Fail(_) => 1,
                    Outcome::Unimplemented => 2,
                    Outcome::Error(_) => 3,
                }
            };
            e[slot] += 1;
        }
        m
    }
}

fn load_dir(dir: &Path) -> Result<Vec<Located<Case>>> {
    let mut out = Vec::new();
    for f in jsonl_files(dir)? {
        out.extend(read_jsonl::<Case>(&f)?);
    }
    Ok(out)
}

/// Runs every case in `corpus/cases` that matches `filter`.
pub fn run_cases(filter: &Filter) -> Result<Summary> {
    let cases = load_dir(&repo_root().join("corpus/cases"))?;
    let divs = load_divergences()?;
    let by_id: HashMap<&str, &Divergence> =
        divs.divergence.iter().map(|d| (d.id.as_str(), d)).collect();
    let mut summary = Summary::default();
    for d in &divs.divergence {
        if !DIVERGENCE_KINDS.contains(&d.kind.as_str()) {
            summary
                .bad_divergences
                .push(format!("{}: unknown kind `{}`", d.id, d.kind));
        }
        if d.reason.trim().is_empty() {
            summary
                .bad_divergences
                .push(format!("{}: empty reason", d.id));
        }
        if !cases.iter().any(|c| c.value.id == d.id) {
            summary
                .bad_divergences
                .push(format!("{}: no such case", d.id));
        }
    }
    for l in cases.iter().filter(|l| filter.matches(&l.value)) {
        let outcome = run_case(&l.value);
        let divergence = by_id.get(l.value.id.as_str()).map(|d| (*d).clone());
        if divergence.is_some() && outcome == Outcome::Pass {
            summary.stale_divergences.push(l.value.id.clone());
        }
        summary.results.push(CaseResult {
            id: l.value.id.clone(),
            op: l.value.op.clone(),
            file: l.file.clone(),
            line: l.line,
            outcome,
            divergence,
        });
    }
    Ok(summary)
}

/// False-positive metrics for one benign file.
#[derive(Debug, Default, Clone)]
pub struct BenignStats {
    pub total: usize,
    /// Flagged as a problem (malicious command, any secret, any hidden-char warning).
    pub flagged: usize,
    /// Commands judged Suspicious that are not tagged `installer`.
    pub warned: usize,
    /// Cases tagged `spec-escalates` (expected to be flagged until Phase 1b).
    pub expected_escalations: usize,
    pub unimplemented: usize,
    pub flagged_ids: Vec<String>,
}

/// Runs the benign corpora and counts false positives per file.
pub fn run_benign(filter: &Filter) -> Result<BTreeMap<String, BenignStats>> {
    let cases = load_dir(&repo_root().join("corpus/benign"))?;
    let mut out: BTreeMap<String, BenignStats> = BTreeMap::new();
    for l in cases.iter().filter(|l| filter.matches(&l.value)) {
        let file = l
            .file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let stats = out.entry(file).or_default();
        stats.total += 1;
        match ops::benign_verdict(&l.value) {
            None => stats.unimplemented += 1,
            Some(Err(e)) => {
                stats.flagged += 1;
                stats
                    .flagged_ids
                    .push(format!("{} (error: {e:#})", l.value.id));
            }
            Some(Ok(v)) => {
                if v == ops::BenignVerdict::Flagged {
                    if l.value.tags.iter().any(|t| t == "spec-escalates") {
                        stats.expected_escalations += 1;
                    } else {
                        stats.flagged += 1;
                        stats.flagged_ids.push(l.value.id.clone());
                    }
                } else if v == ops::BenignVerdict::Warned
                    && !l.value.tags.iter().any(|t| t == "installer")
                {
                    stats.warned += 1;
                }
            }
        }
    }
    Ok(out)
}
