//! Corpus case types, `Text` resolution and loading.
//!
//! The format is defined in `corpus/README.md`. This crate is shared by `xtask`
//! (lint / coverage) and, from Phase 1 on, by the engine's corpus tests.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use serde_json::Value;

/// Upper bound for a resolved `Text`, in chars. Keeps corpus files from
/// describing absurd inputs by accident.
pub const MAX_TEXT_CHARS: usize = 8 << 20;

/// Areas allowed in `cases/*.jsonl` (see corpus/README.md §1).
pub const AREAS: &[&str] = &[
    "command",
    "secret",
    "hidden",
    "wallet",
    "entry",
    "guard",
    "throttle",
    "paste",
    "registered",
    "limits",
    "pastejack",
    "i18n",
    "checksum",
];

/// One corpus case (one line of `cases/*.jsonl` or `benign/*.jsonl`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub area: String,
    pub op: String,
    pub source: String,
    #[serde(default)]
    pub input: Option<Value>,
    #[serde(default)]
    pub args: Option<Value>,
    #[serde(default)]
    pub events: Option<Vec<Value>>,
    pub expect: Value,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// A case together with where it was read from.
#[derive(Debug, Clone)]
pub struct Located<T> {
    pub file: PathBuf,
    pub line: usize,
    pub value: T,
}

/// One line of `legacy-properties.jsonl`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyProperty {
    pub source: String,
    pub disposition: Disposition,
    #[serde(default)]
    pub requirement: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Property,
    Obsolete,
    Covered,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LegacyIndex {
    pub generated_from_commit: String,
    pub entries: Vec<LegacyEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LegacyEntry {
    pub id: String,
    pub kind: String,
}

/// Reads every non-empty line of a JSONL file as `T`.
pub fn read_jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<Located<T>>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str(line)
            .with_context(|| format!("{}:{}: invalid case", path.display(), i + 1))?;
        out.push(Located {
            file: path.to_path_buf(),
            line: i + 1,
            value,
        });
    }
    Ok(out)
}

/// All `*.jsonl` files directly inside `dir`, sorted.
pub fn jsonl_files(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    Ok(files)
}

/// Named charsets for `rand` (corpus/README.md §2).
pub fn charset(name: &str) -> Option<Vec<char>> {
    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
    const DIGITS: &str = "0123456789";
    let s: String = match name {
        "hex" => "0123456789abcdef".into(),
        "HEX" => "0123456789ABCDEF".into(),
        "alnum" => format!("{UPPER}{LOWER}{DIGITS}"),
        "lower" => format!("{LOWER}{DIGITS}"),
        "upper" => format!("{UPPER}{DIGITS}"),
        "digits" => DIGITS.into(),
        "base64" => format!("{UPPER}{LOWER}{DIGITS}+/"),
        "base64url" => format!("{UPPER}{LOWER}{DIGITS}-_"),
        other if other.chars().count() >= 2 => other.into(),
        _ => return None,
    };
    Some(s.chars().collect())
}

/// The legacy test generator: a 31-bit LCG. `skip` advances the stream first,
/// so a legacy `Gen` that produced several strings in a row can be replayed.
pub fn rand_string(seed: u32, charset: &[char], len: usize, skip: usize) -> String {
    let mut state = seed;
    let mut next = || {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345) & 0x7fff_ffff;
        charset[(state >> 8) as usize % charset.len()]
    };
    for _ in 0..skip {
        next();
    }
    (0..len).map(|_| next()).collect()
}

/// Is this JSON value a `Text` object (as opposed to a plain argument object)?
pub fn is_text_object(v: &Value) -> bool {
    match v {
        Value::Object(m) => {
            m.len() == 1
                && ["parts", "rand", "repeat"]
                    .iter()
                    .any(|k| m.contains_key(*k))
        }
        _ => false,
    }
}

/// Resolves a `Text` value to a string.
pub fn resolve_text(v: &Value) -> Result<String> {
    let mut out = String::new();
    resolve_into(v, &mut out)?;
    Ok(out)
}

fn resolve_into(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::String(s) => out.push_str(s),
        Value::Object(m) if m.len() == 1 => {
            if let Some(parts) = m.get("parts") {
                let Value::Array(parts) = parts else {
                    bail!("`parts` must be an array");
                };
                for p in parts {
                    resolve_into(p, out)?;
                }
            } else if let Some(r) = m.get("rand") {
                let seed = r.get("seed").and_then(Value::as_u64).context("rand.seed")?;
                let name = r
                    .get("charset")
                    .and_then(Value::as_str)
                    .context("rand.charset")?;
                let len = r.get("len").and_then(Value::as_u64).context("rand.len")? as usize;
                let skip = r.get("skip").and_then(Value::as_u64).unwrap_or(0) as usize;
                let Some(cs) = charset(name) else {
                    bail!("unknown charset `{name}`");
                };
                if len > MAX_TEXT_CHARS {
                    bail!("rand.len too large");
                }
                let seed = u32::try_from(seed).context("rand.seed must fit in u32")?;
                out.push_str(&rand_string(seed, &cs, len, skip));
            } else if let Some(r) = m.get("repeat") {
                let count = r
                    .get("count")
                    .and_then(Value::as_u64)
                    .context("repeat.count")?;
                let unit = resolve_text(r.get("text").context("repeat.text")?)?;
                let total = unit.chars().count().saturating_mul(count as usize);
                if total > MAX_TEXT_CHARS {
                    bail!("repeat expands to {total} chars (max {MAX_TEXT_CHARS})");
                }
                out.push_str(&unit.repeat(count as usize));
            } else {
                bail!("not a Text object: {v}");
            }
        }
        _ => bail!("not a Text value: {v}"),
    }
    if out.chars().count() > MAX_TEXT_CHARS {
        bail!("text longer than {MAX_TEXT_CHARS} chars");
    }
    Ok(())
}

/// Every string that appears *literally* in a JSON value (Text parts included),
/// with a JSON-pointer-ish path. Used by the leak scan, which must look at the
/// pieces as written in the file, not at the resolved text.
pub fn literal_strings(v: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => out.push((path.to_string(), s.clone())),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                literal_strings(x, &format!("{path}/{i}"), out);
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                literal_strings(x, &format!("{path}/{k}"), out);
            }
        }
        _ => {}
    }
}

/// Resolves every `Text` object inside a JSON value, leaving other values as is.
pub fn resolve_all(v: &Value) -> Result<Value> {
    if is_text_object(v) {
        return Ok(Value::String(resolve_text(v)?));
    }
    Ok(match v {
        Value::Array(a) => Value::Array(a.iter().map(resolve_all).collect::<Result<_>>()?),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| Ok((k.clone(), resolve_all(x)?)))
                .collect::<Result<_>>()?,
        ),
        other => other.clone(),
    })
}

/// Counts cases per op, handy for reports.
pub fn ops_histogram<'a>(cases: impl IntoIterator<Item = &'a Case>) -> BTreeMap<String, usize> {
    let mut h = BTreeMap::new();
    for c in cases {
        *h.entry(c.op.clone()).or_insert(0) += 1;
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rand_matches_reference_vectors() {
        // Computed with the Python and JS implementations of the same LCG.
        let hex = charset("hex").unwrap();
        assert_eq!(
            rand_string(26, &hex, 32, 0),
            "7523db184189a13398d2e2324a1e9d33"
        );
        let alnum = charset("alnum").unwrap();
        assert_eq!(rand_string(7, &alnum, 20, 0), "vjmF2UIqqVeAnNKiLXUT");
    }

    #[test]
    fn skip_continues_the_stream() {
        let hex = charset("hex").unwrap();
        let whole = rand_string(26, &hex, 32, 0);
        assert_eq!(rand_string(26, &hex, 12, 20), whole[20..]);
    }

    #[test]
    fn resolves_nested_text() {
        let v = json!({"parts": ["a", {"repeat": {"text": "b", "count": 3}}, "c"]});
        assert_eq!(resolve_text(&v).unwrap(), "abbbc");
    }

    #[test]
    fn rejects_oversized_repeat() {
        let v = json!({"repeat": {"text": "ab", "count": MAX_TEXT_CHARS}});
        assert!(resolve_text(&v).is_err());
    }

    #[test]
    fn resolve_all_only_touches_text_objects() {
        let v = json!({"packs": ["tw"], "target": {"process": {"parts": ["a", "b"]}}});
        assert_eq!(
            resolve_all(&v).unwrap(),
            json!({"packs": ["tw"], "target": {"process": "ab"}})
        );
    }
}
