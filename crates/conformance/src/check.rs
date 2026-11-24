//! Checking a case's `expect` object.
//!
//! Adapters call [`Expect`]'s methods for the keys their op understands. Each
//! method is a no-op when the key is absent, records a failure when the actual
//! value disagrees, and marks the key as consumed. [`Expect::finish`] reports
//! any key nobody consumed, so a typo or an unimplemented check fails loudly.
//!
//! Structured comparisons ([`partial_match`]) compare only the keys present in
//! the expected object, plus two suffix conventions used across the corpus:
//! `<field>_contain: [..]` (every string is a substring of `<field>`) and
//! `<field>_not_contain: [..]` (none is).

use std::collections::HashSet;

use serde_json::{Map, Value};

pub struct Expect {
    map: Map<String, Value>,
    used: HashSet<String>,
    failures: Vec<String>,
}

fn show(v: &Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 160 {
        format!("{}…", s.chars().take(160).collect::<String>())
    } else {
        s
    }
}

/// Strings from a JSON value that is either a string or an array of strings.
pub fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

impl Expect {
    /// `expect` must be a JSON object.
    pub fn new(v: &Value) -> Result<Expect, String> {
        match v {
            Value::Object(m) => Ok(Expect {
                map: m.clone(),
                used: HashSet::new(),
                failures: Vec::new(),
            }),
            other => Err(format!("expect must be an object, got {}", show(other))),
        }
    }

    /// Is `key` present (without consuming it)?
    pub fn has(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// All keys of the expect object.
    pub fn keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    /// Consumes and returns `key`.
    pub fn take(&mut self, key: &str) -> Option<Value> {
        let v = self.map.get(key).cloned();
        if v.is_some() {
            self.used.insert(key.to_owned());
        }
        v
    }

    /// Records a failure.
    pub fn fail(&mut self, msg: impl Into<String>) {
        self.failures.push(msg.into());
    }

    /// Failures recorded so far plus every unconsumed key.
    pub fn finish(mut self) -> Vec<String> {
        let mut unused: Vec<&String> = self
            .map
            .keys()
            .filter(|k| !self.used.contains(*k))
            .collect();
        unused.sort();
        for k in unused {
            self.failures.push(format!(
                "expect.{k}: not checked by the adapter (unsupported key)"
            ));
        }
        self.failures
    }

    /// Merges a nested expectation (e.g. one event's `expect`) under `prefix`.
    pub fn absorb(&mut self, prefix: &str, sub: Expect) {
        for f in sub.finish() {
            self.failures.push(format!("{prefix}: {f}"));
        }
    }

    /// `key` must equal `actual` (JSON equality).
    pub fn eq(&mut self, key: &str, actual: impl Into<Value>) {
        if let Some(exp) = self.take(key) {
            let actual = actual.into();
            if exp != actual {
                self.fail(format!(
                    "expect.{key}: expected {}, got {}",
                    show(&exp),
                    show(&actual)
                ));
            }
        }
    }

    /// `key` must NOT equal `actual`.
    pub fn ne(&mut self, key: &str, actual: impl Into<Value>) {
        if let Some(exp) = self.take(key) {
            let actual = actual.into();
            if exp == actual {
                self.fail(format!(
                    "expect.{key}: expected anything but {}",
                    show(&exp)
                ));
            }
        }
    }

    /// Every expected string must be a substring of some item in `actual`.
    pub fn contain_in_any(&mut self, key: &str, actual: &[String]) {
        if let Some(exp) = self.take(key) {
            for e in strings(&exp) {
                if !actual.iter().any(|a| a.contains(&e)) {
                    self.fail(format!(
                        "expect.{key}: no item contains {e:?}; got {actual:?}"
                    ));
                }
            }
        }
    }

    /// No item in `actual` may contain any expected string.
    pub fn contain_in_none(&mut self, key: &str, actual: &[String]) {
        if let Some(exp) = self.take(key) {
            for e in strings(&exp) {
                if let Some(a) = actual.iter().find(|a| a.contains(&e)) {
                    self.fail(format!("expect.{key}: {a:?} contains {e:?}"));
                }
            }
        }
    }

    /// Every expected string must be an item of `actual` (exact).
    pub fn include_all(&mut self, key: &str, actual: &[String]) {
        if let Some(exp) = self.take(key) {
            for e in strings(&exp) {
                if !actual.contains(&e) {
                    self.fail(format!("expect.{key}: {e:?} not among {actual:?}"));
                }
            }
        }
    }

    /// Every expected string must be a substring of `actual`.
    pub fn text_contains(&mut self, key: &str, actual: &str) {
        if let Some(exp) = self.take(key) {
            for e in strings(&exp) {
                if !actual.contains(&e) {
                    self.fail(format!("expect.{key}: {actual:?} does not contain {e:?}"));
                }
            }
        }
    }

    /// No expected string may be a substring of `actual`.
    pub fn text_not_contains(&mut self, key: &str, actual: &str) {
        if let Some(exp) = self.take(key) {
            for e in strings(&exp) {
                if actual.contains(&e) {
                    self.fail(format!("expect.{key}: {actual:?} contains {e:?}"));
                }
            }
        }
    }

    pub fn starts_with(&mut self, key: &str, actual: &str) {
        if let Some(exp) = self.take(key) {
            let e = exp.as_str().unwrap_or_default();
            if !actual.starts_with(e) {
                self.fail(format!(
                    "expect.{key}: {actual:?} does not start with {e:?}"
                ));
            }
        }
    }

    pub fn ends_with(&mut self, key: &str, actual: &str) {
        if let Some(exp) = self.take(key) {
            let e = exp.as_str().unwrap_or_default();
            if !actual.ends_with(e) {
                self.fail(format!("expect.{key}: {actual:?} does not end with {e:?}"));
            }
        }
    }

    /// `actual`'s UTF-16 length must be ≤ the expected number.
    pub fn max_utf16(&mut self, key: &str, actual: &str) {
        if let Some(exp) = self.take(key) {
            let max = exp.as_u64().unwrap_or(0) as usize;
            let len = paste_warden_core::text::utf16_len(actual);
            if len > max {
                self.fail(format!("expect.{key}: length {len} > {max}"));
            }
        }
    }

    /// `actual` (a list of objects) must match the expected list exactly in
    /// length and order; each item is compared with [`partial_match`].
    pub fn list_exact(&mut self, key: &str, actual: &[Value]) {
        if let Some(exp) = self.take(key) {
            let exp = exp.as_array().cloned().unwrap_or_default();
            if exp.len() != actual.len() {
                self.fail(format!(
                    "expect.{key}: expected {} item(s), got {}: {}",
                    exp.len(),
                    actual.len(),
                    show(&Value::Array(actual.to_vec()))
                ));
                return;
            }
            for (i, (e, a)) in exp.iter().zip(actual).enumerate() {
                if let Some(why) = partial_match(e, a) {
                    self.fail(format!("expect.{key}[{i}]: {why}"));
                }
            }
        }
    }

    /// Each expected object must partially match some item of `actual`.
    pub fn list_include(&mut self, key: &str, actual: &[Value]) {
        if let Some(exp) = self.take(key) {
            for (i, e) in exp
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                if !actual.iter().any(|a| partial_match(e, a).is_none()) {
                    self.fail(format!(
                        "expect.{key}[{i}]: no item matches {}; got {}",
                        show(e),
                        show(&Value::Array(actual.to_vec()))
                    ));
                }
            }
        }
    }

    /// No item of `actual` may partially match any expected object.
    pub fn list_exclude(&mut self, key: &str, actual: &[Value]) {
        if let Some(exp) = self.take(key) {
            for e in exp.as_array().cloned().unwrap_or_default() {
                if let Some(a) = actual.iter().find(|a| partial_match(&e, a).is_none()) {
                    self.fail(format!(
                        "expect.{key}: {} matches excluded {}",
                        show(a),
                        show(&e)
                    ));
                }
            }
        }
    }
}

/// Compares only the keys present in `expected` (recursively for objects).
/// Supports `<field>_contain` / `<field>_not_contain` (substring lists) for keys
/// that `actual` does not itself define. Returns a description of the first
/// mismatch, or `None` if it matches.
pub fn partial_match(expected: &Value, actual: &Value) -> Option<String> {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (k, ev) in e {
                if let Some(av) = a.get(k) {
                    if let Some(why) = partial_match(ev, av) {
                        return Some(format!("{k}: {why}"));
                    }
                    continue;
                }
                if let Some(base) = k.strip_suffix("_not_contain") {
                    let hay = a.get(base).and_then(Value::as_str).unwrap_or_default();
                    for s in strings(ev) {
                        if hay.contains(&s) {
                            return Some(format!("{base}: {hay:?} contains {s:?}"));
                        }
                    }
                    continue;
                }
                if let Some(base) = k.strip_suffix("_contain") {
                    let hay = a.get(base).and_then(Value::as_str).unwrap_or_default();
                    for s in strings(ev) {
                        if !hay.contains(&s) {
                            return Some(format!("{base}: {hay:?} does not contain {s:?}"));
                        }
                    }
                    continue;
                }
                if ev.is_null() {
                    continue; // expected null and the field is absent
                }
                return Some(format!("{k}: missing (expected {})", show(ev)));
            }
            None
        }
        (e, a) if e == a => None,
        (e, a) => Some(format!("expected {}, got {}", show(e), show(a))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unconsumed_keys_fail() {
        let mut e = Expect::new(&json!({"level": "none", "typo": 1})).unwrap();
        e.eq("level", "none");
        let f = e.finish();
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("typo"));
    }

    #[test]
    fn partial_match_with_suffixes() {
        let actual = json!({"kind": "api_key", "masked": "ghp_****xyz", "span_utf16": [0, 40]});
        assert!(
            partial_match(
                &json!({"kind": "api_key", "masked_contain": ["*"]}),
                &actual
            )
            .is_none()
        );
        assert!(partial_match(&json!({"masked_not_contain": ["abc"]}), &actual).is_none());
        assert!(partial_match(&json!({"masked_contain": ["#"]}), &actual).is_some());
        assert!(partial_match(&json!({"label": "x"}), &actual).is_some());
    }

    #[test]
    fn list_checks() {
        let actual = vec![json!({"kind": "a", "n": 1}), json!({"kind": "b", "n": 2})];
        let mut e = Expect::new(&json!({
            "m": [{"kind": "a"}, {"kind": "b"}],
            "inc": [{"kind": "b"}],
            "exc": [{"kind": "c"}]
        }))
        .unwrap();
        e.list_exact("m", &actual);
        e.list_include("inc", &actual);
        e.list_exclude("exc", &actual);
        assert!(e.finish().is_empty());
    }
}
