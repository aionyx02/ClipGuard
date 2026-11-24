//! Pastejacking data in `rules/pastejack/` (docs/spec/detection-rules.md §7),
//! embedded at build time and parsed once.
//!
//! - `signals.json`: command signals (program invocations and regex patterns)
//! - `hidden-chars.json`: invisible characters counted and stripped
//!
//! Broken data never panics: [`PastejackRules::embedded`] falls back to empty lists
//! (a unit test guarantees the embedded files load and validate).

use std::ops::RangeInclusive;
use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;

const SIGNALS_JSON: &str = include_str!("../../../../rules/pastejack/signals.json");
const HIDDEN_CHARS_JSON: &str = include_str!("../../../../rules/pastejack/hidden-chars.json");

/// JS `\s` / `\S` as regex classes (the `{WS}` / `{NWS}` placeholders).
const WS: &str = r"[\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]";
const NWS: &str = r"[^\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]";
/// ASCII word boundary (the `{b}` placeholder; JS `\b` without the `u` flag).
const ASCII_BOUNDARY: &str = r"(?-u:\b)";

#[derive(Deserialize)]
struct SignalFile {
    id: String,
    #[serde(default)]
    invocation: Vec<String>,
    #[serde(default)]
    regex: Option<String>,
}

#[derive(Deserialize)]
struct SignalsFile {
    signals: Vec<SignalFile>,
}

#[derive(Deserialize)]
struct HiddenCharsFile {
    ranges: Vec<[String; 2]>,
}

/// How a signal matches.
#[derive(Debug, Clone)]
pub enum SignalMatcher {
    /// Lowercase program names that count when invoked.
    Invocation(Vec<String>),
    /// Runs on the ASCII-lowercased text.
    Regex(Regex),
}

/// One command signal.
#[derive(Debug, Clone)]
pub struct SignalRule {
    pub id: String,
    pub matcher: SignalMatcher,
}

/// All pastejacking data.
#[derive(Debug, Clone, Default)]
pub struct PastejackRules {
    pub signals: Vec<SignalRule>,
    pub hidden_chars: Vec<RangeInclusive<char>>,
}

fn code_point(s: &str) -> Option<char> {
    s.strip_prefix("U+")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .and_then(char::from_u32)
}

/// Expands `{b}`, `{WS}`, `{NWS}`.
pub fn expand_placeholders(pattern: &str) -> String {
    pattern
        .replace("{b}", ASCII_BOUNDARY)
        .replace("{NWS}", NWS)
        .replace("{WS}", WS)
}

impl PastejackRules {
    /// Parses and validates the embedded files. Errors name the file that failed.
    pub fn load() -> Result<PastejackRules, String> {
        let signals: SignalsFile = serde_json::from_str(SIGNALS_JSON)
            .map_err(|e| format!("rules/pastejack/signals.json: {e}"))?;
        let hidden: HiddenCharsFile = serde_json::from_str(HIDDEN_CHARS_JSON)
            .map_err(|e| format!("rules/pastejack/hidden-chars.json: {e}"))?;
        let mut problems = Vec::new();

        let mut rules = Vec::new();
        for s in signals.signals {
            if rules.iter().any(|r: &SignalRule| r.id == s.id) {
                problems.push(format!("signals: duplicate id {:?}", s.id));
            }
            let matcher = match (s.invocation.is_empty(), &s.regex) {
                (false, None) => {
                    let ok = s.invocation.iter().all(|n| {
                        !n.is_empty()
                            && n.chars()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    });
                    if !ok {
                        problems.push(format!("signals.{}: invalid program name", s.id));
                    }
                    SignalMatcher::Invocation(s.invocation)
                }
                (true, Some(p)) if !p.is_empty() => match Regex::new(&expand_placeholders(p)) {
                    Ok(re) => SignalMatcher::Regex(re),
                    Err(e) => {
                        problems.push(format!("signals.{}: regex does not compile: {e}", s.id));
                        continue;
                    }
                },
                _ => {
                    problems.push(format!(
                        "signals.{}: needs exactly one of invocation / regex",
                        s.id
                    ));
                    continue;
                }
            };
            rules.push(SignalRule { id: s.id, matcher });
        }
        if rules.is_empty() {
            problems.push("signals: empty list".into());
        }

        let mut hidden_chars = Vec::new();
        for r in &hidden.ranges {
            match (code_point(&r[0]), code_point(&r[1])) {
                (Some(a), Some(b)) if a <= b => hidden_chars.push(a..=b),
                _ => problems.push(format!("hidden-chars: invalid range {r:?}")),
            }
        }
        if hidden_chars.is_empty() {
            problems.push("hidden-chars: empty list".into());
        }

        if !problems.is_empty() {
            return Err(problems.join("; "));
        }
        Ok(PastejackRules {
            signals: rules,
            hidden_chars,
        })
    }

    /// The embedded rules, parsed once (empty lists if they are broken).
    pub fn embedded() -> &'static PastejackRules {
        static RULES: OnceLock<PastejackRules> = OnceLock::new();
        RULES.get_or_init(|| PastejackRules::load().unwrap_or_default())
    }

    pub fn signal(&self, id: &str) -> Option<&SignalRule> {
        self.signals.iter().find(|s| s.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_load_and_validate() {
        let rules = PastejackRules::load().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(rules.signals.len(), 7);
        for s in &rules.signals {
            if let SignalMatcher::Regex(re) = &s.matcher {
                assert!(
                    ["{b}", "{WS}", "{NWS}"]
                        .iter()
                        .all(|p| !re.as_str().contains(p)),
                    "{}: unexpanded placeholder",
                    s.id
                );
            }
        }
        assert!(rules.hidden_chars.iter().any(|r| r.contains(&'\u{200B}')));
    }

    #[test]
    fn placeholders() {
        assert_eq!(expand_placeholders("{b}x{WS}{NWS}").matches('[').count(), 2);
        assert!(expand_placeholders("{b}").starts_with("(?-u"));
    }
}
