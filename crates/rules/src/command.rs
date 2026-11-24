//! Command-detection data in `rules/command/` (docs/spec/detection-rules.md §3).
//!
//! The engine (`paste-warden-core::command`) keeps the structural logic (where a
//! command starts, pipes, variable expansion); the word lists live here as data:
//!
//! - `programs.json`: programs whose full paths the normalizer shortens, and the
//!   fixed system environment variables it expands
//! - `official-hosts.json`: official installer hosts (§3.2)
//! - `official-paths.json`: official installer URL path prefixes on shared hosts
//!   such as raw.githubusercontent.com (§3.2, phase-1.md §1.8)
//! - `bait-keywords.json`: multilingual bait-comment keywords (§3.1, #27)
//! - `extensions.json`: executable / script file extensions
//!
//! The files are embedded at build time with `include_str!`.

use std::sync::OnceLock;

use serde::Deserialize;

const PROGRAMS_JSON: &str = include_str!("../../../rules/command/programs.json");
const OFFICIAL_HOSTS_JSON: &str = include_str!("../../../rules/command/official-hosts.json");
const OFFICIAL_PATHS_JSON: &str = include_str!("../../../rules/command/official-paths.json");
const BAIT_KEYWORDS_JSON: &str = include_str!("../../../rules/command/bait-keywords.json");
const EXTENSIONS_JSON: &str = include_str!("../../../rules/command/extensions.json");

/// A fixed environment variable (`%SystemRoot%` → `C:\Windows`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// An official installer host.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OfficialHost {
    pub host: String,
    #[serde(default)]
    pub note: String,
}

/// An official installer URL prefix on a shared host: `host/segment/…/` (always
/// ends with `/`, at least two path segments).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OfficialPath {
    pub prefix: String,
    #[serde(default)]
    pub note: String,
}

impl OfficialPath {
    /// The host part (before the first `/`).
    pub fn host(&self) -> &str {
        self.prefix.split('/').next().unwrap_or_default()
    }

    /// The path segments after the host (without the trailing empty one).
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.prefix.split('/').skip(1).filter(|s| !s.is_empty())
    }
}

#[derive(Deserialize)]
struct PathsFile {
    prefixes: Vec<OfficialPath>,
}

/// Bait-comment keywords of one language. Each pattern is a regex fragment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BaitLanguage {
    pub lang: String,
    #[serde(default)]
    pub note: String,
    pub patterns: Vec<String>,
}

/// File extensions (without the dot).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Extensions {
    /// Run from a UNC / WebDAV share or a mapped drive.
    pub remote_file: Vec<String>,
    /// Started directly after a download.
    pub launch: Vec<String>,
    /// Run by wscript / cscript.
    pub script_host: Vec<String>,
}

#[derive(Deserialize)]
struct ProgramsFile {
    known_programs: Vec<String>,
    known_env: Vec<EnvVar>,
}

#[derive(Deserialize)]
struct HostsFile {
    hosts: Vec<OfficialHost>,
}

#[derive(Deserialize)]
struct BaitFile {
    languages: Vec<BaitLanguage>,
}

/// All command-detection data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandRules {
    pub known_programs: Vec<String>,
    pub known_env: Vec<EnvVar>,
    pub official_hosts: Vec<OfficialHost>,
    pub official_paths: Vec<OfficialPath>,
    pub bait: Vec<BaitLanguage>,
    pub extensions: Extensions,
}

impl CommandRules {
    /// Parses the embedded files. Errors name the file that failed.
    pub fn load() -> Result<CommandRules, String> {
        let programs: ProgramsFile = serde_json::from_str(PROGRAMS_JSON)
            .map_err(|e| format!("rules/command/programs.json: {e}"))?;
        let hosts: HostsFile = serde_json::from_str(OFFICIAL_HOSTS_JSON)
            .map_err(|e| format!("rules/command/official-hosts.json: {e}"))?;
        let paths: PathsFile = serde_json::from_str(OFFICIAL_PATHS_JSON)
            .map_err(|e| format!("rules/command/official-paths.json: {e}"))?;
        let bait: BaitFile = serde_json::from_str(BAIT_KEYWORDS_JSON)
            .map_err(|e| format!("rules/command/bait-keywords.json: {e}"))?;
        let extensions: Extensions = serde_json::from_str(EXTENSIONS_JSON)
            .map_err(|e| format!("rules/command/extensions.json: {e}"))?;
        let rules = CommandRules {
            known_programs: programs.known_programs,
            known_env: programs.known_env,
            official_hosts: hosts.hosts,
            official_paths: paths.prefixes,
            bait: bait.languages,
            extensions,
        };
        let problems = rules.validate();
        if problems.is_empty() {
            Ok(rules)
        } else {
            Err(problems.join("; "))
        }
    }

    /// The embedded rules, parsed once. Falls back to empty lists if the embedded
    /// files are broken (a unit test guarantees they are not), so the engine never
    /// panics because of rule data.
    pub fn embedded() -> &'static CommandRules {
        static RULES: OnceLock<CommandRules> = OnceLock::new();
        RULES.get_or_init(|| CommandRules::load().unwrap_or_default())
    }

    /// Every bait keyword pattern, in file order.
    pub fn bait_patterns(&self) -> impl Iterator<Item = &str> {
        self.bait
            .iter()
            .flat_map(|l| l.patterns.iter().map(String::as_str))
    }

    /// Checks the data: names are plain words, hosts are lowercase ASCII domain
    /// names, regex fragments compile, nothing is empty or duplicated.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let word = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        };
        check_list("known_programs", &self.known_programs, word, &mut problems);
        for (name, list) in [
            ("extensions.remote_file", &self.extensions.remote_file),
            ("extensions.launch", &self.extensions.launch),
            ("extensions.script_host", &self.extensions.script_host),
        ] {
            check_list(name, list, word, &mut problems);
        }
        let hosts: Vec<String> = self.official_hosts.iter().map(|h| h.host.clone()).collect();
        check_list("official_hosts", &hosts, is_domain, &mut problems);
        let prefixes: Vec<String> = self
            .official_paths
            .iter()
            .map(|p| p.prefix.clone())
            .collect();
        check_list(
            "official_paths",
            &prefixes,
            |p| {
                let segments: Vec<&str> = p.split('/').collect();
                p.ends_with('/')
                    && segments.len() >= 4
                    && segments.first().is_some_and(|h| is_domain(h))
                    && segments[1..segments.len() - 1].iter().all(|s| {
                        !s.is_empty()
                            && !s.chars().all(|c| c == '.')
                            && s.chars()
                                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                    })
            },
            &mut problems,
        );
        for v in &self.known_env {
            if v.name.is_empty() || v.value.is_empty() {
                problems.push(format!("known_env: empty entry {:?}", v.name));
            }
        }
        for p in self.bait_patterns() {
            if p.is_empty() {
                problems.push("bait: empty pattern".into());
            } else if let Err(e) = regex::Regex::new(&format!("(?i){p}")) {
                problems.push(format!("bait: pattern {p:?} does not compile: {e}"));
            }
        }
        if self.bait_patterns().next().is_none() {
            problems.push("bait: no patterns".into());
        }
        problems
    }
}

/// Lowercase ASCII domain name with at least two labels.
fn is_domain(h: &str) -> bool {
    h.split('.').count() >= 2
        && h.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

fn check_list(name: &str, list: &[String], ok: impl Fn(&str) -> bool, problems: &mut Vec<String>) {
    if list.is_empty() {
        problems.push(format!("{name}: empty list"));
    }
    for (i, item) in list.iter().enumerate() {
        if !ok(item) {
            problems.push(format!("{name}: invalid entry {item:?}"));
        }
        if list[..i].contains(item) {
            problems.push(format!("{name}: duplicate entry {item:?}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_load_and_validate() {
        let rules = CommandRules::load().unwrap_or_else(|e| panic!("{e}"));
        assert!(rules.known_programs.iter().any(|p| p == "mshta"));
        assert!(rules.official_hosts.iter().any(|h| h.host == "astral.sh"));
        assert!(rules.bait_patterns().any(|p| p == "captcha"));
        assert!(
            rules
                .extensions
                .remote_file
                .iter()
                .any(|e| e == "search-ms")
        );
        assert_eq!(CommandRules::embedded(), &rules);
    }

    #[test]
    fn validation_catches_bad_data() {
        let mut rules = CommandRules::load().unwrap_or_default();
        rules.official_hosts.push(OfficialHost {
            host: "Bad Host".into(),
            note: String::new(),
        });
        rules.known_programs.push("mshta".into());
        rules.bait[0].patterns.push("(".into());
        for bad in [
            "raw.githubusercontent.com/Homebrew/",
            "raw.githubusercontent.com/Homebrew/install",
            "raw.githubusercontent.com/../install/",
            "raw.githubusercontent.com/a%2f/b/",
            "Raw.example/a/b/",
        ] {
            rules.official_paths.push(OfficialPath {
                prefix: bad.into(),
                note: String::new(),
            });
        }
        let problems = rules.validate();
        assert_eq!(problems.len(), 8, "{problems:?}");
    }

    #[test]
    fn official_path_parts() {
        let rules = CommandRules::load().unwrap_or_default();
        let brew = rules
            .official_paths
            .iter()
            .find(|p| p.prefix.contains("Homebrew"))
            .cloned()
            .unwrap_or_else(|| panic!("no Homebrew prefix"));
        assert_eq!(brew.host(), "raw.githubusercontent.com");
        assert_eq!(brew.segments().collect::<Vec<_>>(), ["Homebrew", "install"]);
    }
}
