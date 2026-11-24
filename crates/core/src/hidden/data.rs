//! Hidden-character data in `rules/hidden/` (docs/spec/detection-rules.md §6.1),
//! embedded at build time and parsed once.
//!
//! - `shell-commands.json`: programs that make a line look like a shell command
//! - `homoglyphs.json`: Cyrillic / Greek look-alikes of Latin letters, per script
//! - `tag-sequences.json`: emoji TAG sequences with a standard (RGI) emoji
//! - `joiners.json`: where ZWNJ / ZWJ are legitimate (emoji, complex scripts, viramas)
//!
//! Broken data never panics: [`HiddenRules::embedded`] falls back to empty lists
//! (a unit test guarantees the embedded files load and validate).

use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::sync::OnceLock;

use serde::Deserialize;

const SHELL_COMMANDS_JSON: &str = include_str!("../../../../rules/hidden/shell-commands.json");
const HOMOGLYPHS_JSON: &str = include_str!("../../../../rules/hidden/homoglyphs.json");
const TAG_SEQUENCES_JSON: &str = include_str!("../../../../rules/hidden/tag-sequences.json");
const JOINERS_JSON: &str = include_str!("../../../../rules/hidden/joiners.json");

/// Longest tag spec of an RGI subdivision flag that is looked for (legacy bound).
pub const MAX_TAG_SPEC_LEN: usize = 8;

#[derive(Deserialize)]
struct ShellCommandsFile {
    programs: Vec<String>,
}

#[derive(Deserialize)]
struct HomoglyphScriptFile {
    script: String,
    confusables: Vec<String>,
    ranges: Vec<[String; 2]>,
}

#[derive(Deserialize)]
struct HomoglyphsFile {
    scripts: Vec<HomoglyphScriptFile>,
}

#[derive(Deserialize)]
struct TagSequencesFile {
    rgi_subdivision_flags: Vec<String>,
}

#[derive(Deserialize)]
struct ViramaFile {
    script: String,
    virama: String,
    block: [String; 2],
}

#[derive(Deserialize)]
struct JoinersFile {
    emoji_ranges: Vec<[String; 2]>,
    complex_script_range: [String; 2],
    viramas: Vec<ViramaFile>,
}

/// One script of look-alike letters.
#[derive(Debug, Clone, Default)]
pub struct HomoglyphScript {
    /// Script name, also the `script` argument of the `hidden-homoglyph` message.
    pub script: String,
    pub confusables: HashSet<char>,
    /// Blocks whose other letters are genuine text of this script.
    pub ranges: Vec<RangeInclusive<char>>,
}

/// A virama after which a ZWJ selects a half form / chillu letter.
#[derive(Debug, Clone)]
pub struct Virama {
    pub script: String,
    pub virama: char,
    /// The script's block: the letter before the virama must be in it.
    pub block: RangeInclusive<char>,
}

/// All hidden-character data.
#[derive(Debug, Clone)]
pub struct HiddenRules {
    /// Lowercase program names.
    pub shell_commands: HashSet<String>,
    pub homoglyphs: Vec<HomoglyphScript>,
    pub rgi_flag_tags: Vec<String>,
    pub emoji_ranges: Vec<RangeInclusive<char>>,
    pub complex_script_range: RangeInclusive<char>,
    pub viramas: Vec<Virama>,
}

impl Default for HiddenRules {
    fn default() -> Self {
        HiddenRules {
            shell_commands: HashSet::new(),
            homoglyphs: Vec::new(),
            rgi_flag_tags: Vec::new(),
            emoji_ranges: Vec::new(),
            // An empty range: nothing is a complex-script letter.
            complex_script_range: '\u{1}'..='\u{0}',
            viramas: Vec::new(),
        }
    }
}

/// `"U+0D4D"` → U+0D4D.
fn code_point(s: &str) -> Result<char, String> {
    s.strip_prefix("U+")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .and_then(char::from_u32)
        .ok_or_else(|| format!("invalid code point {s:?}"))
}

fn range(pair: &[String; 2]) -> Result<RangeInclusive<char>, String> {
    let (a, b) = (code_point(&pair[0])?, code_point(&pair[1])?);
    if a > b {
        return Err(format!("empty range {pair:?}"));
    }
    Ok(a..=b)
}

impl HiddenRules {
    /// Parses and validates the embedded files. Errors name the file that failed.
    pub fn load() -> Result<HiddenRules, String> {
        let shell: ShellCommandsFile = serde_json::from_str(SHELL_COMMANDS_JSON)
            .map_err(|e| format!("rules/hidden/shell-commands.json: {e}"))?;
        let homoglyphs: HomoglyphsFile = serde_json::from_str(HOMOGLYPHS_JSON)
            .map_err(|e| format!("rules/hidden/homoglyphs.json: {e}"))?;
        let tags: TagSequencesFile = serde_json::from_str(TAG_SEQUENCES_JSON)
            .map_err(|e| format!("rules/hidden/tag-sequences.json: {e}"))?;
        let joiners: JoinersFile = serde_json::from_str(JOINERS_JSON)
            .map_err(|e| format!("rules/hidden/joiners.json: {e}"))?;

        let mut problems = Vec::new();

        let mut shell_commands = HashSet::new();
        for p in &shell.programs {
            let ok = !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !ok {
                problems.push(format!("shell-commands: invalid entry {p:?}"));
            }
            if !shell_commands.insert(p.clone()) {
                problems.push(format!("shell-commands: duplicate entry {p:?}"));
            }
        }
        if shell_commands.is_empty() {
            problems.push("shell-commands: empty list".into());
        }

        let mut scripts = Vec::new();
        let mut seen = HashSet::new();
        for s in homoglyphs.scripts {
            let mut ranges = Vec::new();
            for r in &s.ranges {
                match range(r) {
                    Ok(r) => ranges.push(r),
                    Err(e) => problems.push(format!("homoglyphs.{}: {e}", s.script)),
                }
            }
            let mut confusables = HashSet::new();
            for c in &s.confusables {
                let mut it = c.chars();
                match (it.next(), it.next()) {
                    (Some(ch), None) if ranges.iter().any(|r| r.contains(&ch)) => {
                        if !seen.insert(ch) {
                            problems.push(format!("homoglyphs: duplicate {c:?}"));
                        }
                        confusables.insert(ch);
                    }
                    _ => problems.push(format!(
                        "homoglyphs.{}: {c:?} is not one character of the script",
                        s.script
                    )),
                }
            }
            if confusables.is_empty() || ranges.is_empty() || s.script.is_empty() {
                problems.push(format!("homoglyphs.{}: empty", s.script));
            }
            scripts.push(HomoglyphScript {
                script: s.script,
                confusables,
                ranges,
            });
        }
        if scripts.is_empty() {
            problems.push("homoglyphs: no scripts".into());
        }

        for t in &tags.rgi_subdivision_flags {
            let ok = (2..=MAX_TAG_SPEC_LEN).contains(&t.len())
                && t.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
            if !ok {
                problems.push(format!("tag-sequences: invalid entry {t:?}"));
            }
        }
        if tags.rgi_subdivision_flags.is_empty() {
            problems.push("tag-sequences: empty list".into());
        }

        let mut emoji_ranges = Vec::new();
        for r in &joiners.emoji_ranges {
            match range(r) {
                Ok(r) => emoji_ranges.push(r),
                Err(e) => problems.push(format!("joiners.emoji_ranges: {e}")),
            }
        }
        if emoji_ranges.is_empty() {
            problems.push("joiners.emoji_ranges: empty list".into());
        }
        let complex_script_range = range(&joiners.complex_script_range).unwrap_or_else(|e| {
            problems.push(format!("joiners.complex_script_range: {e}"));
            HiddenRules::default().complex_script_range
        });
        let mut viramas = Vec::new();
        for v in &joiners.viramas {
            match (code_point(&v.virama), range(&v.block)) {
                (Ok(virama), Ok(block)) if block.contains(&virama) => viramas.push(Virama {
                    script: v.script.clone(),
                    virama,
                    block,
                }),
                _ => problems.push(format!("joiners.viramas: invalid entry {:?}", v.script)),
            }
        }
        if viramas.is_empty() {
            problems.push("joiners.viramas: empty list".into());
        }

        if !problems.is_empty() {
            return Err(problems.join("; "));
        }
        Ok(HiddenRules {
            shell_commands,
            homoglyphs: scripts,
            rgi_flag_tags: tags.rgi_subdivision_flags,
            emoji_ranges,
            complex_script_range,
            viramas,
        })
    }

    /// The embedded rules, parsed once (empty lists if they are broken).
    pub fn embedded() -> &'static HiddenRules {
        static RULES: OnceLock<HiddenRules> = OnceLock::new();
        RULES.get_or_init(|| HiddenRules::load().unwrap_or_default())
    }

    /// The script whose look-alike `c` is, if any.
    pub fn confusable_script(&self, c: char) -> Option<&str> {
        self.homoglyphs
            .iter()
            .find(|s| s.confusables.contains(&c))
            .map(|s| s.script.as_str())
    }

    /// Is `c` in one of the homoglyph scripts' blocks?
    pub fn in_homoglyph_script(&self, c: char) -> bool {
        self.homoglyphs
            .iter()
            .any(|s| s.ranges.iter().any(|r| r.contains(&c)))
    }

    pub fn is_emoji_like(&self, c: char) -> bool {
        self.emoji_ranges.iter().any(|r| r.contains(&c))
    }

    /// The virama entry for `c`, if `c` is one.
    pub fn virama(&self, c: char) -> Option<&Virama> {
        self.viramas.iter().find(|v| v.virama == c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_load_and_validate() {
        let rules = HiddenRules::load().unwrap_or_else(|e| panic!("{e}"));
        assert!(rules.shell_commands.contains("powershell"));
        assert!(rules.shell_commands.contains("apt-get"));
        assert_eq!(rules.confusable_script('е'), Some("cyrillic"));
        assert_eq!(rules.confusable_script('ο'), Some("greek"));
        assert_eq!(rules.confusable_script('e'), None);
        assert!(rules.in_homoglyph_script('и'));
        assert!(rules.in_homoglyph_script('λ'));
        assert!(rules.rgi_flag_tags.iter().any(|t| t == "gbeng"));
        assert!(rules.is_emoji_like('\u{1F468}'));
        assert!(rules.complex_script_range.contains(&'\u{0D28}'));
        assert_eq!(
            rules.virama('\u{0D4D}').map(|v| v.script.as_str()),
            Some("malayalam")
        );
    }

    #[test]
    fn bad_code_points_are_rejected() {
        assert!(code_point("0D4D").is_err());
        assert!(code_point("U+D800").is_err());
        assert!(range(&["U+0010".into(), "U+0001".into()]).is_err());
        assert_eq!(code_point("U+0D4D"), Ok('\u{0D4D}'));
    }
}
