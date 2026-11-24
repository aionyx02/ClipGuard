//! Normalization before command rules are matched (legacy `CommandNormalizer`,
//! docs/spec/detection-rules.md §3.0, #19).
//!
//! Rewrites the spellings cmd / PowerShell treat as the same thing into the
//! simplest form, so detection rules only need to know `mshta https://…`:
//!
//! 0. drop invisible characters that can split keywords (soft hyphen, zero-width,
//!    U+180E, Hangul fillers, the TAG block)
//! 1. dash variants → `-`
//! 2. cmd `^` escapes (`m^s^h^t^a`, `^^` → `^`, trailing `^` joins lines)
//! 3. `set x=…` / `set "x=…"` then `%x%` / `!x!` (one level, bounded)
//! 4. fixed system environment variables (`%SystemRoot%`, `$env:windir`, …)
//! 5. quotes inside words (`"m"sh"ta"`, `ms""hta`)
//! 6. full paths of known programs → bare name (`"C:\…\mshta.exe"` → `mshta`)
//!
//! Pure: never reads the real environment or the file system. The output is only
//! used for matching; callers keep the original text.

use std::collections::HashMap;

use paste_warden_rules::command::CommandRules;
use regex::Captures;

use super::re::{Re, alternation, lazy_re};

/// At most this many distinct `set` variables are remembered.
pub const MAX_VARIABLES: usize = 16;
/// `set` values longer than this (chars) are ignored.
pub const MAX_VALUE_LENGTH: usize = 1024;
/// At most this many `%x%` / `!x!` substitutions per text (stops `%a%%a%…` blow-ups).
pub const MAX_EXPANSIONS: usize = 64;
/// Passes of the split-quote collapse (`"m"sh"ta"` needs two).
pub const MAX_QUOTE_PASSES: usize = 8;

/// Alternation of known program names from `rules/command/programs.json`.
pub(crate) fn known_programs() -> String {
    alternation(&CommandRules::embedded().known_programs)
}

lazy_re! { fn caret_newline = r"\^\r?\n"; }
lazy_re! { fn caret = r"(?s)\^(.)"; }
lazy_re! {
    fn set_quoted = r#"(?im)(?:^|[\s&|(;])set\s+"(?P<n>[a-z_][\w.#$@-]*)=(?P<v>[^"\r\n]*)""#;
}
lazy_re! {
    fn set_plain = r#"(?im)(?:^|[\s&|(;"])set\s+(?P<n>[a-z_][\w.#$@-]*)=(?P<v>[^&|\r\n"]*)"#;
}
lazy_re! { fn percent_var = r#"%(?P<n>[^%\s"]{1,64})%"#; }
lazy_re! { fn bang_var = r"(?i)!(?P<n>[a-z_][\w.#$@-]{0,63})!"; }
lazy_re! { fn ps_env_var = r"(?i)\$env:(?P<n>[a-z_]\w*(?:\(x86\))?)"; }
lazy_re! { fn quote_after_word = r#"(\w)"(\w*)""#; }
lazy_re! { fn quote_before_word = r#""(\w*)"(\w)"#; }
lazy_re! {
    fn quoted_path = format!(
        r#"(?i)"(?:(?:[a-z]:|\\\\|\.{{1,2}})[\\/](?:[^"\r\n]*[\\/])?)?(?P<p>{})(?:\.exe)?""#,
        known_programs()
    );
}
lazy_re! {
    fn plain_path = format!(
        r#"(?im)(?:^|[\s;&|(=,'"])(?P<dir>[^\s"'|&;<>()]*[\\/])(?P<tail>(?P<p>{})(?:\.exe)?)(?:$|[\s"'|&;<>()])"#,
        known_programs()
    );
}

/// Normalizes `text` for command matching (legacy `CommandNormalizer.Normalize`).
pub fn normalize(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let s = normalize_dashes(&strip_invisible(text));
    let s = unescape_carets(&s);
    let s = expand_variables(&s);
    let s = collapse_split_quotes(s);
    shorten_program_paths(&s)
}

/// Step 2: cmd `^` escapes (`m^s^h^t^a`, `^^` → `^`, trailing `^` joins lines).
pub(crate) fn unescape_carets(s: &str) -> String {
    let s = replace(caret_newline(), s, "");
    replace(caret(), &s, "${1}")
}

/// Step 6: full paths of known programs → bare name.
pub(crate) fn shorten_program_paths(s: &str) -> String {
    strip_known_paths(&replace(quoted_path(), s, "${p}"))
}

fn replace(re: &Re, s: &str, rep: &str) -> String {
    match re.get() {
        Some(r) => r.replace_all(s, rep).into_owned(),
        None => s.to_owned(),
    }
}

/// Invisible characters that can split a keyword (`pow<U+00AD>ershell`).
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2060}'
            | '\u{FEFF}'
            | '\u{180E}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

pub(crate) fn strip_invisible(s: &str) -> String {
    s.chars().filter(|&c| !is_invisible(c)).collect()
}

fn is_dash(c: char) -> bool {
    matches!(
        c,
        '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{FE58}' | '\u{FE63}' | '\u{FF0D}'
    )
}

pub(crate) fn normalize_dashes(s: &str) -> String {
    s.chars()
        .map(|c| if is_dash(c) { '-' } else { c })
        .collect()
}

pub(crate) fn known_env(name: &str) -> Option<&'static str> {
    CommandRules::embedded()
        .known_env
        .iter()
        .find(|v| v.name.to_lowercase() == name.to_lowercase())
        .map(|v| v.value.as_str())
}

pub(crate) fn expand_variables(s: &str) -> String {
    let vars = set_variables(s);
    expand_with(s, &vars)
}

/// `set x=…` / `set "x=…"` variables in `s`: lowercase names, at most
/// [`MAX_VARIABLES`], values up to [`MAX_VALUE_LENGTH`] chars.
pub(crate) fn set_variables(s: &str) -> HashMap<String, String> {
    let mut vars: HashMap<String, String> = HashMap::new();
    'outer: for re in [set_quoted(), set_plain()] {
        let Some(re) = re.get() else { continue };
        for c in re.captures_iter(s) {
            if vars.len() >= MAX_VARIABLES {
                break 'outer;
            }
            let (Some(n), Some(v)) = (c.name("n"), c.name("v")) else {
                continue;
            };
            let value = v.as_str().trim_end();
            if value.chars().count() <= MAX_VALUE_LENGTH {
                vars.insert(n.as_str().to_lowercase(), value.to_owned());
            }
        }
    }
    vars
}

/// Looks up a `set` variable, then a fixed system variable.
pub(crate) fn lookup_variable<'a>(
    vars: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    vars.get(&name.to_lowercase())
        .map(String::as_str)
        .or_else(|| known_env(name))
}

fn expand_with(s: &str, vars: &HashMap<String, String>) -> String {
    let mut budget = MAX_EXPANSIONS;
    let mut lookup = |c: &Captures<'_>| -> String {
        let whole = c.get(0).map_or("", |m| m.as_str());
        let name = c.name("n").map_or("", |m| m.as_str());
        if budget == 0 {
            return whole.to_owned();
        }
        match lookup_variable(vars, name) {
            Some(v) => {
                budget -= 1;
                v.to_owned()
            }
            None => whole.to_owned(),
        }
    };

    let mut out = s.to_owned();
    if let Some(r) = percent_var().get() {
        out = r.replace_all(&out, &mut lookup).into_owned();
    }
    if let Some(r) = bang_var().get() {
        out = r.replace_all(&out, &mut lookup).into_owned();
    }
    if let Some(r) = ps_env_var().get() {
        out = r
            .replace_all(&out, |c: &Captures<'_>| {
                let name = c.name("n").map_or("", |m| m.as_str());
                known_env(name).map_or_else(
                    || c.get(0).map_or("", |m| m.as_str()).to_owned(),
                    str::to_owned,
                )
            })
            .into_owned();
    }
    out
}

/// `"m"sh"ta"` → `"mshta"` → (quoted_path) `mshta`. Only word characters are
/// joined, so real string arguments such as `-c "iex(…)"` stay intact.
pub(crate) fn collapse_split_quotes(mut s: String) -> String {
    if !s.contains('"') {
        return s;
    }
    for _ in 0..MAX_QUOTE_PASSES {
        let next = replace(
            quote_before_word(),
            &replace(quote_after_word(), &s, "${1}${2}"),
            "${1}${2}",
        );
        if next == s {
            break;
        }
        s = next;
    }
    s
}

/// Unquoted full paths of known programs → bare name. URLs (`://`) and paths that
/// only use `/` without a drive letter (`github.com/powershell/powershell`) are not
/// Windows paths and stay as they are.
fn strip_known_paths(s: &str) -> String {
    let Some(re) = plain_path().get() else {
        return s.to_owned();
    };
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut pos = 0;
    while pos <= s.len() {
        let Some(c) = re.captures_at(s, pos) else {
            break;
        };
        let (Some(dir), Some(tail), Some(p)) = (c.name("dir"), c.name("tail"), c.name("p")) else {
            break;
        };
        let d = dir.as_str();
        let windows_path = !d.contains("://")
            && (d.contains('\\')
                || d.as_bytes().get(1) == Some(&b':')
                    && d.as_bytes().first().is_some_and(u8::is_ascii_alphabetic));
        if windows_path {
            out.push_str(&s[copied..dir.start()]);
            out.push_str(p.as_str());
            copied = tail.end();
        }
        // The delimiter after the program name may start the next path.
        pos = tail.end();
    }
    out.push_str(&s[copied..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [
            caret_newline(),
            caret(),
            set_quoted(),
            set_plain(),
            percent_var(),
            bang_var(),
            ps_env_var(),
            quote_after_word(),
            quote_before_word(),
            quoted_path(),
            plain_path(),
        ] {
            assert!(re.compiled());
        }
    }

    #[test]
    fn examples() {
        assert_eq!(normalize("m^s^h^t^a x"), "mshta x");
        assert_eq!(normalize("\"m\"sh\"ta\" x"), "mshta x");
        assert_eq!(normalize(r#""C:\Windows\System32\mshta.exe" x"#), "mshta x");
        assert_eq!(normalize(r"C:\a\cmd C:\b\mshta.exe"), "cmd mshta");
        assert_eq!(
            normalize("github.com/powershell/powershell"),
            "github.com/powershell/powershell"
        );
        assert_eq!(normalize("%ComSpec% /c dir"), "cmd /c dir");
        assert_eq!(
            normalize("set x=mshta&& call %x%"),
            "set x=mshta&& call mshta"
        );
        assert_eq!(normalize("pow\u{AD}ershell \u{2013}w"), "powershell -w");
        assert_eq!(normalize("hi!there!"), "hi!there!");
    }

    #[test]
    fn idempotent_on_examples() {
        for s in [
            "m^s^h^t^a https://x",
            r#""C:\x\pwsh.exe" -c "iex""#,
            "set a=1&echo %a%",
        ] {
            let once = normalize(s);
            assert_eq!(normalize(&once), once, "{s}");
        }
    }
}
