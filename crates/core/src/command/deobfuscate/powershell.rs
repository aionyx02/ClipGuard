//! PowerShell string building: backtick escapes, `[char]`, string variables,
//! `[string]::Concat/Join/Format`, `+`, `-join`, `-f`, `-replace`, and literals run
//! as commands (`& ('mshta')`, `iex 'iwr …'`). Only literals are evaluated;
//! anything that depends on runtime values is left as it is.

use std::collections::HashMap;

use regex::{Captures, Regex};

use crate::command::normalize::{MAX_EXPANSIONS, MAX_VALUE_LENGTH, MAX_VARIABLES};
use crate::command::re::lazy_re;

use super::{LIT, MAX_CONCAT_PASSES, MAX_LIST_ITEMS, MAX_PATTERN_LENGTH, MAX_REGEX_REPLACES};
use super::{lit_value, quote};

/// A number in `[char]` code: decimal or `0x` hex.
const NUM: &str = r"(?:0x[0-9a-f]{1,6}|\d{1,7})";

fn list() -> String {
    format!(r"{LIT}(?:\s*,\s*{LIT})*")
}

lazy_re! { fn lit = format!("(?i){LIT}"); }
lazy_re! { fn num = format!("(?i){NUM}"); }
lazy_re! { fn char_one = format!(r"(?i)\[char\]\s*(?:\(\s*(?P<a>{NUM})\s*\)|(?P<b>{NUM})(?-u:\b))"); }
lazy_re! { fn char_array = format!(r"(?i)\[char\[\]\]\s*@?\(\s*(?P<l>{NUM}(?:\s*,\s*{NUM})*)\s*\)"); }
lazy_re! {
    fn ps_assign = format!(r"(?im)(?:^|[;{{(\s])\$(?P<n>[a-z_]\w{{0,63}})\s*=\s*(?P<v>{LIT})\s*(?:;|$|\}})");
}
lazy_re! { fn ps_var = r"(?i)\$(?P<n>[a-z_]\w{0,63})(?-u:\b)"; }
lazy_re! {
    fn string_method = format!(
        r"(?i)\[(?:system\.)?string\]\s*::\s*(?P<m>concat|join|format)\s*\(\s*(?P<l>{})\s*\)",
        list()
    );
}
lazy_re! { fn concat_pair = format!(r"(?P<a>{LIT})\s*\+\s*(?P<b>{LIT})"); }
lazy_re! { fn join_binary = format!(r"(?i)\(\s*(?P<l>{})\s*\)\s*-join\s*(?P<sep>{LIT})", list()); }
lazy_re! {
    fn join_bare_binary =
        format!(r"(?i)(?P<l>{LIT}(?:\s*,\s*{LIT})+)\s*-join\s*(?P<sep>{LIT})");
}
lazy_re! { fn join_unary = format!(r"(?i)-join\s*\(\s*(?P<l>{})\s*\)", list()); }
lazy_re! { fn join_unary_bare = format!(r"(?i)-join\s+(?P<l>{LIT}(?:\s*,\s*{LIT})+)"); }
lazy_re! {
    fn format_op = format!(
        r"(?i)(?P<f>{LIT})\s*-f\s*(?:\(\s*(?P<l1>{0})\s*\)|(?P<l2>{0}))",
        list()
    );
}
lazy_re! {
    fn replace_op = format!(
        r"(?i)(?P<s>{LIT})\s*-(?P<op>[ci]?replace)\s*(?P<p>{LIT})(?:\s*,\s*(?P<r>{LIT}))?"
    );
}
lazy_re! {
    fn replace_method = format!(
        r"(?i)(?P<s>{LIT})\s*\.replace\s*\(\s*(?P<p>{LIT})\s*,\s*(?P<r>{LIT})\s*\)"
    );
}
lazy_re! { fn paren_lit = format!(r"(?m)(?P<pre>^|[^\w\]\.])\(\s*(?P<l>{LIT})\s*\)"); }
lazy_re! { fn run_lit = format!(r"(?i)(?P<op>&|(?-u:\b)iex(?-u:\b)|(?-u:\b)invoke-expression(?-u:\b))\s*(?P<l>{LIT})"); }

/// Literal values of a matched list.
fn items(list: &str) -> Option<Vec<String>> {
    let re = lit().get()?;
    let v: Vec<String> = re
        .find_iter(list)
        .take(MAX_LIST_ITEMS + 1)
        .filter_map(|m| lit_value(m.as_str()))
        .collect();
    (v.len() <= MAX_LIST_ITEMS).then_some(v)
}

fn whole<'a>(c: &Captures<'a>) -> &'a str {
    c.get(0).map_or("", |m| m.as_str())
}

/// `re.replace_all` with a closure that may decline (returning `None` keeps the
/// match); counts replacements.
fn replace_with(
    re: Option<&Regex>,
    s: &str,
    mut f: impl FnMut(&Captures<'_>) -> Option<String>,
) -> Option<(String, usize)> {
    let re = re?;
    let mut count = 0usize;
    let out = re.replace_all(s, |c: &Captures<'_>| match f(c) {
        Some(r) => {
            count += 1;
            r
        }
        None => whole(c).to_owned(),
    });
    (count > 0).then(|| (out.into_owned(), count))
}

/// Applies `f` until nothing changes (at most [`MAX_CONCAT_PASSES`] times).
fn fixpoint(s: &str, f: impl Fn(&str) -> Option<(String, usize)>) -> Option<(String, usize)> {
    let mut cur: Option<(String, usize)> = None;
    for _ in 0..MAX_CONCAT_PASSES {
        let src = cur.as_ref().map_or(s, |(t, _)| t.as_str());
        match f(src) {
            Some((next, n)) => {
                let total = cur.as_ref().map_or(0, |(_, c)| *c) + n;
                cur = Some((next, total));
            }
            None => break,
        }
    }
    cur
}

/// `` p`ow`er `` → `power`; a backtick before a line break joins the lines.
/// Markdown markers were already removed in layer 0.
pub(super) fn backticks(s: &str) -> Option<(String, usize)> {
    if !s.contains('`') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    let mut count = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '`' {
            out.push(c);
            continue;
        }
        count += 1;
        match chars.next() {
            Some('\r') if chars.peek() == Some(&'\n') => {
                chars.next();
                out.push(' ');
            }
            Some('\n') => out.push(' '),
            Some(x) => out.push(x),
            None => {}
        }
    }
    Some((out, count))
}

fn char_from(n: &str) -> Option<char> {
    let v = match n.get(..2) {
        Some(p) if p.eq_ignore_ascii_case("0x") => u32::from_str_radix(&n[2..], 16).ok()?,
        _ => n.parse::<u32>().ok()?,
    };
    char::from_u32(v).filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
}

/// `[char]109` → `'m'`; `[char[]](109,115)` → `('m','s')`.
pub(super) fn char_codes(s: &str) -> Option<(String, usize)> {
    if !s.to_ascii_lowercase().contains("[char") {
        return None;
    }
    let first = replace_with(char_array().get(), s, |c| {
        let l = c.name("l")?.as_str();
        let codes: Vec<&str> = num().get()?.find_iter(l).map(|m| m.as_str()).collect();
        if codes.len() > MAX_LIST_ITEMS {
            return None;
        }
        let chars: Option<Vec<String>> = codes
            .iter()
            .map(|n| char_from(n).map(|ch| quote(&ch.to_string())))
            .collect();
        Some(format!("({})", chars?.join(",")))
    });
    let src = first.as_ref().map_or(s, |(t, _)| t.as_str());
    let second = replace_with(char_one().get(), src, |c| {
        let n = c.name("a").or_else(|| c.name("b"))?.as_str();
        char_from(n).map(|ch| quote(&ch.to_string()))
    });
    match (first, second) {
        (_, Some((t, n2))) => Some((t, n2 + 1)),
        (Some(f), None) => Some(f),
        (None, None) => None,
    }
}

/// `$a = 'ms'` … `$a` → `'ms'` (raw inside double quotes). Variables assigned
/// different values are skipped; bounded like cmd variables.
pub(super) fn variables(s: &str) -> Option<(String, usize)> {
    if !s.contains('$') {
        return None;
    }
    let mut vars: HashMap<String, Option<String>> = HashMap::new();
    for c in ps_assign().get()?.captures_iter(s) {
        let (Some(n), Some(v)) = (c.name("n"), c.name("v").and_then(|m| lit_value(m.as_str())))
        else {
            continue;
        };
        if v.chars().count() > MAX_VALUE_LENGTH {
            continue;
        }
        let name = n.as_str().to_ascii_lowercase();
        match vars.get(&name) {
            Some(Some(old)) if *old != v => {
                vars.insert(name, None);
            }
            Some(_) => {}
            None if vars.len() < MAX_VARIABLES => {
                vars.insert(name, Some(v));
            }
            None => {}
        }
    }
    if vars.values().all(Option::is_none) {
        return None;
    }
    let re = ps_var().get()?;
    let mut out = String::with_capacity(s.len());
    let mut copied = 0usize;
    let mut count = 0usize;
    for c in re.captures_iter(s) {
        if count >= MAX_EXPANSIONS {
            break;
        }
        let (Some(m), Some(n)) = (c.get(0), c.name("n")) else {
            continue;
        };
        let Some(Some(value)) = vars.get(&n.as_str().to_ascii_lowercase()) else {
            continue;
        };
        // An assignment target stays (`$a = …`, but not `$a == …`).
        let rest = s[m.end()..].trim_start();
        if rest.starts_with('=') && !rest.starts_with("==") {
            continue;
        }
        let line_start = s[..m.start()].rfind('\n').map_or(0, |i| i + 1);
        let in_double = s[line_start..m.start()].matches('"').count() % 2 == 1;
        out.push_str(&s[copied..m.start()]);
        if in_double {
            out.push_str(value);
        } else {
            out.push_str(&quote(value));
        }
        copied = m.end();
        count += 1;
    }
    if count == 0 {
        return None;
    }
    out.push_str(&s[copied..]);
    Some((out, count))
}

/// `[string]::Concat('a','b')`, `[string]::Join('', …)`, `[string]::Format('{0}', …)`.
pub(super) fn string_methods(s: &str) -> Option<(String, usize)> {
    replace_with(string_method().get(), s, |c| {
        let m = c.name("m")?.as_str().to_ascii_lowercase();
        let v = items(c.name("l")?.as_str())?;
        let value = match m.as_str() {
            "concat" => v.concat(),
            "join" => {
                let (sep, rest) = v.split_first()?;
                rest.join(sep)
            }
            _ => {
                let (fmt, rest) = v.split_first()?;
                format_ps(fmt, rest)?
            }
        };
        Some(quote(&value))
    })
}

/// `'ms' + 'hta'` → `'mshta'`.
pub(super) fn concat(s: &str) -> Option<(String, usize)> {
    if !s.contains('+') {
        return None;
    }
    fixpoint(s, |t| {
        replace_with(concat_pair().get(), t, |c| {
            let a = lit_value(c.name("a")?.as_str())?;
            let b = lit_value(c.name("b")?.as_str())?;
            Some(quote(&(a + &b)))
        })
    })
}

/// `-join ('a','b')`, `('a','b') -join ''`, `'a','b' -join ''`, `-join 'a','b'`.
pub(super) fn join(s: &str) -> Option<(String, usize)> {
    if !s.to_ascii_lowercase().contains("-join") {
        return None;
    }
    let binary = |re: Option<&Regex>, t: &str| {
        replace_with(re, t, |c| {
            let v = items(c.name("l")?.as_str())?;
            let sep = lit_value(c.name("sep")?.as_str())?;
            Some(quote(&v.join(&sep)))
        })
    };
    let unary = |re: Option<&Regex>, t: &str| {
        replace_with(re, t, |c| {
            Some(quote(&items(c.name("l")?.as_str())?.concat()))
        })
    };
    let mut cur = s.to_owned();
    let mut count = 0usize;
    for i in 0..4 {
        let r = match i {
            0 => binary(join_binary().get(), &cur),
            1 => binary(join_bare_binary().get(), &cur),
            2 => unary(join_unary().get(), &cur),
            _ => unary(join_unary_bare().get(), &cur),
        };
        if let Some((t, n)) = r {
            cur = t;
            count += n;
        }
    }
    (count > 0).then_some((cur, count))
}

/// .NET composite format with literal arguments: `{0}`, `{1,5}`, `{0:x}` (alignment
/// and format are ignored), `{{` / `}}`. `None` if an index is missing or the
/// format is malformed.
fn format_ps(fmt: &str, args: &[String]) -> Option<String> {
    let mut out = String::with_capacity(fmt.len());
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut spec = String::new();
                loop {
                    match chars.next()? {
                        '}' => break,
                        x if spec.len() < 32 => spec.push(x),
                        _ => return None,
                    }
                }
                let index = spec
                    .split([',', ':'])
                    .next()?
                    .trim()
                    .parse::<usize>()
                    .ok()?;
                out.push_str(args.get(index)?);
            }
            '}' => return None,
            _ => out.push(c),
        }
    }
    Some(out)
}

/// `'{1}{0}' -f 'hta','ms'` → `'mshta'`.
pub(super) fn format(s: &str) -> Option<(String, usize)> {
    if !s.to_ascii_lowercase().contains("-f") {
        return None;
    }
    replace_with(format_op().get(), s, |c| {
        let fmt = lit_value(c.name("f")?.as_str())?;
        let l = c.name("l1").or_else(|| c.name("l2"))?.as_str();
        Some(quote(&format_ps(&fmt, &items(l)?)?))
    })
}

/// `'mXhta' -replace 'x','s'` (regex, case-insensitive unless `-creplace`) and
/// `'mXhta'.Replace('X','s')` (literal, case-sensitive).
pub(super) fn replace(s: &str) -> Option<(String, usize)> {
    if !s.to_ascii_lowercase().contains("replace") {
        return None;
    }
    let budget = std::cell::Cell::new(MAX_REGEX_REPLACES);
    fixpoint(s, |t| {
        let a = replace_with(replace_op().get(), t, |c| {
            let subject = lit_value(c.name("s")?.as_str())?;
            let pattern = lit_value(c.name("p")?.as_str())?;
            let with = match c.name("r") {
                Some(r) => lit_value(r.as_str())?,
                None => String::new(),
            };
            if pattern.is_empty()
                || pattern.chars().count() > MAX_PATTERN_LENGTH
                || budget.get() == 0
            {
                return None;
            }
            budget.set(budget.get() - 1);
            let case_sensitive = c.name("op")?.as_str().eq_ignore_ascii_case("creplace");
            let re = regex::RegexBuilder::new(&pattern)
                .case_insensitive(!case_sensitive)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
                .ok()?;
            Some(quote(&re.replace_all(&subject, with.as_str())))
        });
        let src = a.as_ref().map_or(t, |(x, _)| x.as_str());
        let b = replace_with(replace_method().get(), src, |c| {
            let subject = lit_value(c.name("s")?.as_str())?;
            let pattern = lit_value(c.name("p")?.as_str())?;
            let with = lit_value(c.name("r")?.as_str())?;
            (!pattern.is_empty()).then(|| quote(&subject.replace(&pattern, &with)))
        });
        match (a, b) {
            (Some((_, n1)), Some((x, n2))) => Some((x, n1 + n2)),
            (Some(x), None) | (None, Some(x)) => Some(x),
            (None, None) => None,
        }
    })
}

/// Is `rest` (after a literal) the end of an expression?
fn ends_expression(rest: &str) -> bool {
    let r = rest.trim_start_matches([' ', '\t']);
    r.is_empty() || r.starts_with([';', '|', ')', '}', '\r', '\n'])
}

/// `('x')` → `'x'` (not a call like `f('x')` or `[char]('x')`); then
/// `& 'mshta'` → `& mshta` (a single token) and `iex 'iwr …'` → `iex iwr …`
/// (when the literal ends the expression).
pub(super) fn unwrap(s: &str) -> Option<(String, usize)> {
    if !s.contains('\'') && !s.contains('"') {
        return None;
    }
    let parens = fixpoint(s, |t| {
        replace_with(paren_lit().get(), t, |c| {
            Some(format!(
                "{}{}",
                c.name("pre")?.as_str(),
                c.name("l")?.as_str()
            ))
        })
    });
    let src = parens.as_ref().map_or(s, |(t, _)| t.as_str());
    let re = run_lit().get();
    let run = replace_with(re, src, |c| {
        let op = c.name("op")?.as_str();
        let l = c.name("l")?;
        let value = lit_value(l.as_str())?;
        if value.is_empty() {
            return None;
        }
        if op == "&" {
            let token = value.chars().all(|ch| {
                ch.is_alphanumeric() || matches!(ch, '.' | '\\' | ':' | '/' | '~' | '-' | '_')
            });
            token.then(|| format!("& {value}"))
        } else {
            ends_expression(&src[l.end()..]).then(|| format!("{op} {value}"))
        }
    });
    match (parens, run) {
        (Some((_, n1)), Some((x, n2))) => Some((x, n1 + n2)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [
            lit(),
            num(),
            char_one(),
            char_array(),
            ps_assign(),
            ps_var(),
            string_method(),
            concat_pair(),
            join_binary(),
            join_bare_binary(),
            join_unary(),
            join_unary_bare(),
            format_op(),
            replace_op(),
            replace_method(),
            paren_lit(),
            run_lit(),
        ] {
            assert!(re.compiled());
        }
    }

    fn t(f: fn(&str) -> Option<(String, usize)>, s: &str) -> String {
        f(s).map_or_else(|| s.to_owned(), |(o, _)| o)
    }

    #[test]
    fn transforms() {
        assert_eq!(t(concat, "'a'+'b' + \"c\"+'d'"), "'abcd'");
        assert_eq!(t(concat, "'a'+$b"), "'a'+$b");
        assert_eq!(t(join, "('a','b') -join '-'"), "'a-b'");
        assert_eq!(t(join, "'a','b' -join ''"), "'ab'");
        assert_eq!(t(join, "-join 'a','b'"), "'ab'");
        assert_eq!(t(format, "'{0}{{x}}{1:x}' -f 'a','b'"), "'a{x}b'");
        assert_eq!(t(format, "'{2}' -f 'a'"), "'{2}' -f 'a'");
        assert_eq!(t(replace, "'aXb' -creplace 'x','y'"), "'aXb'");
        assert_eq!(t(replace, "'aXb' -replace 'x'"), "'ab'");
        assert_eq!(t(replace, "'a.b'.Replace('.','')"), "'ab'");
        assert_eq!(t(replace, "'aaa' -replace '(a)','$1$1'"), "'aaaaaa'");
        assert_eq!(t(replace, "'x' -replace '(','y'"), "'x' -replace '(','y'");
        assert_eq!(t(char_codes, "[char]0x41+[char](66)"), "'A'+'B'");
        assert_eq!(t(char_codes, "[char]0"), "[char]0");
        assert_eq!(t(unwrap, "x.DownloadString('u')"), "x.DownloadString('u')");
        assert_eq!(t(unwrap, "iex ('a' + $b)"), "iex ('a' + $b)");
        assert_eq!(
            t(unwrap, "& 'C:\\Program Files\\x.exe' /s"),
            "& 'C:\\Program Files\\x.exe' /s"
        );
        assert_eq!(
            t(variables, "$u = 'x'; \"y $u\"; $u"),
            "$u = 'x'; \"y x\"; 'x'"
        );
        assert_eq!(t(variables, "$u='a'; $u='b'; $u"), "$u='a'; $u='b'; $u");
        assert_eq!(t(backticks, "a`\r\nb``c`"), "a b`c");
    }
}
