//! `xtask rules gitleaks <gitleaks.toml> <version> <commit>`: converts gitleaks'
//! default rules (`config/gitleaks.toml`, MIT) into `rules/gitleaks.json`. Port of
//! the legacy `tools/convert-gitleaks.mjs`; the output is byte-identical for the
//! same input except for the rules this port no longer skips (see [`SKIP`]).
//!
//! The toml is downloaded separately; this never touches the network:
//!
//! ```text
//! gh api -H "Accept: application/vnd.github.raw" \
//!   "repos/gitleaks/gitleaks/contents/config/gitleaks.toml?ref=<commit>" > gitleaks.toml
//! cargo run -p xtask -- rules gitleaks gitleaks.toml v8.30.1 <commit SHA>
//! ```
//!
//! Conversion (docs/spec/detection-rules.md §5.4): Go RE2 → the shared rule dialect.
//! `\w \d \s .` become explicit ASCII classes; a leading `(?i)` becomes the rule's
//! `ignoreCase`, any other `(?i)` / `(?-i:…)` is expanded into `[Aa]` classes;
//! `(?P<name>…)` becomes a plain group (same number); POSIX classes are expanded.
//! Unsupported syntax skips the rule with a reason. The leading `[\w.-]{0,50}?`
//! (it only widens the match over the variable name) is dropped. Path-only rules,
//! client IDs and rules covered by `rules/api-keys.json` are skipped; allowlist
//! samples that are themselves complete keys are not copied.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use regex::Regex;

/// Entry point: `args` are the words after `rules`.
pub fn run(args: &[&str]) -> Result<bool> {
    match args {
        ["gitleaks", toml, version, commit] => {
            let src = fs::read_to_string(toml).with_context(|| format!("reading {toml}"))?;
            let parsed = parse_toml(&src)?;
            let (main, late) = convert_config(&parsed, version, commit)?;
            for (name, out) in [("gitleaks.json", &main), ("gitleaks-late.json", &late)] {
                let target = repo_root().join("rules").join(name);
                let mut text = String::new();
                write_json(out, 0, &mut text);
                text.push('\n');
                fs::write(&target, text)
                    .with_context(|| format!("writing {}", target.display()))?;
                let count = |k: &str| match out.get(k) {
                    Some(J::Arr(a)) => a.len(),
                    _ => 0,
                };
                println!(
                    "kept {} rules, skipped {} → {}",
                    count("rules"),
                    count("skipped"),
                    target.display()
                );
            }
            Ok(true)
        }
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- rules gitleaks <gitleaks.toml> <version> <commit>"
            );
            Ok(false)
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

// ---------------------------------------------------------------- ordered JSON

/// A JSON value with ordered object keys, printed like `JSON.stringify(v, null, 2)`.
#[derive(Debug, Clone, PartialEq)]
pub enum J {
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, k: &str) -> Option<&J> {
        match self {
            J::Obj(o) => o.iter().find(|(n, _)| n == k).map(|(_, v)| v),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }
    fn as_arr(&self) -> &[J] {
        match self {
            J::Arr(a) => a,
            _ => &[],
        }
    }
    fn truthy(&self) -> bool {
        match self {
            J::Bool(b) => *b,
            J::Num(n) => *n != 0.0 && !n.is_nan(),
            J::Str(s) => !s.is_empty(),
            J::Arr(_) | J::Obj(_) => true,
        }
    }
}

fn obj(fields: Vec<(&str, J)>) -> J {
    J::Obj(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

fn s(v: &str) -> J {
    J::Str(v.to_owned())
}

fn write_json(v: &J, indent: usize, out: &mut String) {
    let pad = |n: usize, out: &mut String| out.extend(std::iter::repeat_n(' ', n));
    match v {
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Num(n) => out.push_str(&format!("{n}")),
        J::Str(x) => write_json_string(x, out),
        J::Arr(a) if a.is_empty() => out.push_str("[]"),
        J::Obj(o) if o.is_empty() => out.push_str("{}"),
        J::Arr(a) => {
            out.push_str("[\n");
            for (k, x) in a.iter().enumerate() {
                pad(indent + 2, out);
                write_json(x, indent + 2, out);
                out.push_str(if k + 1 < a.len() { ",\n" } else { "\n" });
            }
            pad(indent, out);
            out.push(']');
        }
        J::Obj(o) => {
            out.push_str("{\n");
            for (k, (name, x)) in o.iter().enumerate() {
                pad(indent + 2, out);
                write_json_string(name, out);
                out.push_str(": ");
                write_json(x, indent + 2, out);
                out.push_str(if k + 1 < o.len() { ",\n" } else { "\n" });
            }
            pad(indent, out);
            out.push('}');
        }
    }
}

fn write_json_string(x: &str, out: &mut String) {
    out.push('"');
    for c in x.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------- mini TOML

/// Parses the subset of TOML gitleaks.toml uses (legacy `parseToml`): `key = value`,
/// `[table]`, `[[array.of.tables]]`, `'''…'''`, `'…'`, `"…"`, arrays, booleans,
/// numbers, `#` comments.
pub fn parse_toml(src: &str) -> Result<J> {
    let c: Vec<char> = src.chars().collect();
    let mut p = Toml { c: &c, i: 0 };
    let mut root = J::Obj(Vec::new());
    let mut current: Vec<String> = Vec::new();
    loop {
        p.skip_ws();
        if p.i >= c.len() {
            break;
        }
        if p.starts_with("[[") {
            let end = p.find("]]", p.i).context("unterminated [[")?;
            let path: Vec<String> = p
                .slice(p.i + 2, end)
                .trim()
                .split('.')
                .map(str::to_owned)
                .collect();
            p.i = end + 2;
            let (last, parents) = path.split_last().context("empty table name")?;
            let parent = navigate(&mut root, parents)?;
            let arr = entry(parent, last, J::Arr(Vec::new()))?;
            match arr {
                J::Arr(a) => a.push(J::Obj(Vec::new())),
                _ => bail!("{last} is not an array of tables"),
            }
            current = path;
            continue;
        }
        if c[p.i] == '[' {
            let end = p.find("]", p.i).context("unterminated [")?;
            let name = p.slice(p.i + 1, end).trim().to_owned();
            p.i = end + 1;
            if let J::Obj(o) = &mut root {
                o.retain(|(k, _)| *k != name);
                o.push((name.clone(), J::Obj(Vec::new())));
            }
            current = vec![name];
            continue;
        }
        let eq = p.find("=", p.i).context("expected key = value")?;
        let key = p.slice(p.i, eq).trim().to_owned();
        p.i = eq + 1;
        let v = p.read_value()?;
        match navigate(&mut root, &current)? {
            J::Obj(o) => {
                o.retain(|(k, _)| *k != key);
                o.push((key, v));
            }
            _ => bail!("cannot assign {key}"),
        }
    }
    Ok(root)
}

/// Follows `path` from `root`: tables are entered, arrays of tables enter their last
/// element; missing tables are created.
fn navigate<'a>(root: &'a mut J, path: &[String]) -> Result<&'a mut J> {
    let mut cur = root;
    for k in path {
        let next = entry(cur, k, J::Obj(Vec::new()))?;
        cur = match next {
            J::Arr(a) => a.last_mut().context("empty array of tables")?,
            other => other,
        };
    }
    Ok(cur)
}

fn entry<'a>(t: &'a mut J, k: &str, default: J) -> Result<&'a mut J> {
    let J::Obj(o) = t else {
        bail!("{k}: parent is not a table");
    };
    let pos = match o.iter().position(|(n, _)| n == k) {
        Some(p) => p,
        None => {
            o.push((k.to_owned(), default));
            o.len() - 1
        }
    };
    Ok(&mut o[pos].1)
}

struct Toml<'a> {
    c: &'a [char],
    i: usize,
}

impl Toml<'_> {
    fn starts_with(&self, s: &str) -> bool {
        s.chars()
            .enumerate()
            .all(|(k, ch)| self.c.get(self.i + k) == Some(&ch))
    }
    fn find(&self, s: &str, from: usize) -> Option<usize> {
        let pat: Vec<char> = s.chars().collect();
        (from..self.c.len()).find(|&k| self.c[k..].starts_with(&pat))
    }
    fn slice(&self, a: usize, b: usize) -> String {
        self.c[a.min(b)..b.min(self.c.len())].iter().collect()
    }
    fn skip_ws(&mut self) {
        loop {
            while self.i < self.c.len() && matches!(self.c[self.i], ' ' | '\t' | '\r' | '\n' | ',')
            {
                self.i += 1;
            }
            if self.c.get(self.i) == Some(&'#') {
                while self.i < self.c.len() && self.c[self.i] != '\n' {
                    self.i += 1;
                }
                continue;
            }
            break;
        }
    }
    fn read_value(&mut self) -> Result<J> {
        self.skip_ws();
        if self.starts_with("'''") {
            let end = self.find("'''", self.i + 3).context("unterminated '''")?;
            let v = self.slice(self.i + 3, end);
            self.i = end + 3;
            return Ok(J::Str(v));
        }
        match self.c.get(self.i) {
            Some('\'') => {
                let end = self.find("'", self.i + 1).context("unterminated '")?;
                let v = self.slice(self.i + 1, end);
                self.i = end + 1;
                Ok(J::Str(v))
            }
            Some('"') => {
                let mut v = String::new();
                self.i += 1;
                while let Some(&ch) = self.c.get(self.i) {
                    if ch == '"' {
                        break;
                    }
                    if ch == '\\' {
                        let e = self.c.get(self.i + 1).copied().unwrap_or('\\');
                        v.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        });
                        self.i += 2;
                    } else {
                        v.push(ch);
                        self.i += 1;
                    }
                }
                self.i += 1;
                Ok(J::Str(v))
            }
            Some('[') => {
                self.i += 1;
                let mut arr = Vec::new();
                loop {
                    self.skip_ws();
                    match self.c.get(self.i) {
                        None => bail!("unterminated array"),
                        Some(']') => {
                            self.i += 1;
                            return Ok(J::Arr(arr));
                        }
                        Some(_) => arr.push(self.read_value()?),
                    }
                }
            }
            _ => {
                let start = self.i;
                while self.i < self.c.len()
                    && self.i - start < 64
                    && !matches!(self.c[self.i], ' ' | '\t' | '\r' | '\n' | ',' | ']' | '#')
                {
                    self.i += 1;
                }
                let tok = self.slice(start, self.i);
                Ok(match tok.as_str() {
                    "true" => J::Bool(true),
                    "false" => J::Bool(false),
                    t => J::Num(t.parse().with_context(|| format!("bad value {t:?}"))?),
                })
            }
        }
    }
}

// ---------------------------------------------------------------- RE2 → rule dialect

/// Syntax the shared rule dialect cannot express (the rule is skipped with this reason).
#[derive(Debug)]
pub struct Unsupported(pub String);

type R<T> = std::result::Result<T, Unsupported>;

fn unsupported<T>(m: impl Into<String>) -> R<T> {
    Err(Unsupported(m.into()))
}

type Ranges = Vec<(u32, u32)>;

const SPACE: &[(u32, u32)] = &[(9, 10), (12, 13), (32, 32)];
const DIGIT: &[(u32, u32)] = &[(48, 57)];
const WORD: &[(u32, u32)] = &[(48, 57), (65, 90), (95, 95), (97, 122)];

fn posix(name: &str) -> Option<&'static [(u32, u32)]> {
    Some(match name {
        "alnum" => &[(48, 57), (65, 90), (97, 122)],
        "alpha" => &[(65, 90), (97, 122)],
        "digit" => DIGIT,
        "lower" => &[(97, 122)],
        "upper" => &[(65, 90)],
        "space" => &[(9, 13), (32, 32)],
        "xdigit" => &[(48, 57), (65, 70), (97, 102)],
        "word" => WORD,
        "punct" => &[(33, 47), (58, 64), (91, 96), (123, 126)],
        _ => return None,
    })
}

fn normalize_ranges(ranges: &[(u32, u32)]) -> Ranges {
    let mut r = ranges.to_vec();
    r.sort_by_key(|x| x.0);
    let mut out: Ranges = Vec::new();
    for x in r {
        match out.last_mut() {
            Some(last) if x.0 <= last.1 + 1 => last.1 = last.1.max(x.1),
            _ => out.push(x),
        }
    }
    out
}

fn fold_case(ranges: &[(u32, u32)]) -> Ranges {
    let mut all = ranges.to_vec();
    for &(a, b) in ranges {
        let (lo, hi) = (a.max(97), b.min(122));
        if lo <= hi {
            all.push((lo - 32, hi - 32));
        }
        let (lo, hi) = (a.max(65), b.min(90));
        if lo <= hi {
            all.push((lo + 32, hi + 32));
        }
    }
    normalize_ranges(&all)
}

fn class_char(c: u32) -> String {
    let ch = char::from_u32(c).unwrap_or('\u{fffd}');
    if ch.is_ascii_alphanumeric() {
        return ch.to_string();
    }
    match c {
        9 => "\\t".into(),
        10 => "\\n".into(),
        13 => "\\r".into(),
        12 => "\\f".into(),
        11 => "\\v".into(),
        33..=126 => {
            if "\\]^-[".contains(ch) {
                format!("\\{ch}")
            } else {
                ch.to_string()
            }
        }
        32 => " ".into(),
        0..=0xff => format!("\\x{c:02x}"),
        _ => format!("\\u{c:04x}"),
    }
}

fn render_class(ranges: &[(u32, u32)], negated: bool) -> String {
    let r = normalize_ranges(ranges);
    if !negated && r.len() == 1 && r[0].0 == 0 && r[0].1 >= 0xffff {
        return "[\\s\\S]".into();
    }
    const BLOCKS: [(u32, u32); 3] = [(48, 57), (65, 90), (97, 122)];
    let mut body = String::new();
    for (a, b) in r {
        let mut c = a;
        while c <= b {
            if let Some(block) = BLOCKS.iter().find(|(lo, hi)| c >= *lo && c <= *hi) {
                let end = b.min(block.1);
                if end == c {
                    body += &class_char(c);
                } else if end == c + 1 {
                    body += &class_char(c);
                    body += &class_char(end);
                } else {
                    body += &format!("{}-{}", class_char(c), class_char(end));
                }
                c = end + 1;
            } else if !(32..=126).contains(&c) {
                let mut end = c;
                while end < b && !(32..=126).contains(&(end + 1)) {
                    end += 1;
                }
                if end - c >= 3 {
                    body += &format!("{}-{}", class_char(c), class_char(end));
                } else {
                    for k in c..=end {
                        body += &class_char(k);
                    }
                }
                c = end + 1;
            } else {
                body += &class_char(c);
                c += 1;
            }
        }
    }
    format!("[{}{body}]", if negated { "^" } else { "" })
}

#[derive(Debug, Clone, Copy)]
struct Flags {
    i: bool,
    s: bool,
}

/// A converted regex.
#[derive(Debug)]
pub struct Converted {
    pub regex: String,
    pub ignore_case: bool,
    pub groups: usize,
    /// Start of each capture group's body in the source pattern (char index).
    pub group_starts: Vec<usize>,
}

struct Conv {
    p: Vec<char>,
    i: usize,
    ignore_case: bool,
    groups: usize,
    group_starts: Vec<usize>,
    offset: usize,
}

/// Converts one RE2 regex (legacy `convertRegex`).
pub fn convert_regex(src: &str) -> R<Converted> {
    let mut pattern = src;
    let mut ignore_case = false;
    let flag_re = flag_switch_re();
    if let Some(rest) = pattern.strip_prefix("(?i)")
        && !flag_re.is_match(rest)
    {
        ignore_case = true;
        pattern = rest;
    }
    let p: Vec<char> = pattern.chars().collect();
    let offset = src.chars().count() - p.len();
    let mut c = Conv {
        p,
        i: 0,
        ignore_case,
        groups: 0,
        group_starts: Vec::new(),
        offset,
    };
    let mut flags = Flags {
        i: ignore_case,
        s: false,
    };
    let regex = c.parse_seq(&mut flags)?;
    if c.i != c.p.len() {
        return unsupported("多出來的右括號");
    }
    Ok(Converted {
        regex,
        ignore_case,
        groups: c.groups,
        group_starts: c.group_starts,
    })
}

fn flag_switch_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\(\?-?[a-z]*i").expect("valid"))
}

fn group_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^\(\?(P?<[A-Za-z_][A-Za-z0-9_]*>|[a-zA-Z]*(?:-[a-zA-Z]*)?[:)])")
            .expect("valid")
    })
}

fn quant_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\{(\d*)(,?)(\d*)\}").expect("valid"))
}

enum Atom {
    Char(u32),
    Set(Ranges),
}

impl Conv {
    fn at(&self, k: usize) -> Option<char> {
        self.p.get(k).copied()
    }
    fn rest(&self) -> String {
        self.p[self.i.min(self.p.len())..].iter().collect()
    }
    fn index_of(&self, s: &str, from: usize) -> Option<usize> {
        let pat: Vec<char> = s.chars().collect();
        (from..self.p.len()).find(|&k| self.p[k..].starts_with(&pat))
    }
    fn hex(&mut self) -> u32 {
        // After `\x`: `{…}` or two hex digits (JS parseInt semantics: NaN → 0 here).
        if self.at(self.i) == Some('{') {
            let end = self.index_of("}", self.i).unwrap_or(self.p.len());
            let v: String = self.p[self.i + 1..end].iter().collect();
            self.i = end + 1;
            u32::from_str_radix(&v, 16).unwrap_or(0)
        } else {
            let end = (self.i + 2).min(self.p.len());
            let v: String = self.p[self.i..end].iter().collect();
            self.i += 2;
            u32::from_str_radix(&v, 16).unwrap_or(0)
        }
    }

    fn read_class_atom(&mut self) -> R<Atom> {
        let c = self.at(self.i).unwrap_or('\0');
        if c == '[' && self.at(self.i + 1) == Some(':') {
            let Some(end) = self.index_of(":]", self.i) else {
                return unsupported("POSIX 類別沒有結束");
            };
            let name: String = self.p[self.i + 2..end].iter().collect();
            let Some(set) = posix(&name) else {
                return unsupported(format!("POSIX 類別 {name}"));
            };
            self.i = end + 2;
            return Ok(Atom::Set(set.to_vec()));
        }
        if c == '\\' {
            let e = self.at(self.i + 1).unwrap_or('\0');
            self.i += 2;
            return match e {
                'd' => Ok(Atom::Set(DIGIT.to_vec())),
                'w' => Ok(Atom::Set(WORD.to_vec())),
                's' => Ok(Atom::Set(SPACE.to_vec())),
                'D' | 'W' | 'S' => unsupported(format!("字元類別裡的 \\{e}")),
                'n' => Ok(Atom::Char(10)),
                'r' => Ok(Atom::Char(13)),
                't' => Ok(Atom::Char(9)),
                'f' => Ok(Atom::Char(12)),
                'v' => Ok(Atom::Char(11)),
                'x' => Ok(Atom::Char(self.hex())),
                'p' | 'P' => unsupported("Unicode 類別 \\p"),
                e if e.is_ascii_alphanumeric() => unsupported(format!("跳脫字元 \\{e}")),
                e => Ok(Atom::Char(e as u32)),
            };
        }
        self.i += 1;
        Ok(Atom::Char(c as u32))
    }

    fn parse_class(&mut self, flags: Flags) -> R<String> {
        self.i += 1; // [
        let mut negated = false;
        if self.at(self.i) == Some('^') {
            negated = true;
            self.i += 1;
        }
        let mut ranges: Ranges = Vec::new();
        let mut first = true;
        while first || self.at(self.i) != Some(']') {
            if self.i >= self.p.len() {
                return unsupported("字元類別沒有結束");
            }
            first = false;
            let a = match self.read_class_atom()? {
                Atom::Set(s) => {
                    ranges.extend(s);
                    continue;
                }
                Atom::Char(a) => a,
            };
            if self.at(self.i) == Some('-') && self.at(self.i + 1) != Some(']') {
                self.i += 1;
                match self.read_class_atom()? {
                    Atom::Set(_) => return unsupported("範圍的終點是類別"),
                    Atom::Char(b) => ranges.push((a, b)),
                }
            } else {
                ranges.push((a, a));
            }
        }
        self.i += 1; // ]
        if ranges.is_empty() {
            return unsupported("空的字元類別");
        }
        Ok(if flags.i && !self.ignore_case {
            render_class(&fold_case(&ranges), negated)
        } else {
            render_class(&ranges, negated)
        })
    }

    fn parse_quantifier(&mut self) -> R<Option<String>> {
        let c = self.at(self.i);
        let mut q = match c {
            Some(ch @ ('*' | '+' | '?')) => {
                self.i += 1;
                ch.to_string()
            }
            Some('{') => {
                let rest = self.rest();
                let Some(m) = quant_re().captures(&rest) else {
                    return Ok(None);
                };
                let (lo, hi) = (&m[1], &m[3]);
                if lo.is_empty() && hi.is_empty() {
                    return Ok(None);
                }
                if lo.is_empty() {
                    return unsupported("{,n} 量詞");
                }
                let all = m[0].to_owned();
                self.i += all.chars().count();
                all
            }
            _ => return Ok(None),
        };
        if self.at(self.i) == Some('?') {
            q.push('?');
            self.i += 1;
        }
        if self.at(self.i) == Some('+') {
            return unsupported("possessive 量詞");
        }
        Ok(Some(q))
    }

    fn parse_seq(&mut self, flags: &mut Flags) -> R<String> {
        let mut out = String::new();
        while self.i < self.p.len() {
            let c = self.p[self.i];
            if c == ')' {
                return Ok(out);
            }
            if c == '|' {
                out.push('|');
                self.i += 1;
                continue;
            }
            let atom: String;
            if c == '(' {
                if self.at(self.i + 1) == Some('?') {
                    let rest = self.rest();
                    let Some(m) = group_re().captures(&rest) else {
                        let head: String = rest.chars().take(6).collect();
                        return unsupported(format!("群組語法 {head}"));
                    };
                    let tok = m[1].to_owned();
                    let whole = m[0].chars().count();
                    if tok.ends_with('>') {
                        self.groups += 1;
                        self.i += whole;
                        self.group_starts.push(self.i + self.offset);
                        let mut inner = *flags;
                        atom = format!("({})", self.parse_seq(&mut inner)?);
                    } else {
                        let body = &tok[..tok.len() - 1];
                        let (on, off) = body.split_once('-').unwrap_or((body, ""));
                        if let Some(f) = on.chars().chain(off.chars()).find(|f| !"is".contains(*f))
                        {
                            return unsupported(format!("旗標 {f}"));
                        }
                        let mut next = *flags;
                        for f in on.chars() {
                            match f {
                                'i' => next.i = true,
                                _ => next.s = true,
                            }
                        }
                        for f in off.chars() {
                            match f {
                                'i' => next.i = false,
                                _ => next.s = false,
                            }
                        }
                        self.i += whole;
                        if tok.ends_with(')') {
                            // `(?i)`: changes the flags for the rest of this group.
                            *flags = next;
                            continue;
                        }
                        if self.ignore_case && off.contains('i') {
                            return unsupported("(?-i) 出現在整條 ignoreCase 的規則裡");
                        }
                        atom = format!("(?:{})", self.parse_seq(&mut next)?);
                    }
                } else {
                    self.groups += 1;
                    self.i += 1;
                    self.group_starts.push(self.i + self.offset);
                    let mut inner = *flags;
                    atom = format!("({})", self.parse_seq(&mut inner)?);
                }
                if self.at(self.i) != Some(')') {
                    return unsupported("括號沒有結束");
                }
                self.i += 1;
            } else if c == '[' {
                atom = self.parse_class(*flags)?;
            } else if c == '\\' {
                let e = self.at(self.i + 1).unwrap_or('\0');
                self.i += 2;
                atom = match e {
                    'd' => "[0-9]".into(),
                    'D' => "[^0-9]".into(),
                    'w' => "[A-Za-z0-9_]".into(),
                    'W' => "[^A-Za-z0-9_]".into(),
                    's' => render_class(SPACE, false),
                    'S' => render_class(SPACE, true),
                    'b' => "\\b".into(),
                    'B' => "\\B".into(),
                    'z' => "$".into(),
                    'A' => "^".into(),
                    'n' => "\\n".into(),
                    'r' => "\\r".into(),
                    't' => "\\t".into(),
                    'f' => "\\f".into(),
                    'x' => {
                        let v = self.hex();
                        render_class(&[(v, v)], false)
                    }
                    e if e.is_ascii_alphanumeric() => {
                        return unsupported(format!("跳脫字元 \\{e}"));
                    }
                    e => format!("\\{e}"),
                };
            } else if c == '.' {
                atom = if flags.s { "[\\s\\S]" } else { "[^\\n]" }.into();
                self.i += 1;
            } else if c == '^' || c == '$' {
                atom = c.to_string();
                self.i += 1;
            } else if matches!(c, '*' | '+' | '?') {
                return unsupported("量詞前面沒有東西");
            } else if c == '{' || c == '}' {
                atom = format!("\\{c}");
                self.i += 1;
            } else {
                self.i += 1;
                atom = if flags.i && !self.ignore_case && c.is_ascii_alphabetic() {
                    format!("[{}{}]", c.to_ascii_uppercase(), c.to_ascii_lowercase())
                } else if c.is_ascii_alphanumeric() || " _-:=,;'\"`<>@#%&~!/".contains(c) {
                    c.to_string()
                } else {
                    render_class(&[(c as u32, c as u32)], false)
                };
            }
            let q = self.parse_quantifier()?;
            if q.is_some() && matches!(atom.as_str(), "^" | "$" | "\\b" | "\\B") {
                return unsupported("錨點加量詞");
            }
            out.push_str(&atom);
            if let Some(q) = q {
                out.push_str(&q);
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------- rules

/// Dropped from the start of a regex: it only widens the match over the variable name.
const LEADING_NAME: &str = r"[\w.-]{0,50}?";

const WORDS: &[(&str, &str)] = &[
    ("api", "API"),
    ("aws", "AWS"),
    ("gcp", "GCP"),
    ("pat", "PAT"),
    ("id", "ID"),
    ("url", "URL"),
    ("sdk", "SDK"),
    ("jwt", "JWT"),
    ("oauth", "OAuth"),
    ("github", "GitHub"),
    ("gitlab", "GitLab"),
    ("npm", "npm"),
    ("pypi", "PyPI"),
    ("ssh", "SSH"),
    ("dsn", "DSN"),
    ("smtp", "SMTP"),
    ("ai", "AI"),
    ("iam", "IAM"),
    ("ci", "CI"),
    ("cli", "CLI"),
    ("hmac", "HMAC"),
    ("rsa", "RSA"),
    ("scm", "SCM"),
    ("sso", "SSO"),
    ("jfrog", "JFrog"),
    ("openai", "OpenAI"),
    ("huggingface", "Hugging Face"),
    ("digitalocean", "DigitalOcean"),
    ("newrelic", "New Relic"),
    ("sendgrid", "SendGrid"),
    ("sendinblue", "Sendinblue"),
    ("mailchimp", "Mailchimp"),
    ("mailgun", "Mailgun"),
    ("linkedin", "LinkedIn"),
    ("youtube", "YouTube"),
    ("pagerduty", "PagerDuty"),
    ("planetscale", "PlanetScale"),
    ("rubygems", "RubyGems"),
    ("dropbox", "Dropbox"),
    ("hashicorp", "HashiCorp"),
    ("mongodb", "MongoDB"),
    ("postman", "Postman"),
    ("twilio", "Twilio"),
    ("vault", "Vault"),
    ("1password", "1Password"),
    ("key", "key"),
    ("token", "token"),
    ("secret", "secret"),
    ("access", "access"),
    ("client", "client"),
    ("password", "password"),
    ("personal", "personal"),
    ("private", "private"),
    ("refresh", "refresh"),
    ("service", "service"),
    ("account", "account"),
    ("webhook", "webhook"),
    ("app", "app"),
    ("admin", "admin"),
    ("user", "user"),
    ("live", "live"),
    ("test", "test"),
];

/// Hand-picked labels where the generated one reads badly.
const LABELS: &[(&str, &str)] = &[("npm-access-token", "npm token")];

/// Covered by `rules/api-keys.json`, which has stricter bounds or extra validation.
const COVERED: &[(&str, &str)] = &[
    ("github-pat", "api-keys.json 的 github-token 已涵蓋（ghp_）"),
    (
        "github-oauth",
        "api-keys.json 的 github-token 已涵蓋（gho_）",
    ),
    (
        "github-app-token",
        "api-keys.json 的 github-token 已涵蓋（ghu_、ghs_）",
    ),
    (
        "github-refresh-token",
        "api-keys.json 的 github-token 已涵蓋（ghr_）",
    ),
    (
        "github-fine-grained-pat",
        "api-keys.json 的 github-fine-grained-pat 已涵蓋",
    ),
    ("jwt", "api-keys.json 的 jwt 已涵蓋，而且會驗 header"),
    (
        "private-key",
        "api-keys.json 的 private-key-pem 已涵蓋；gitleaks 的版本往後掃到 END 行，沒有長度上限",
    ),
];

/// Skipped for other reasons. Phase 1b: `curl-auth-header` and `curl-auth-user` are
/// kept again; the legacy converter skipped them only because a backtracking JS
/// engine made them O(n²), and Rust `regex` is linear.
const SKIP: &[(&str, &str)] = &[
    (
        "generic-api-key",
        "上下文＋亂度的通用規則由 rules/context.json（第 2 層）負責",
    ),
    (
        "sourcegraph-access-token",
        "其中一個分支是單獨的 40 位 hex，文字裡只要出現 sourcegraph 就會把 git commit SHA 當成 token（誤報樣本會擋）",
    ),
];

/// Rules more generic than layer 2 (`rules/context.json`, priority 30): they take
/// whatever follows `curl -H` / `curl -u`. They go to `rules/gitleaks-late.json`
/// (priority [`LATE_PRIORITY`]) so the calibrated layer-2 rules keep their labels
/// on overlaps and these only add what layer 2 misses (`curl -u user:pass`,
/// `-H "X-Token: …"`, short Basic credentials).
const LATE: &[&str] = &["curl-auth-header", "curl-auth-user"];

/// Priority of `rules/gitleaks-late.json`: after context.json (30), before the
/// PII packs (40).
const LATE_PRIORITY: f64 = 35.0;

fn lookup<'a>(table: &'a [(&str, &'a str)], k: &str) -> Option<&'a str> {
    table.iter().find(|(n, _)| *n == k).map(|(_, v)| *v)
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// Display label from a gitleaks id (`npm-access-token` → `npm token`).
pub fn label_from_id(id: &str) -> String {
    if let Some(l) = lookup(LABELS, id) {
        return l.to_owned();
    }
    id.split('-')
        .enumerate()
        .map(|(k, p)| match lookup(WORDS, p) {
            Some(w) if k == 0 && w.starts_with(|c: char| c.is_ascii_lowercase()) => capitalize(w),
            Some(w) => w.to_owned(),
            None if k == 0 => capitalize(p),
            None => p.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// An allowlist sample that is itself a whole key: plain literal, ≥ 20 chars.
fn is_literal_sample(re: &str) -> bool {
    re.encode_utf16().count() >= 20
        && !re
            .replace("\\.", "")
            .contains(|c: char| "\\[](){}*+?|^$".contains(c))
}

/// Literal chars at the start of `src[start..]` (stops at regex syntax); a char
/// followed by a quantifier does not count.
fn literal_prefix_length(src: &[char], start: usize) -> usize {
    let mut k = start;
    let mut n = 0;
    while k < src.len() {
        let c = src[k];
        if c == '\\' {
            match src.get(k + 1) {
                Some(e) if e.is_ascii_alphanumeric() => break,
                _ => {}
            }
            k += 2;
            n += 1;
            continue;
        }
        if "[](){}*+?|^$.".contains(c) {
            break;
        }
        k += 1;
        n += 1;
    }
    if n > 0 && src.get(k).is_some_and(|c| "*+?{".contains(*c)) {
        n -= 1;
    }
    n
}

fn convert_exclusions(allowlists: &[&J], notes: &mut Vec<String>) -> (Vec<J>, Vec<J>) {
    let mut exclude = Vec::new();
    let mut stopwords = Vec::new();
    for a in allowlists {
        if a.get("paths").is_some_and(J::truthy)
            && a.get("condition")
                .and_then(J::as_str)
                .unwrap_or("OR")
                .eq_ignore_ascii_case("AND")
        {
            // Must also match a path: the clipboard has none, so it never holds.
            continue;
        }
        let target = a.get("regexTarget").and_then(J::as_str).unwrap_or("secret");
        for re in a.get("regexes").map(J::as_arr).unwrap_or_default() {
            let Some(re) = re.as_str() else { continue };
            if is_literal_sample(re) {
                notes.push("allowlist 的完整 key 範例沒有收錄".into());
                continue;
            }
            match convert_regex(re) {
                Ok(c) => {
                    let mut f = vec![("regex", J::Str(c.regex))];
                    if c.ignore_case {
                        f.push(("ignoreCase", J::Bool(true)));
                    }
                    if target != "secret" {
                        f.push(("target", s(target)));
                    }
                    exclude.push(obj(f));
                }
                Err(Unsupported(m)) => notes.push(format!("allowlist regex 無法轉換（{m}）")),
            }
        }
        for w in a.get("stopwords").map(J::as_arr).unwrap_or_default() {
            if let Some(w) = w.as_str() {
                stopwords.push(J::Str(w.to_lowercase()));
            }
        }
    }
    (exclude, stopwords)
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

/// Converts a parsed gitleaks.toml (legacy `convertConfig`) into the contents of
/// `rules/gitleaks.json` and `rules/gitleaks-late.json` ([`LATE`] rules).
pub fn convert_config(toml: &J, version: &str, commit: &str) -> Result<(J, J)> {
    let mut rules = Vec::new();
    let mut late = Vec::new();
    let mut skipped = Vec::new();
    for r in toml.get("rules").map(J::as_arr).unwrap_or_default() {
        let id = r.get("id").and_then(J::as_str).context("rule without id")?;
        let mut skip = |reason: &str| {
            skipped.push(obj(vec![("id", s(id)), ("reason", s(reason))]));
        };
        if let Some(reason) = lookup(SKIP, id).or_else(|| lookup(COVERED, id)) {
            skip(reason);
            continue;
        }
        let Some(regex) = r.get("regex").and_then(J::as_str).filter(|x| !x.is_empty()) else {
            skip("只比對檔名（path），剪貼簿沒有檔名");
            continue;
        };
        if r.get("path").is_some_and(J::truthy) {
            skip("只在特定檔案類型（path）才成立，剪貼簿沒有檔名，套用到所有文字誤報太高");
            continue;
        }
        if id.ends_with("-client-id") {
            skip("client ID 是公開的識別碼，不是機密");
            continue;
        }
        let keywords = r.get("keywords").map(J::as_arr).unwrap_or_default();
        if keywords.is_empty() {
            skip("沒有 keywords，無法預先篩選，每段文字都要跑");
            continue;
        }

        let nested = format!("{LEADING_NAME}(?i:{LEADING_NAME}");
        let ci_leading = format!("(?i){LEADING_NAME}");
        let regex: String = if let Some(rest) = regex.strip_prefix(nested.as_str()) {
            format!("(?i:{rest}")
        } else if let Some(rest) = regex.strip_prefix(ci_leading.as_str()) {
            format!("(?i){rest}")
        } else if let Some(rest) = regex.strip_prefix(LEADING_NAME) {
            rest.to_owned()
        } else {
            regex.to_owned()
        };

        let c = match convert_regex(&regex) {
            Ok(c) => c,
            Err(Unsupported(m)) => {
                skip(&format!("regex 無法轉成 .NET 與 JS 共用的語法：{m}"));
                continue;
            }
        };

        let mut notes = Vec::new();
        let allowlists: Vec<&J> = r
            .get("allowlists")
            .map(J::as_arr)
            .unwrap_or_default()
            .iter()
            .collect();
        let (exclude, stopwords) = convert_exclusions(&allowlists, &mut notes);
        let secret_group = match r.get("secretGroup") {
            Some(J::Num(n)) => Some(*n as usize),
            _ => None,
        };
        let group_index = secret_group.unwrap_or(usize::from(c.groups > 0));
        let src: Vec<char> = regex.chars().collect();
        let mut start = if group_index > 0 {
            c.group_starts.get(group_index - 1).copied().unwrap_or(0)
        } else {
            0
        };
        if group_index == 0 && regex.starts_with("\\b") {
            start = 2;
        }
        let keep_start = literal_prefix_length(&src, start).min(16);

        let mut f: Vec<(&str, J)> = vec![
            ("id", J::Str(format!("gitleaks.{id}"))),
            ("kind", s("api-key")),
            ("label", J::Str(label_from_id(id))),
            ("regex", J::Str(c.regex)),
        ];
        if c.ignore_case {
            f.push(("ignoreCase", J::Bool(true)));
        }
        if let Some(g) = secret_group {
            f.push(("secretGroup", J::Num(g as f64)));
        }
        let kws = dedup(
            keywords
                .iter()
                .filter_map(J::as_str)
                .map(str::to_lowercase)
                .collect(),
        );
        f.push(("keywords", J::Arr(kws.into_iter().map(J::Str).collect())));
        if let Some(e) = r.get("entropy").filter(|e| e.truthy()) {
            f.push(("entropy", e.clone()));
        }
        if !exclude.is_empty() {
            f.push(("exclude", J::Arr(exclude)));
        }
        if !stopwords.is_empty() {
            f.push(("stopwords", J::Arr(stopwords)));
        }
        f.push(("mask", obj(vec![("keepStart", J::Num(keep_start as f64))])));
        if !notes.is_empty() {
            f.push((
                "notes",
                J::Arr(dedup(notes).into_iter().map(J::Str).collect()),
            ));
        }
        if LATE.contains(&id) {
            late.push(obj(f));
        } else {
            rules.push(obj(f));
        }
    }

    let global: Vec<&J> = toml.get("allowlist").into_iter().collect();
    let (exclude, stopwords) = convert_exclusions(&global, &mut Vec::new());
    let file = |name: &str, priority: f64, description: &str, skipped: Vec<J>, rules: Vec<J>| {
        obj(vec![
            ("format", J::Num(1.0)),
            ("name", s(name)),
            ("priority", J::Num(priority)),
            ("description", s(description)),
            (
                "source",
                obj(vec![
                    ("project", s("https://github.com/gitleaks/gitleaks")),
                    ("file", s("config/gitleaks.toml")),
                    ("license", s("MIT")),
                    ("version", s(version)),
                    ("commit", s(commit)),
                ]),
            ),
            ("exclude", J::Arr(exclude.clone())),
            ("stopwords", J::Arr(stopwords.clone())),
            ("skipped", J::Arr(skipped)),
            ("rules", J::Arr(rules)),
        ])
    };
    Ok((
        file(
            "gitleaks",
            20.0,
            "由 cargo xtask rules gitleaks 從 gitleaks 預設規則轉換產生，不要手動修改。授權見 THIRD_PARTY_NOTICES.md。",
            skipped,
            rules,
        ),
        file(
            "gitleaks-late",
            LATE_PRIORITY,
            "由 cargo xtask rules gitleaks 從 gitleaks 預設規則轉換產生，不要手動修改。比第 2 層（context.json）更泛的規則（curl 的標頭與帳密），排在它後面，重疊時以第 2 層的標籤為準。授權見 THIRD_PARTY_NOTICES.md。",
            Vec::new(),
            late,
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_conversion() {
        let c = convert_regex(r"(?i)\b(foo)[\w.-]{8}\z").unwrap();
        assert!(c.ignore_case);
        assert_eq!(c.regex, r"\b(foo)[\-.0-9A-Z_a-z]{8}$");
        let c = convert_regex(r"x(?i:ab)").unwrap();
        assert_eq!(c.regex, "x(?:[Aa][Bb])");
        assert!(convert_regex(r"a\pL").is_err());
        let c = convert_regex(r"(?P<n>a)(b)").unwrap();
        assert_eq!((c.regex.as_str(), c.groups), ("(a)(b)", 2));
    }

    #[test]
    fn toml_subset() {
        let t = parse_toml(
            "title = \"x\"\n[allowlist]\nregexes = ['''a''', 'b']\n[[rules]]\nid = \"r\"\nentropy = 3.5\n[[rules.allowlists]]\nstopwords = [\"S\"]\n",
        )
        .unwrap();
        let r = &t.get("rules").unwrap().as_arr()[0];
        assert_eq!(r.get("entropy"), Some(&J::Num(3.5)));
        assert_eq!(r.get("allowlists").unwrap().as_arr().len(), 1);
        assert_eq!(
            t.get("allowlist")
                .unwrap()
                .get("regexes")
                .unwrap()
                .as_arr()
                .len(),
            2
        );
    }

    #[test]
    fn labels() {
        assert_eq!(label_from_id("npm-access-token"), "npm token");
        assert_eq!(label_from_id("curl-auth-header"), "Curl auth header");
        assert_eq!(label_from_id("github-pat"), "GitHub PAT");
    }

    #[test]
    fn json_like_js() {
        let mut o = String::new();
        write_json(
            &obj(vec![
                ("a", J::Arr(vec![])),
                ("b", J::Num(2.75)),
                ("c", s("q\"\u{1}")),
            ]),
            0,
            &mut o,
        );
        assert_eq!(
            o,
            "{\n  \"a\": [],\n  \"b\": 2.75,\n  \"c\": \"q\\\"\\u0001\"\n}"
        );
    }
}
