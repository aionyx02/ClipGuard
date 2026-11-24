//! cmd variable edits: substrings `%x:~start,length%` / `!x:~start,length!` and
//! replacements `%x:old=new%` / `%x:*old=new%`, on `set` variables and the fixed
//! system variables (`%ComSpec:~-7,3%` → `cmd`). Never reads the environment.

use crate::command::normalize::{MAX_EXPANSIONS, lookup_variable, set_variables};
use crate::command::re::lazy_re;

const NAME: &str = r"[a-z_][\w.#$@()-]{0,63}";

lazy_re! {
    fn substring = format!(
        r"(?i)%(?P<n>{NAME}):~(?P<a>-?\d{{1,6}})(?:,(?P<b>-?\d{{1,6}}))?%|!(?P<n2>{NAME}):~(?P<a2>-?\d{{1,6}})(?:,(?P<b2>-?\d{{1,6}}))?!"
    );
}
lazy_re! {
    fn substitute = format!(
        r"(?i)%(?P<n>{NAME}):(?P<o>\*?[^=%!~\r\n][^=%!\r\n]{{0,63}})=(?P<r>[^%!\r\n]{{0,64}})%|!(?P<n2>{NAME}):(?P<o2>\*?[^=%!~\r\n][^=%!\r\n]{{0,63}})=(?P<r2>[^%!\r\n]{{0,64}})!"
    );
}

/// cmd's `%x:~a,b%`: negative `a` counts from the end; negative `b` drops chars
/// from the end; no `b` means "to the end".
fn cut(value: &str, a: i64, b: Option<i64>) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = i64::try_from(chars.len()).unwrap_or(i64::MAX);
    let start = if a < 0 { (len + a).max(0) } else { a.min(len) };
    let end = match b {
        None => len,
        Some(b) if b < 0 => (len + b).max(start),
        Some(b) => (start + b).min(len),
    };
    let (s, e) = (
        usize::try_from(start).unwrap_or(0),
        usize::try_from(end.max(start)).unwrap_or(0),
    );
    chars
        .get(s..e)
        .map(|c| c.iter().collect())
        .unwrap_or_default()
}

/// Case-insensitive replace of every `old` (or, with `*old`, of everything up to
/// and including the first `old`).
fn substitute_value(value: &str, old: &str, new: &str) -> String {
    let lower = value.to_lowercase();
    if let Some(old) = old.strip_prefix('*') {
        let o = old.to_lowercase();
        return match lower.find(&o) {
            // Lowercasing can change byte lengths; fall back to no change then.
            Some(i) if lower.len() == value.len() => format!("{new}{}", &value[i + o.len()..]),
            _ => value.to_owned(),
        };
    }
    let o = old.to_lowercase();
    if o.is_empty() || lower.len() != value.len() {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len());
    let mut copied = 0;
    for (i, _) in lower.match_indices(&o) {
        if i < copied {
            continue;
        }
        out.push_str(&value[copied..i]);
        out.push_str(new);
        copied = i + o.len();
    }
    out.push_str(&value[copied..]);
    out
}

/// Expands cmd substrings and replacements of known variables.
pub(super) fn substrings(s: &str) -> Option<(String, usize)> {
    if !s.contains(":~") && !s.contains('=') {
        return None;
    }
    let vars = set_variables(s);
    let mut count = 0usize;
    let mut out = s.to_owned();
    if let Some(re) = substring().get() {
        out = re
            .replace_all(&out, |c: &regex::Captures<'_>| {
                let whole = c.get(0).map_or("", |m| m.as_str()).to_owned();
                if count >= MAX_EXPANSIONS {
                    return whole;
                }
                let (n, a, b) = match c.name("n") {
                    Some(n) => (n, c.name("a"), c.name("b")),
                    None => match c.name("n2") {
                        Some(n) => (n, c.name("a2"), c.name("b2")),
                        None => return whole,
                    },
                };
                let Some(value) = lookup_variable(&vars, n.as_str()) else {
                    return whole;
                };
                let a = a.and_then(|m| m.as_str().parse::<i64>().ok()).unwrap_or(0);
                let b = b.and_then(|m| m.as_str().parse::<i64>().ok());
                count += 1;
                cut(value, a, b)
            })
            .into_owned();
    }
    if let Some(re) = substitute().get() {
        out = re
            .replace_all(&out, |c: &regex::Captures<'_>| {
                let whole = c.get(0).map_or("", |m| m.as_str()).to_owned();
                if count >= MAX_EXPANSIONS {
                    return whole;
                }
                let (n, o, r) = match c.name("n") {
                    Some(n) => (n, c.name("o"), c.name("r")),
                    None => match c.name("n2") {
                        Some(n) => (n, c.name("o2"), c.name("r2")),
                        None => return whole,
                    },
                };
                let (Some(value), Some(o)) = (lookup_variable(&vars, n.as_str()), o) else {
                    return whole;
                };
                count += 1;
                substitute_value(value, o.as_str(), r.map_or("", |m| m.as_str()))
            })
            .into_owned();
    }
    (count > 0).then_some((out, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        assert!(substring().compiled());
        assert!(substitute().compiled());
    }

    #[test]
    fn cuts() {
        assert_eq!(cut("abcdef", 1, Some(3)), "bcd");
        assert_eq!(cut("abcdef", -2, None), "ef");
        assert_eq!(cut("abcdef", 0, Some(-2)), "abcd");
        assert_eq!(cut("abcdef", 10, Some(2)), "");
        assert_eq!(cut("abcdef", -10, Some(2)), "ab");
        assert_eq!(cut("abcdef", 4, Some(-4)), "");
    }

    #[test]
    fn substitutions() {
        assert_eq!(substitute_value("mZhta", "z", "s"), "mshta");
        assert_eq!(substitute_value("xxmshta", "*xx", ""), "mshta");
        assert_eq!(
            substrings("set x=AB&& %x:b=c% !x:~1!")
                .map(|(s, _)| s)
                .as_deref(),
            Some("set x=AB&& Ac B")
        );
        assert_eq!(substrings("%nope:~1,2%"), None);
    }
}
