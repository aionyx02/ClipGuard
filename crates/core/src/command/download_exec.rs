//! Download-and-execute (legacy `DownloadExecution`, docs/spec/detection-rules.md
//! §3.1–3.2, #20): fetch content from the network and hand it to iex, PowerShell,
//! cmd or a shell, or save it to a file and start that file. This is the core
//! ClickFix move and is enough to block on its own, unless every source host is an
//! official installer host (F17), in which case it only warns.
//!
//! Only matches normalized text ([`super::normalize`]).

use paste_warden_rules::command::CommandRules;

use super::re::{alternation, lazy_re};

const FETCH: &str = r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)(?:\.exe)?\b";
const INTERPRETER: &str = r"(?:iex|invoke-expression|powershell|pwsh|cmd|(?:ba|z)?sh)(?:\.exe)?\b";
const WEB_CLIENT: &str = r"\(?\s*new-object\s+(?:system\.)?net\.webclient\b";

lazy_re! {
    /// Any kind of download (combined with other conditions).
    pub(crate) fn any_fetch = format!(
        r"(?i){FETCH}|download(?:string|data|file)\b|\bnet\.webclient\b|\bstart-bitstransfer\b|\bcertutil\b.*-urlcache|\bbitsadmin\b.*/transfer"
    );
}
lazy_re! {
    /// A: download piped to iex or an interpreter. The download needs at least one
    /// argument so a table row `| curl | cmd |` does not count.
    fn pipe_to_interpreter = format!(
        r"(?i)(?:{FETCH}\s+[^\s|]|download(?:string|data)\s*\()[^\r\n]*\|\s*{INTERPRETER}"
    );
}
lazy_re! {
    /// B: iex wrapping a download.
    fn invoke_fetch = format!(
        r#"(?i)\b(?:iex|invoke-expression)\b[\s("'&{{$]*(?:{FETCH}|{WEB_CLIENT}|\[(?:system\.)?net\.webclient\])"#
    );
}
lazy_re! {
    /// C (1/2): download stored in a variable.
    fn assign_fetch = format!(
        r#"(?i)\$[\w:]+\s*=\s*[\s("'$]*(?:{FETCH}|{WEB_CLIENT})|\$[\w:]+\s*=\s*[^\r\n;]*download(?:string|data)\s*\("#
    );
}
lazy_re! {
    /// C (2/2): iex of a variable.
    fn invoke_variable =
        r#"(?i)\b(?:iex|invoke-expression)\b[\s("'&{]*\$|\$[\w:]+[^\r\n|]*\|\s*(?:iex|invoke-expression)\b"#;
}
lazy_re! {
    /// D: `[ScriptBlock]::Create` (with any download).
    fn script_block_create = r"(?i)scriptblock\]\s*::\s*create\b";
}
lazy_re! {
    /// E (1/2): download saved to a file.
    fn save_to_file = r"(?im)-outfile\b|\bdownloadfile\b|-urlcache\b|/transfer\b|\bstart-bitstransfer\b|(?:^|\s)(?:-o|--output|--output-document)(?:\s|=)";
}
lazy_re! {
    /// E (2/2): a file being started.
    fn run_file = format!(
        r#"(?im)\b(?:start-process|saps|invoke-item)\b|(?:^|[;&|(])\s*(?:start|call)\s+\S|(?:^|[;(]|&&|\|\|)\s*&\s*\S|(?:^|[;&|(])\s*["']?[^\s"'|&;<>()]*\.(?:{})\b"#,
        alternation(&CommandRules::embedded().extensions.launch)
    );
}
lazy_re! {
    /// URL host: up to the next separator; [`clean_host`] removes `user@` and the
    /// port. Backslash ends the host too (`https://evil\.astral.sh` → `evil`).
    fn url_host = r#"(?i)\b(?:https?|ftp)://(?P<host>[^/\s"'`)\]|;?#\\]*)"#;
}
lazy_re! {
    /// Download target without a scheme (`irm get.scoop.sh`, `iwr -useb get.scoop.sh`).
    /// The host must be followed by a separator, so `irm astral.sh@x` yields no host.
    fn bare_host = format!(
        r#"(?im){FETCH}(?:\s+-(?:usebasicparsing|useb|uri|[fsl]{{1,4}}))*\s+["']?(?P<host>[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:$|[\s/"'|;)])"#
    );
}
lazy_re! {
    /// URLs built from pieces cannot be trusted (`'https://astral.sh'+'.example.invalid'`).
    fn built_string = r#"(?i)["']\s*\+|\+\s*["']|-join\b|\[char\]|["']\s*-f\b|-replace\b|`|frombase64string"#;
}
lazy_re! {
    /// Lines that may carry the source host: execution and variable assignments.
    fn relevant_line = r#"(?i)\b(?:iex|invoke-expression)\b|scriptblock\]|\$[\w:]+\s*=|\bset\s+"?[a-z_][\w.-]*="#;
}

/// Does normalized `text` contain a download-and-execute construct?
pub(crate) fn is_match(text: &str) -> bool {
    if pipe_to_interpreter().is_match(text) || invoke_fetch().is_match(text) {
        return true;
    }
    if assign_fetch().is_match(text) && invoke_variable().is_match(text) {
        return true;
    }
    if script_block_create().is_match(text) && any_fetch().is_match(text) {
        return true;
    }
    save_to_file().is_match(text) && run_file().is_match(text) && any_fetch().is_match(text)
}

/// Every host on the download / execute / assignment lines is an official
/// installer host, at least one host was found, and no URL is built from pieces.
/// Other lines (a README link copied along with the command) are ignored.
pub(crate) fn is_from_official_source(text: &str) -> bool {
    if built_string().is_match(text) {
        return false;
    }
    let relevant = text
        .split('\n')
        .filter(|line| any_fetch().is_match(line) || relevant_line().is_match(line))
        .collect::<Vec<_>>()
        .join("\n");
    let hosts = hosts(&relevant);
    !hosts.is_empty() && hosts.iter().all(|h| is_official_host(h))
}

/// Is `host` an official installer host or a subdomain of one
/// (`rules/command/official-hosts.json`)? ASCII only, case-insensitive; substrings,
/// prefixes and extra characters never match.
pub fn is_official_host(host: &str) -> bool {
    is_ascii_host(host)
        && CommandRules::embedded().official_hosts.iter().any(|o| {
            let o = o.host.as_str();
            host.eq_ignore_ascii_case(o)
                || host.len() > o.len()
                    && host.get(host.len() - o.len() - 1..).is_some_and(|tail| {
                        tail.starts_with('.') && tail[1..].eq_ignore_ascii_case(o)
                    })
        })
}

/// `^[a-z0-9-]+(?:\.[a-z0-9-]+)+$`, ASCII only.
fn is_ascii_host(host: &str) -> bool {
    let mut labels = 0;
    for label in host.split('.') {
        if label.is_empty()
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
        labels += 1;
    }
    labels >= 2
}

/// Download hosts in `text` (URLs first, then scheme-less targets), lowercase,
/// without duplicates, in order of appearance.
pub(crate) fn hosts(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let raw = url_host()
        .get()
        .into_iter()
        .flat_map(|r| r.captures_iter(text))
        .chain(
            bare_host()
                .get()
                .into_iter()
                .flat_map(|r| r.captures_iter(text)),
        )
        .filter_map(|c| c.name("host").map(|m| m.as_str()));
    for h in raw {
        let h = clean_host(h);
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// Drops `user@`, a trailing `:port`, trailing dots; lowercases.
fn clean_host(raw: &str) -> String {
    let host = raw.rsplit_once('@').map_or(raw, |(_, h)| h);
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    host.to_lowercase().trim_end_matches('.').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [
            any_fetch(),
            pipe_to_interpreter(),
            invoke_fetch(),
            assign_fetch(),
            invoke_variable(),
            script_block_create(),
            save_to_file(),
            run_file(),
            url_host(),
            bare_host(),
            built_string(),
            relevant_line(),
        ] {
            assert!(re.compiled());
        }
    }

    #[test]
    fn official_hosts() {
        assert!(is_official_host("astral.sh"));
        assert!(is_official_host("DOCS.Astral.sh"));
        assert!(!is_official_host("xastral.sh"));
        assert!(!is_official_host("astral.sh.example.invalid"));
        assert!(!is_official_host("a\u{212A}a.ms"));
        assert!(!is_official_host("sh"));
    }

    #[test]
    fn host_extraction() {
        assert_eq!(
            hosts("irm https://user@Astral.sh:443/x | iex; iwr -useb get.scoop.sh"),
            vec!["astral.sh", "get.scoop.sh"]
        );
        assert_eq!(hosts(r"iwr https://evil\.astral.sh"), vec!["evil"]);
        assert!(hosts("irm astral.sh@example.invalid").is_empty());
    }
}
