//! Pastejacking: compares the text the user selected with the text the page
//! actually wrote to the clipboard (legacy browser extension `lib/pastejack.js`,
//! docs/spec/detection-rules.md §7).
//!
//! The legacy implementation is JavaScript; this port keeps its semantics,
//! including JS-specific details: `\s` / `trim()` use the ECMAScript whitespace
//! set, `\b` is an ASCII word boundary and `/i` folds ASCII letters only.

mod data;

pub use data::{PastejackRules, SignalMatcher, SignalRule};

use crate::Message;

/// Default `max` of [`preview`] (legacy `preview(text, max = 160)`), in UTF-16 code units.
pub const PREVIEW_MAX: usize = 160;

/// Invisible characters counted and stripped by the extension (legacy `HIDDEN_CHARS`,
/// now `rules/pastejack/hidden-chars.json`). Unlike the desktop detector there are no
/// exception rules: only the count the page *added* matters, so a flag or soft hyphen
/// the user selected cancels out.
pub fn is_hidden_char(c: char) -> bool {
    // Fast path: everything listed is outside ASCII.
    !c.is_ascii()
        && PastejackRules::embedded()
            .hidden_chars
            .iter()
            .any(|r| r.contains(&c))
}

/// ECMAScript `WhiteSpace` + `LineTerminator` (what JS `\s` and `trim()` match).
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn is_js_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// JS `String.prototype.trim`.
fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_space)
}

/// A command signal: the page-added content looks like something to execute.
/// A compact subset of the desktop command detector (legacy `COMMAND_SIGNALS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandSignal {
    PowerShell,
    Mshta,
    Cmd,
    PipeShell,
    Iex,
    Lolbin,
    Sudo,
}

impl CommandSignal {
    /// All signals, in legacy order.
    pub const ALL: [CommandSignal; 7] = [
        CommandSignal::PowerShell,
        CommandSignal::Mshta,
        CommandSignal::Cmd,
        CommandSignal::PipeShell,
        CommandSignal::Iex,
        CommandSignal::Lolbin,
        CommandSignal::Sudo,
    ];

    /// Short id, also the selector value used by the `pastejack-added` message.
    pub fn as_str(self) -> &'static str {
        match self {
            CommandSignal::PowerShell => "powershell",
            CommandSignal::Mshta => "mshta",
            CommandSignal::Cmd => "cmd",
            CommandSignal::PipeShell => "pipe-shell",
            CommandSignal::Iex => "iex",
            CommandSignal::Lolbin => "lolbin",
            CommandSignal::Sudo => "sudo",
        }
    }

    /// The signal's display name (legacy `pj_sig_*`).
    pub fn message(self) -> Message {
        Message::new(match self {
            CommandSignal::PowerShell => "pastejack-sig-powershell",
            CommandSignal::Mshta => "pastejack-sig-mshta",
            CommandSignal::Cmd => "pastejack-sig-cmd",
            CommandSignal::PipeShell => "pastejack-sig-pipe-shell",
            CommandSignal::Iex => "pastejack-sig-iex",
            CommandSignal::Lolbin => "pastejack-sig-lolbin",
            CommandSignal::Sudo => "pastejack-sig-sudo",
        })
    }

    /// Matches the ASCII-lowercased text with this signal's rule from
    /// `rules/pastejack/signals.json` (no rule = never matches).
    fn matches(self, lower: &str) -> bool {
        match PastejackRules::embedded()
            .signal(self.as_str())
            .map(|r| &r.matcher)
        {
            Some(SignalMatcher::Invocation(names)) => invocation(lower, names),
            Some(SignalMatcher::Regex(re)) => re.is_match(lower),
            None => false,
        }
    }
}

/// `(?:^|[\s;&|("'])(?:name)(?:\.exe)?(?=\s+[-/"'#a-z0-9]|\s*$|\s*[|;&])` with `/im`:
/// the program name must be followed by an argument, a quote, a comment, the end
/// of a line or a pipe / separator to count as a call (like C# `Invocation()`).
fn invocation(lower: &str, names: &[String]) -> bool {
    names.iter().any(|name| {
        lower.match_indices(name.as_str()).any(|(at, _)| {
            let before_ok = lower[..at]
                .chars()
                .next_back()
                .is_none_or(|c| is_js_space(c) || matches!(c, ';' | '&' | '|' | '(' | '"' | '\''));
            if !before_ok {
                return false;
            }
            let rest = &lower[at + name.len()..];
            // `(?:\.exe)?` then the lookahead; without `.exe` the next char would be `.`,
            // which can never satisfy the lookahead, so trying both is the same as this.
            invocation_tail(rest.strip_prefix(".exe").unwrap_or(rest))
        })
    })
}

/// The lookahead `(?=\s+[-/"'#a-z0-9]|\s*$|\s*[|;&])` (`$` is multiline).
fn invocation_tail(rest: &str) -> bool {
    let mut spaces = 0usize;
    for c in rest.chars() {
        if is_js_line_terminator(c) {
            return true; // `\s*` stops right before a line end
        }
        if is_js_space(c) {
            spaces += 1;
            continue;
        }
        return matches!(c, '|' | ';' | '&')
            || (spaces > 0
                && (matches!(c, '-' | '/' | '"' | '\'' | '#') || c.is_ascii_alphanumeric()));
    }
    true // end of input
}

/// Command signals present in `text` (legacy `commandSignals`), in legacy order.
pub fn command_signals(text: &str) -> Vec<CommandSignal> {
    if text.is_empty() {
        return Vec::new();
    }
    let lower = text.to_ascii_lowercase();
    CommandSignal::ALL
        .into_iter()
        .filter(|s| s.matches(&lower))
        .collect()
}

/// Comparison normalization (legacy `normalize`): drops invisible characters, unifies
/// line breaks and no-break spaces, collapses whitespace runs to one space, trims.
pub fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    // `\r\n?` → `\n` and the no-break spaces → ' ' are all whitespace, so they
    // vanish into the whitespace collapse below.
    for c in text.chars().filter(|c| !is_hidden_char(*c)) {
        if is_js_space(c) {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(c);
    }
    out
}

fn hidden_char_count(text: &str) -> usize {
    text.chars().filter(|c| is_hidden_char(*c)).count()
}

/// How the written text relates to the selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyKind {
    /// The page wrote nothing (blocks copying; not pastejacking).
    Empty,
    /// Same content.
    Same,
    /// Keeps the selection but adds something (news sites add attribution).
    Appended,
    /// The selection is gone or changed.
    Replaced,
    /// Nothing was selected; the page wrote on its own (copy buttons).
    Unselected,
}

impl CopyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CopyKind::Empty => "empty",
            CopyKind::Same => "same",
            CopyKind::Appended => "appended",
            CopyKind::Replaced => "replaced",
            CopyKind::Unselected => "unselected",
        }
    }
}

/// Result of [`compare`] (legacy `analyzeCopy` return value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastejackVerdict {
    pub kind: CopyKind,
    /// Whether to warn the user.
    pub warn: bool,
    pub reasons: Vec<Message>,
}

/// Compares the user's `selection` with what the page `written` to the clipboard
/// (legacy `analyzeCopy({selection, written})`).
pub fn compare(selection: &str, written: &str) -> PastejackVerdict {
    let sel = normalize(selection);
    let wr = normalize(written);
    let mut reasons = Vec::new();
    let verdict = |kind, warn, reasons| PastejackVerdict {
        kind,
        warn,
        reasons,
    };

    let written_hidden = hidden_char_count(written);
    if wr.is_empty() && written_hidden == 0 {
        return verdict(CopyKind::Empty, false, reasons);
    }

    let new_hidden = written_hidden > hidden_char_count(selection);
    if new_hidden {
        reasons.push(Message::new("pastejack-hidden"));
    }

    // Only signals the page added count; a command the user selected (a tutorial) does not.
    let sel_signals = command_signals(selection);
    let added: Vec<CommandSignal> = command_signals(written)
        .into_iter()
        .filter(|s| !sel_signals.contains(s))
        .collect();
    // A line break acts as Enter: pasted into a terminal it runs immediately.
    let added_newline_exec =
        js_trim(written).contains('\n') && !js_trim(selection).contains('\n') && !added.is_empty();
    reasons.extend(
        added
            .iter()
            .map(|s| Message::new("pastejack-added").arg("signal", s.as_str())),
    );
    if added_newline_exec {
        reasons.push(Message::new("pastejack-newline"));
    }

    if sel.is_empty() {
        let warn = !added.is_empty() || new_hidden;
        return verdict(CopyKind::Unselected, warn, reasons);
    }
    if sel == wr {
        return verdict(CopyKind::Same, new_hidden, reasons);
    }
    if wr.contains(&sel) {
        let warn = !reasons.is_empty();
        return verdict(CopyKind::Appended, warn, reasons);
    }
    reasons.insert(0, Message::new("pastejack-replaced"));
    verdict(CopyKind::Replaced, true, reasons)
}

/// Display text for the warning (legacy `preview`): invisible characters become
/// `⟦U+XXXX⟧`, then the result is cut to `max` UTF-16 code units plus `…`.
/// A cut that would split a surrogate pair drops that character.
pub fn preview(text: &str, max: usize) -> String {
    let mut visible = String::with_capacity(text.len());
    for c in text.chars() {
        if is_hidden_char(c) {
            visible.push_str(&format!("⟦U+{:04X}⟧", u32::from(c)));
        } else {
            visible.push(c);
        }
    }
    if crate::text::utf16_len(&visible) <= max {
        return visible;
    }
    let cut = crate::text::utf16_to_byte(&visible, max);
    let mut out = visible.get(..cut).unwrap_or_default().to_owned();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals() {
        assert!(command_signals("我在學 PowerShell 很好玩").is_empty());
        assert!(command_signals("see github.com/powershell/powershell").is_empty());
        assert_eq!(command_signals("cmd /c whoami"), [CommandSignal::Cmd]);
        assert_eq!(
            command_signals("PWSH.exe -c x"),
            [CommandSignal::PowerShell]
        );
        assert_eq!(command_signals("x;pwsh"), [CommandSignal::PowerShell]);
        assert_eq!(command_signals("pwsh  \nfoo"), [CommandSignal::PowerShell]);
        assert!(command_signals("pwsh.exe.bak").is_empty());
        assert_eq!(
            command_signals("curl -s https://x.invalid/p | bash"),
            [CommandSignal::PipeShell]
        );
        assert!(command_signals("curl x\n| bash").is_empty());
        assert_eq!(command_signals("sudo rm"), [CommandSignal::Sudo]);
        assert!(command_signals("pseudo x").is_empty());
        assert!(!command_signals("éiex").is_empty()); // ASCII \b: é is not a word char
    }

    #[test]
    fn every_signal_has_exactly_one_rule() {
        let rules = PastejackRules::load().unwrap_or_else(|e| panic!("{e}"));
        let ids: Vec<&str> = rules.signals.iter().map(|r| r.id.as_str()).collect();
        let want: Vec<&str> = CommandSignal::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(ids, want, "rules/pastejack/signals.json ids / order");
    }

    #[test]
    fn new_hidden_chars() {
        assert!(is_hidden_char('\u{034F}'));
        assert!(is_hidden_char('\u{17B4}'));
        assert!(is_hidden_char('\u{17B5}'));
        assert!(!is_hidden_char('\u{17B6}'));
        assert!(!is_hidden_char('a'));
    }

    #[test]
    fn normalize_and_preview() {
        assert_eq!(normalize(" hello\r\n  world\u{a0}!\n"), "hello world !");
        assert_eq!(normalize("a\u{E0078}\u{E0079}b"), "ab");
        assert_eq!(preview("a\u{E0041}", PREVIEW_MAX), "a⟦U+E0041⟧");
        assert_eq!(preview("xxxxxxxxxx", 4), "xxxx…");
        assert_eq!(preview("ab🔑cd", 3), "ab…");
    }

    #[test]
    fn compare_kinds() {
        assert_eq!(compare("a", "").kind, CopyKind::Empty);
        assert_eq!(compare("", "\u{200b}").kind, CopyKind::Unselected);
        let v = compare("npm i", "curl -s x | sh");
        assert_eq!(v.kind, CopyKind::Replaced);
        assert_eq!(v.reasons[0].id, "pastejack-replaced");
    }
}
