//! The Phase 1 acceptance test: every corpus case passes (or is a documented
//! divergence). Narrow the run while developing with `PW_CORPUS_AREA`,
//! `PW_CORPUS_OP`, `PW_CORPUS_ID`, or use `cargo run -p xtask -- corpus run`.

use paste_warden_conformance::{Filter, Outcome, run_cases};

#[test]
fn corpus_cases_pass() {
    let filter = Filter::from_env();
    let summary = run_cases(&filter).expect("corpus loads");
    let failures: Vec<_> = summary.failures().collect();
    for r in failures.iter().take(50) {
        eprintln!(
            "{}:{} {} [{}]: {:?}",
            r.file.display(),
            r.line,
            r.id,
            r.op,
            r.outcome
        );
    }
    assert!(
        summary.bad_divergences.is_empty(),
        "bad divergences: {:?}",
        summary.bad_divergences
    );
    assert!(
        summary.stale_divergences.is_empty(),
        "divergences that now pass (remove them): {:?}",
        summary.stale_divergences
    );
    let unimplemented = failures
        .iter()
        .filter(|r| r.outcome == Outcome::Unimplemented)
        .count();
    assert!(
        failures.is_empty(),
        "{} of {} corpus cases fail ({unimplemented} unimplemented)",
        failures.len(),
        summary.results.len()
    );
}
