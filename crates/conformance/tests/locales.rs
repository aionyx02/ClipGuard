//! Every message id the engine can emit is translated in every shipped locale
//! (phase-1.md §1.7). Ids are found by scanning the core sources for string
//! literals with an area prefix, so a new `Message::new("cmd-…")` without a
//! Fluent entry fails here.

use std::collections::BTreeSet;
use std::path::Path;

use paste_warden_conformance::repo_root;
use paste_warden_i18n::{LOCALES, Localizer};

const PREFIXES: &[&str] = &[
    "cmd-",
    "secret-",
    "hidden-",
    "wallet-",
    "entry-",
    "paste-",
    "pastejack-",
    "registered-",
    "guard-",
    "throttle-",
    "ui-",
];

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).expect("readable dir").flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// String literals in core that look like message ids.
fn engine_ids() -> BTreeSet<String> {
    let mut files = Vec::new();
    rust_files(&repo_root().join("crates/core/src"), &mut files);
    let mut ids = BTreeSet::new();
    for f in files {
        let text = std::fs::read_to_string(&f).expect("readable source");
        for literal in text.split('"').skip(1).step_by(2) {
            let is_id = PREFIXES.iter().any(|p| literal.starts_with(p))
                && literal.len() > 4
                && literal
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !literal.ends_with('-');
            if is_id {
                ids.insert(literal.to_owned());
            }
        }
    }
    ids
}

#[test]
fn every_engine_message_is_translated() {
    let ids = engine_ids();
    assert!(ids.len() > 50, "scanner found only {} ids", ids.len());
    for locale in LOCALES {
        let loc = Localizer::new(locale);
        let missing: Vec<_> = ids.iter().filter(|id| !loc.has(id)).collect();
        assert!(missing.is_empty(), "{locale}: missing {missing:?}");
    }
}
