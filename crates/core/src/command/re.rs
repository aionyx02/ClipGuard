//! Lazily compiled regexes that never panic.
//!
//! Patterns are built from engine code plus rule data (`rules/command/`). A pattern
//! that fails to compile (a broken rule file) degrades to "never matches" instead
//! of panicking; `tests::all_patterns_compile` in each module guarantees that the
//! shipped patterns compile.

use regex::Regex;

/// A compiled regex, or nothing if the pattern did not compile.
pub(crate) struct Re(Option<Regex>);

impl Re {
    pub(crate) fn new(pattern: &str) -> Re {
        Re(regex::RegexBuilder::new(pattern)
            .size_limit(32 << 20)
            .dfa_size_limit(16 << 20)
            .build()
            .ok())
    }

    pub(crate) fn is_match(&self, text: &str) -> bool {
        self.0.as_ref().is_some_and(|r| r.is_match(text))
    }

    pub(crate) fn get(&self) -> Option<&Regex> {
        self.0.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn compiled(&self) -> bool {
        self.0.is_some()
    }
}

/// A signal: a lazily compiled pattern and the message id it produces.
pub(crate) type Signal = (fn() -> &'static Re, &'static str);

/// Defines a function returning a `&'static Re` compiled on first use.
macro_rules! lazy_re {
    ($(#[$meta:meta])* $vis:vis fn $name:ident = $pattern:expr;) => {
        $(#[$meta])*
        $vis fn $name() -> &'static $crate::command::re::Re {
            static RE: std::sync::OnceLock<$crate::command::re::Re> = std::sync::OnceLock::new();
            RE.get_or_init(|| $crate::command::re::Re::new(&$pattern))
        }
    };
}
pub(crate) use lazy_re;

/// `a|b|c` from a list of plain words (regex-escaped).
pub(crate) fn alternation<S: AsRef<str>>(words: &[S]) -> String {
    words
        .iter()
        .map(|w| regex::escape(w.as_ref()))
        .collect::<Vec<_>>()
        .join("|")
}
