//! Localizable messages. The engine returns ids + arguments; `paste-warden-i18n`
//! renders them with the Fluent files in `locales/<lang>/*.ftl`.

use std::borrow::Cow;

/// A message argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Str(String),
    Num(i64),
}

impl From<&str> for Arg {
    fn from(s: &str) -> Self {
        Arg::Str(s.to_owned())
    }
}
impl From<String> for Arg {
    fn from(s: String) -> Self {
        Arg::Str(s)
    }
}
impl From<i64> for Arg {
    fn from(n: i64) -> Self {
        Arg::Num(n)
    }
}
impl From<usize> for Arg {
    fn from(n: usize) -> Self {
        Arg::Num(i64::try_from(n).unwrap_or(i64::MAX))
    }
}

/// A localizable message: a Fluent message id (kebab-case, prefixed by area:
/// `cmd-`, `secret-`, `hidden-`, `wallet-`, `entry-`, `paste-`, `pastejack-`,
/// `registered-`, `ui-`) plus named arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: Cow<'static, str>,
    pub args: Vec<(Cow<'static, str>, Arg)>,
}

impl Message {
    pub fn new(id: &'static str) -> Self {
        Message {
            id: Cow::Borrowed(id),
            args: Vec::new(),
        }
    }

    /// Adds a named argument (builder style).
    pub fn arg(mut self, name: &'static str, value: impl Into<Arg>) -> Self {
        self.args.push((Cow::Borrowed(name), value.into()));
        self
    }
}
