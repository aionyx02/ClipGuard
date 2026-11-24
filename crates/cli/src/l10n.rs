//! Locale helpers for the command line.

use paste_warden_core::{Arg, Message};
use paste_warden_i18n::Localizer;
use paste_warden_i18n::locale::map_locale;

/// The locale from the environment (`LC_ALL` > `LC_MESSAGES` > `LANG`);
/// `zh-TW` for Traditional Chinese, `en` otherwise. The caller passes the
/// values in so this stays testable.
pub fn env_locale(
    lc_all: Option<&str>,
    lc_messages: Option<&str>,
    lang: Option<&str>,
) -> &'static str {
    let value = [lc_all, lc_messages, lang]
        .into_iter()
        .flatten()
        .find(|v| !v.trim().is_empty())
        .unwrap_or("en");
    // `zh_TW.UTF-8` → `zh_TW`
    let name = value.split(['.', '@']).next().unwrap_or(value);
    map_locale(name)
}

/// [`env_locale`] with the process environment.
pub fn process_locale() -> &'static str {
    let get = |k: &str| std::env::var(k).ok();
    env_locale(
        get("LC_ALL").as_deref(),
        get("LC_MESSAGES").as_deref(),
        get("LANG").as_deref(),
    )
}

/// Normalizes a user-supplied locale (`zh-TW`, `zh_tw`, `en`, …).
pub fn parse_locale(s: &str) -> &'static str {
    map_locale(s)
}

/// Shorthand for a `cli-*` message with string arguments.
pub fn msg(id: &'static str, args: &[(&'static str, Arg)]) -> Message {
    let mut m = Message::new(id);
    for (k, v) in args {
        m = m.arg(k, v.clone());
    }
    m
}

/// Renders `id` with `args`.
pub fn t(l10n: &Localizer, id: &'static str, args: &[(&'static str, Arg)]) -> String {
    l10n.format(&msg(id, args))
}

/// Both shipped locales, zh-TW first (hook reasons are bilingual: the model
/// reads either, and the user sees their own language).
pub struct Bilingual {
    pub zh: Localizer,
    pub en: Localizer,
}

impl Default for Bilingual {
    fn default() -> Self {
        Bilingual {
            zh: Localizer::new("zh-TW"),
            en: Localizer::new("en"),
        }
    }
}

impl Bilingual {
    /// `zh-TW text \n en text`, each built by `f`.
    pub fn render(&self, f: impl Fn(&Localizer) -> String) -> String {
        format!("{}\n{}", f(&self.zh), f(&self.en))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_locale_follows_posix_precedence() {
        assert_eq!(env_locale(None, None, Some("zh_TW.UTF-8")), "zh-TW");
        assert_eq!(
            env_locale(Some("en_US.UTF-8"), None, Some("zh_TW.UTF-8")),
            "en"
        );
        assert_eq!(env_locale(Some(""), None, Some("zh_HK")), "zh-TW");
        assert_eq!(env_locale(None, None, None), "en");
        assert_eq!(env_locale(None, None, Some("C")), "en");
    }
}
