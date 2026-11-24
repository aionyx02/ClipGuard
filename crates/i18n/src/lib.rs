//! Renders [`paste_warden_core::Message`]s with Fluent.
//!
//! All `locales/<lang>/*.ftl` files are embedded at build time. Unicode bidi
//! isolation marks are disabled so rendered text is plain (and matches the
//! legacy strings in the corpus byte for byte).
#![forbid(unsafe_code)]

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource, FluentValue};
use paste_warden_core::{Arg, Message};
use unic_langid::LanguageIdentifier;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/locales.rs"));
}

/// Locales shipped with PasteWarden, in fallback order.
pub const LOCALES: &[&str] = &["en", "zh-TW"];
/// Locale used when nothing matches.
pub const FALLBACK: &str = "en";

/// A loaded locale.
pub struct Localizer {
    locale: &'static str,
    bundle: FluentBundle<FluentResource>,
}

/// Problems found while loading `.ftl` files (syntax errors, duplicate ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    pub locale: String,
    pub file: String,
    pub detail: String,
}

impl Localizer {
    /// Loads `locale` (`"zh-TW"`, `"en"`); anything else falls back to English.
    pub fn new(locale: &str) -> Localizer {
        Self::try_new(locale).0
    }

    /// Like [`Localizer::new`] but also returns load problems (for tests).
    pub fn try_new(locale: &str) -> (Localizer, Vec<LoadError>) {
        let locale = LOCALES
            .iter()
            .copied()
            .find(|l| l.eq_ignore_ascii_case(locale))
            .unwrap_or(FALLBACK);
        let langid: LanguageIdentifier = locale.parse().expect("valid built-in locale");
        let mut bundle = FluentBundle::new_concurrent(vec![langid]);
        bundle.set_use_isolating(false);
        let mut errors = Vec::new();
        for (lang, file, text) in embedded::FILES {
            if *lang != locale {
                continue;
            }
            let res = match FluentResource::try_new((*text).to_owned()) {
                Ok(r) => r,
                Err((r, errs)) => {
                    errors.extend(errs.iter().map(|e| LoadError {
                        locale: locale.into(),
                        file: (*file).into(),
                        detail: format!("{e:?}"),
                    }));
                    r
                }
            };
            if let Err(errs) = bundle.add_resource(res) {
                errors.extend(errs.iter().map(|e| LoadError {
                    locale: locale.into(),
                    file: (*file).into(),
                    detail: format!("{e:?}"),
                }));
            }
        }
        (Localizer { locale, bundle }, errors)
    }

    pub fn locale(&self) -> &'static str {
        self.locale
    }

    /// Does this locale define `id`?
    pub fn has(&self, id: &str) -> bool {
        self.bundle
            .get_message(id)
            .and_then(|m| m.value())
            .is_some()
    }

    /// Renders a message. A missing id renders as the id itself so it is visible
    /// in tests instead of silently empty.
    pub fn format(&self, msg: &Message) -> String {
        let Some(pattern) = self.bundle.get_message(&msg.id).and_then(|m| m.value()) else {
            return msg.id.to_string();
        };
        let mut args = FluentArgs::new();
        for (name, value) in &msg.args {
            match value {
                Arg::Str(s) => args.set(name.as_ref(), FluentValue::from(s.as_str())),
                Arg::Num(n) => args.set(name.as_ref(), FluentValue::from(*n)),
            }
        }
        let mut errors = Vec::new();
        self.bundle
            .format_pattern(pattern, Some(&args), &mut errors)
            .into_owned()
    }

    /// All message ids defined in this locale (for completeness checks).
    pub fn ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for (lang, _file, text) in embedded::FILES {
            if *lang != self.locale {
                continue;
            }
            for line in text.lines() {
                // A message starts at column 0 with `identifier =` (terms start with `-`).
                let Some((id, _)) = line.split_once('=') else {
                    continue;
                };
                let id = id.trim_end();
                if !line.starts_with(|c: char| c.is_ascii_alphabetic())
                    || !id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    continue;
                }
                ids.push(id.to_owned());
            }
        }
        ids.sort();
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_locale_loads_without_errors() {
        for l in LOCALES {
            let (_, errors) = Localizer::try_new(l);
            assert!(errors.is_empty(), "{l}: {errors:?}");
        }
    }

    #[test]
    fn locales_define_the_same_ids() {
        let en = Localizer::new("en").ids();
        let zh = Localizer::new("zh-TW").ids();
        let only_en: Vec<_> = en.iter().filter(|i| !zh.contains(i)).collect();
        let only_zh: Vec<_> = zh.iter().filter(|i| !en.contains(i)).collect();
        assert!(
            only_en.is_empty() && only_zh.is_empty(),
            "only en: {only_en:?}; only zh-TW: {only_zh:?}"
        );
    }

    #[test]
    fn unknown_locale_falls_back_to_english() {
        assert_eq!(Localizer::new("fr").locale(), "en");
        assert_eq!(Localizer::new("zh-tw").locale(), "zh-TW");
    }

    #[test]
    fn missing_id_renders_as_id() {
        let l = Localizer::new("en");
        assert_eq!(l.format(&Message::new("no-such-id")), "no-such-id");
    }
}
