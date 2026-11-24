//! UI locale selection (legacy `UiCulture`) as pure functions: the caller reads the
//! command line, environment and system locale and passes them in as strings.
//!
//! - [`map_locale`]: system locale → shipped locale. Traditional Chinese (`zh-TW`,
//!   `zh-HK`, `zh-MO`, `zh-Hant[-*]`, legacy `zh-CHT`) → `zh-TW`; everything else,
//!   including Simplified Chinese and bare `zh`, → `en` (no Simplified translation;
//!   the browser extension does the same).
//! - [`resolve_locale`]: command line (`--lang=<v>` / `--lang <v>`) > environment
//!   value > system locale; unknown values are ignored.

/// ISO 639-1 language codes (plus a few common ISO 639-2/3 codes) accepted as the
/// primary subtag of a forced locale. Stands in for .NET's predefined cultures so a
/// typo such as `zz-QQ` is ignored instead of becoming a fake locale.
const LANGUAGES: &[&str] = &[
    "aa", "ab", "ae", "af", "ak", "am", "an", "ar", "as", "av", "ay", "az", "ba", "be", "bg", "bi",
    "bm", "bn", "bo", "br", "bs", "ca", "ce", "ch", "co", "cr", "cs", "cu", "cv", "cy", "da", "de",
    "dv", "dz", "ee", "el", "en", "eo", "es", "et", "eu", "fa", "ff", "fi", "fj", "fo", "fr", "fy",
    "ga", "gd", "gl", "gn", "gu", "gv", "ha", "he", "hi", "ho", "hr", "ht", "hu", "hy", "hz", "ia",
    "id", "ie", "ig", "ii", "ik", "io", "is", "it", "iu", "ja", "jv", "ka", "kg", "ki", "kj", "kk",
    "kl", "km", "kn", "ko", "kr", "ks", "ku", "kv", "kw", "ky", "la", "lb", "lg", "li", "ln", "lo",
    "lt", "lu", "lv", "mg", "mh", "mi", "mk", "ml", "mn", "mr", "ms", "mt", "my", "na", "nb", "nd",
    "ne", "ng", "nl", "nn", "no", "nr", "nv", "ny", "oc", "oj", "om", "or", "os", "pa", "pi", "pl",
    "ps", "pt", "qu", "rm", "rn", "ro", "ru", "rw", "sa", "sc", "sd", "se", "sg", "si", "sk", "sl",
    "sm", "sn", "so", "sq", "sr", "ss", "st", "su", "sv", "sw", "ta", "te", "tg", "th", "ti", "tk",
    "tl", "tn", "to", "tr", "ts", "tt", "tw", "ty", "ug", "uk", "ur", "uz", "ve", "vi", "vo", "wa",
    "wo", "xh", "yi", "yo", "za", "zh", "zu", // ISO 639-2/3 codes with predefined cultures:
    "fil", "haw", "chr", "yue", "gsw", "kok", "sah", "moh", "quz", "smn", "sms", "sma", "smj",
];

/// Legacy .NET culture names that are not BCP 47 well-formed.
const LEGACY_NAMES: &[&str] = &["zh-CHT", "zh-CHS"];

/// Traditional Chinese regions (their .NET parent culture is `zh-Hant`).
const HANT_REGIONS: &[&str] = &["TW", "HK", "MO"];

fn is_alpha(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_private_region(r: &str) -> bool {
    let r = r.to_ascii_uppercase();
    let b = r.as_bytes();
    matches!(b, [b'A', b'A'] | [b'Z', b'Z'])
        || matches!(b, [b'Q', b'M'..=b'Z'])
        || matches!(b, [b'X', b'A'..=b'Z'])
}

/// Is `name` (already trimmed, `-`-separated) a known locale name?
/// Language (known) [-Script (4 letters)] [-Region (2 letters, not private use, or
/// 3 digits)] [-variants (5–8 alphanumerics)].
pub fn is_known_locale(name: &str) -> bool {
    if LEGACY_NAMES.iter().any(|l| l.eq_ignore_ascii_case(name)) {
        return true;
    }
    let mut parts = name.split('-');
    let Some(lang) = parts.next() else {
        return false;
    };
    let lang = lang.to_ascii_lowercase();
    if !LANGUAGES.contains(&lang.as_str()) {
        return false;
    }
    let mut stage = 0; // 0: script allowed, 1: region allowed, 2: variants only
    for p in parts {
        let script = stage == 0 && p.len() == 4 && is_alpha(p);
        let region = stage <= 1
            && ((p.len() == 2 && is_alpha(p) && !is_private_region(p))
                || (p.len() == 3 && p.bytes().all(|b| b.is_ascii_digit())));
        let variant = (5..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric());
        if script {
            stage = 1;
        } else if region || variant {
            stage = 2;
        } else {
            return false;
        }
    }
    true
}

/// Maps a system locale name (BCP 47, `_` or `-`; `""` = none) to a shipped
/// locale: `"zh-TW"` or `"en"` (legacy `UiCulture.Map`).
pub fn map_locale(system: &str) -> &'static str {
    let name = system.trim().replace('_', "-");
    if name.eq_ignore_ascii_case("zh-CHT") {
        return "zh-TW";
    }
    let mut parts = name.split('-');
    if !parts.next().is_some_and(|l| l.eq_ignore_ascii_case("zh")) {
        return "en";
    }
    for p in parts {
        if p.len() == 4 && is_alpha(p) {
            // An explicit script decides: zh-Hant-* is Traditional, zh-Hans-* is not.
            return if p.eq_ignore_ascii_case("Hant") {
                "zh-TW"
            } else {
                "en"
            };
        }
        if p.len() == 2 && is_alpha(p) {
            return if HANT_REGIONS.iter().any(|r| r.eq_ignore_ascii_case(p)) {
                "zh-TW"
            } else {
                "en"
            };
        }
    }
    "en"
}

/// The value of the first `--lang=<v>` / `--lang <v>` argument (name compared
/// case-insensitively). A trailing `--lang` has no value.
fn lang_from_args<S: AsRef<str>>(argv: &[S]) -> Option<&str> {
    const FLAG: &str = "--lang";
    for (i, a) in argv.iter().enumerate() {
        let a = a.as_ref();
        if let Some(head) = a.get(..FLAG.len() + 1)
            && head.eq_ignore_ascii_case("--lang=")
        {
            return a.get(FLAG.len() + 1..);
        }
        if a.eq_ignore_ascii_case(FLAG) {
            return argv.get(i + 1).map(AsRef::as_ref);
        }
    }
    None
}

/// Trims, turns `_` into `-`, and keeps the value only if it is a known locale.
fn parse_forced(value: Option<&str>) -> Option<String> {
    let v = value?.trim().replace('_', "-");
    (!v.is_empty() && is_known_locale(&v)).then_some(v)
}

/// Chooses the UI locale (legacy `UiCulture.Resolve`): command line > environment
/// value > system locale, each ignored when empty or unknown, then [`map_locale`].
pub fn resolve_locale<S: AsRef<str>>(argv: &[S], env: Option<&str>, system: &str) -> &'static str {
    match parse_forced(lang_from_args(argv)).or_else(|| parse_forced(env)) {
        Some(forced) => map_locale(&forced),
        None => map_locale(system),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps() {
        for (s, l) in [
            ("zh-TW", "zh-TW"),
            ("zh-HK", "zh-TW"),
            ("zh-MO", "zh-TW"),
            ("zh-Hant", "zh-TW"),
            ("zh-Hant-SG", "zh-TW"),
            ("zh_tw", "zh-TW"),
            ("zh-CHT", "zh-TW"),
            ("zh-CN", "en"),
            ("zh-Hans-HK", "en"),
            ("zh", "en"),
            ("en-US", "en"),
            ("", "en"),
        ] {
            assert_eq!(map_locale(s), l, "{s}");
        }
    }

    #[test]
    fn known_locales() {
        assert!(is_known_locale("en-GB"));
        assert!(is_known_locale("zh-Hant-TW"));
        assert!(is_known_locale("es-419"));
        assert!(!is_known_locale("zz-QQ"));
        assert!(!is_known_locale("en-QQ"));
        assert!(!is_known_locale("not a culture"));
        assert!(!is_known_locale(""));
    }

    #[test]
    fn resolves() {
        assert_eq!(resolve_locale(&["--lang=en"], Some("zh-TW"), "zh-TW"), "en");
        assert_eq!(resolve_locale(&["--LANG", "en-GB"], None, "zh-TW"), "en");
        assert_eq!(resolve_locale::<&str>(&[], Some("zh_tw"), "en-US"), "zh-TW");
        assert_eq!(
            resolve_locale(&["--lang=zz-QQ"], Some("not a culture"), "zh-TW"),
            "zh-TW"
        );
        assert_eq!(resolve_locale(&["--lang"], Some(" "), "zh-TW"), "zh-TW");
        assert_eq!(resolve_locale(&["--lang=é"], None, "en"), "en");
    }
}
