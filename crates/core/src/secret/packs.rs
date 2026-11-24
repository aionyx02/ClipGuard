//! PII rule packs (legacy `SecretPacks`, spec §5.6): the universal pack is always on;
//! country packs are chosen by region / locale and can be added or disabled by hand.
//! Pack names are the rule files' `pack`: `universal` or an ISO 3166 two-letter code
//! in upper case (`TW`).

use std::collections::BTreeSet;

pub use paste_warden_rules::secret::UNIVERSAL;

/// A set of enabled packs. The universal pack is always active regardless of membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSet {
    packs: BTreeSet<String>,
}

impl Default for PackSet {
    /// Legacy `SecretPacks.Default`: universal + TW.
    fn default() -> Self {
        PackSet::from_codes([UNIVERSAL, "TW"])
    }
}

impl PackSet {
    /// Only the universal pack.
    pub fn universal() -> Self {
        PackSet::from_codes([UNIVERSAL])
    }

    /// Builds a set from pack codes, case-insensitively (`tw` = `TW`, `Universal` =
    /// `universal`). Unknown codes are kept but match no rule.
    pub fn from_codes<S: AsRef<str>>(codes: impl IntoIterator<Item = S>) -> Self {
        let mut packs = BTreeSet::new();
        packs.insert(UNIVERSAL.to_owned());
        for c in codes {
            let c = c.as_ref().trim();
            if c.eq_ignore_ascii_case(UNIVERSAL) {
                continue;
            }
            packs.insert(c.to_ascii_uppercase());
        }
        PackSet { packs }
    }

    /// Every pack the built-in rules define (universal plus all countries).
    pub fn all() -> Self {
        PackSet::from_codes(countries())
    }

    /// Is `pack` (as written in a rule file) active?
    pub fn contains(&self, pack: &str) -> bool {
        pack == UNIVERSAL || self.packs.contains(pack)
    }

    pub fn insert(&mut self, pack: &str) {
        if !pack.eq_ignore_ascii_case(UNIVERSAL) {
            self.packs.insert(pack.trim().to_ascii_uppercase());
        }
    }

    pub fn remove(&mut self, pack: &str) {
        self.packs.remove(&pack.trim().to_ascii_uppercase());
    }

    /// Pack codes as stored (`universal`, `TW`, …), sorted.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.packs.iter().map(String::as_str)
    }
}

/// Country packs in the built-in rules (not `universal`), sorted (legacy `SecretPacks.Countries`).
pub fn countries() -> &'static [String] {
    use std::sync::OnceLock;
    static C: OnceLock<Vec<String>> = OnceLock::new();
    C.get_or_init(|| {
        let set: BTreeSet<String> = super::engine::builtin()
            .rules()
            .iter()
            .map(|r| r.def.pack.clone())
            .filter(|p| p != UNIVERSAL)
            .collect();
        set.into_iter().collect()
    })
}

/// Languages that map to a single country when no region is given.
const LANGUAGE_ONLY: &[(&str, &str)] = &[("ja", "JP"), ("ko", "KR")];

fn language_only(lang: &str) -> Option<&'static str> {
    let l = lang.to_lowercase();
    LANGUAGE_ONLY.iter().find(|(k, _)| *k == l).map(|(_, v)| *v)
}

/// Country pack for a region (`TW`) or locale name (`zh-TW`, `zh-Hant-HK`, `zh_CN`,
/// `ja`), or `None` (legacy `SecretPacks.CountryOf`). A lone two-letter code is a region
/// only in upper case; lower case is a language (only `ja` and `ko` map to a country).
pub fn country_of(region_or_locale: &str) -> Option<String> {
    let t = region_or_locale.trim();
    if t.is_empty() {
        return None;
    }
    let parts: Vec<&str> = t.split(['-', '_']).collect();
    let region: Option<String> = if parts.len() == 1 {
        let p = parts[0];
        if p.len() == 2 && p.bytes().all(|b| b.is_ascii_uppercase()) {
            Some(p.to_owned())
        } else {
            language_only(p).map(str::to_owned)
        }
    } else {
        parts[1..]
            .iter()
            .find(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_alphabetic()))
            .map(|p| p.to_ascii_uppercase())
            .or_else(|| language_only(parts[0]).map(str::to_owned))
    };
    region.filter(|r| countries().iter().any(|c| c == r))
}

fn known(pack: &str) -> Option<String> {
    let p = pack.trim().to_uppercase();
    countries().contains(&p).then_some(p)
}

/// Packs to enable (legacy `SecretPacks.ForRegion`): universal, the region's country,
/// plus `extra`, minus `disabled`. Unknown codes are ignored.
pub fn for_region<S: AsRef<str>, T: AsRef<str>>(
    region_or_locale: Option<&str>,
    extra: impl IntoIterator<Item = S>,
    disabled: impl IntoIterator<Item = T>,
) -> PackSet {
    let mut set = PackSet::universal();
    if let Some(c) = region_or_locale.and_then(country_of) {
        set.insert(&c);
    }
    for e in extra {
        if let Some(k) = known(e.as_ref()) {
            set.insert(&k);
        }
    }
    for d in disabled {
        if let Some(k) = known(d.as_ref()) {
            set.remove(&k);
        }
    }
    set
}

/// Extension behavior (legacy `packsForLocales(navigator.languages)`): every preferred
/// locale counts; the union of their country packs plus universal.
pub fn for_locales<S: AsRef<str>>(locales: impl IntoIterator<Item = S>) -> PackSet {
    let mut set = PackSet::universal();
    for l in locales {
        if let Some(c) = country_of(l.as_ref()) {
            set.insert(&c);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_of_forms() {
        assert_eq!(country_of("TW").as_deref(), Some("TW"));
        assert_eq!(country_of("tw"), None);
        assert_eq!(country_of("zh-Hant-HK").as_deref(), Some("HK"));
        assert_eq!(country_of("zh_CN").as_deref(), Some("CN"));
        assert_eq!(country_of("ja").as_deref(), Some("JP"));
        assert_eq!(country_of("en-GB"), None);
        assert_eq!(country_of("  "), None);
    }

    #[test]
    fn region_with_extra_and_disabled() {
        let p = for_region(Some("zh-TW"), [" jp "], ["tw", "xx"]);
        assert_eq!(p.iter().collect::<Vec<_>>(), vec!["JP", "universal"]);
    }
}
