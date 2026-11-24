//! Rule-file helpers a regex cannot express (legacy `PiiFormats`): `validate`
//! functions, `mask.canonical` forms and the `card-groups` finder.

use paste_warden_rules::secret::{CanonicalKind, ValidatorKind};

use super::checksum;

/// Taiwan IDs may contain at most this many separators (`A 123 456 789`); `\r\n` counts once.
pub const MAX_ID_SEPARATORS: usize = 3;

/// Longest card number in digits (ISO/IEC 7812).
pub const MAX_CARD_DIGITS: usize = 19;
/// Shortest card number in digits.
pub const MIN_CARD_DIGITS: usize = 13;

/// ASCII digits of `s`.
pub fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// ASCII letters and digits of `s`, upper-cased.
pub fn alnum_upper(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Runs a `validate` function on a candidate (separators included).
pub fn validate(kind: ValidatorKind, s: &str) -> bool {
    match kind {
        ValidatorKind::JwtHeader => is_jwt(s),
        ValidatorKind::TwId => is_taiwan_id(s),
        ValidatorKind::TwUbn => checksum::is_valid_business_id(s),
        ValidatorKind::Iban => checksum::is_valid_iban(&alnum_upper(s)),
        ValidatorKind::E164 => checksum::is_plausible_e164(&digits(s)),
        ValidatorKind::CnId => checksum::is_valid_china_resident_id(&alnum_upper(s)),
        ValidatorKind::JpMyNumber => checksum::is_valid_my_number(&digits(s)),
        ValidatorKind::HkId => checksum::is_valid_hong_kong_id(&alnum_upper(s)),
        ValidatorKind::SgNric => checksum::is_valid_singapore_nric(&alnum_upper(s)),
        ValidatorKind::UsSsn => is_us_ssn(s),
    }
}

fn is_taiwan_id(s: &str) -> bool {
    let id = alnum_upper(s);
    let len = s.chars().count();
    let cr = s.chars().filter(|&c| c == '\r').count();
    let separators = len.saturating_sub(id.chars().count()).saturating_sub(cr);
    separators <= MAX_ID_SEPARATORS && checksum::is_valid_taiwan_id(&id)
}

/// Both SSN separators must be the same (`123-45-6789`, `123 45 6789`) or absent.
fn is_us_ssn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() == 11 && chars[3] != chars[6] {
        return false;
    }
    (chars.len() == 9 || chars.len() == 11) && checksum::is_plausible_us_ssn(&d)
}

/// JWT: the header (before the first `.`) must decode (base64url, padding optional)
/// to a JSON object with a string `alg`.
pub fn is_jwt(token: &str) -> bool {
    use base64::Engine as _;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let segment = token.split('.').next().unwrap_or_default();
    if segment.len() % 4 == 1 {
        return false;
    }
    let Ok(bytes) = ENGINE.decode(segment) else {
        return false;
    };
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(serde_json::Value::Object(o)) => o.get("alg").is_some_and(serde_json::Value::is_string),
        _ => false,
    }
}

/// Applies a `mask.canonical` form.
pub fn canonical(kind: CanonicalKind, s: &str) -> String {
    match kind {
        CanonicalKind::AlnumUpper => alnum_upper(s),
        CanonicalKind::Digits => digits(s),
        CanonicalKind::TwMobile => {
            // +886 912…, 886 0912… are shown like the domestic 0912….
            let d = digits(s);
            match d.strip_prefix("886") {
                Some(rest) => format!("0{}", rest.strip_prefix('0').unwrap_or(rest)),
                None => d,
            }
        }
        CanonicalKind::E164 => format!("+{}", digits(s)),
    }
}

#[derive(Debug, Clone, Copy)]
struct Group {
    start: usize,
    end: usize,
    sep_before: u8,
}

impl Group {
    fn len(&self) -> usize {
        self.end - self.start
    }
}

/// If a separator followed by a digit is at `pos`, returns (digit position, separator
/// kind); `\r\n` and `\n` both count as `\n`.
fn separator_at(t: &[u8], pos: usize) -> Option<(usize, u8)> {
    let c = *t.get(pos)?;
    let (next, kind) = match c {
        b' ' | b'.' | b'-' | b'\n' => (pos + 1, c),
        b'\r' if t.get(pos + 1) == Some(&b'\n') => (pos + 2, b'\n'),
        _ => return None,
    };
    t.get(next)
        .is_some_and(u8::is_ascii_digit)
        .then_some((next, kind))
}

fn is_card_grouping(groups: &[Group], first: usize, last: usize) -> bool {
    if first == last {
        return true;
    }
    let mut sep = 0u8;
    for g in &groups[first + 1..=last] {
        if g.sep_before == b'\n' {
            continue;
        }
        if sep == 0 {
            sep = g.sep_before;
        } else if sep != g.sep_before {
            return false;
        }
    }
    let count = last - first + 1;
    if count == 3
        && groups[first].len() == 4
        && groups[first + 1].len() == 6
        && matches!(groups[last].len(), 4 | 5)
    {
        return true; // Diners, Amex
    }
    groups[first..last].iter().all(|g| g.len() == 4) && (1..=4).contains(&groups[last].len())
}

/// Major card networks' IIN prefixes and lengths.
fn is_card_prefix(d: &[u8]) -> bool {
    let p = |n: usize| {
        d[..n]
            .iter()
            .fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'))
    };
    let len = d.len();
    match d[0] {
        b'4' => matches!(len, 13 | 16 | 19),
        b'5' => (51..=55).contains(&p(2)) && len == 16,
        b'2' => (2221..=2720).contains(&p(4)) && len == 16,
        b'3' => {
            (matches!(p(2), 34 | 37) && len == 15)
                || ((3528..=3589).contains(&p(4)) && (16..=19).contains(&len))
                || ((matches!(p(2), 36 | 38) || (300..=305).contains(&p(3)))
                    && (14..=19).contains(&len))
        }
        b'6' => {
            (d.starts_with(b"6011")
                || d.starts_with(b"65")
                || (644..=649).contains(&p(3))
                || d.starts_with(b"62"))
                && (16..=19).contains(&len)
        }
        _ => false,
    }
}

/// Card number candidates in the ASCII view (legacy `PiiFormats.CardCandidates`):
/// runs of digit groups joined by single separators; within a run, the first
/// consecutive groups totalling 13–19 digits with a card-like grouping (4-4-4-4 with a
/// last group of 1–4, Amex 4-6-5, Diners 4-6-4, consistent separator, a line break may
/// replace any), a known IIN prefix and a valid Luhn check. Returns `(index, len)`.
pub fn card_candidates(t: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut groups: Vec<Group> = Vec::new();
    let mut digits_buf: Vec<u8> = Vec::with_capacity(MAX_CARD_DIGITS);
    let mut i = 0;
    while i < t.len() {
        if !t[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        groups.clear();
        let mut sep = 0u8;
        loop {
            let start = i;
            while i < t.len() && t[i].is_ascii_digit() {
                i += 1;
            }
            groups.push(Group {
                start,
                end: i,
                sep_before: sep,
            });
            match separator_at(t, i) {
                Some((next, kind)) => {
                    sep = kind;
                    i = next;
                }
                None => break,
            }
        }

        let mut g = 0;
        while g < groups.len() {
            let mut total = 0;
            for h in g..groups.len() {
                total += groups[h].len();
                if total > MAX_CARD_DIGITS {
                    break;
                }
                // With several groups, all but the last must have 4 digits (the second
                // may have 6 for Amex / Diners); otherwise stop early (keeps `1 1 1 …` linear).
                if h > g {
                    let prev = groups[h - 1].len();
                    if prev != 4 && !(h - 1 == g + 1 && prev == 6) {
                        break;
                    }
                }
                if total < MIN_CARD_DIGITS || !is_card_grouping(&groups, g, h) {
                    continue;
                }
                digits_buf.clear();
                for k in &groups[g..=h] {
                    digits_buf.extend_from_slice(&t[k.start..k.end]);
                }
                let Ok(d) = std::str::from_utf8(&digits_buf) else {
                    continue;
                };
                if !is_card_prefix(&digits_buf) || !checksum::is_valid_luhn(d) {
                    continue;
                }
                out.push((groups[g].start, groups[h].end - groups[g].start));
                g = h; // the next candidate starts after this card
                break;
            }
            g += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards() {
        assert_eq!(card_candidates(b"x 4111 1111 1111 1111 y"), vec![(2, 19)]);
        assert_eq!(card_candidates(b"4111111111111111"), vec![(0, 16)]);
        assert!(card_candidates(b"2024-01-15 2024-02-16").is_empty());
        assert!(card_candidates(b"4111 1111-1111 1111").is_empty());
        assert_eq!(card_candidates(b"4111 1111\n1111 1111"), vec![(0, 19)]);
    }

    #[test]
    fn jwt_header() {
        // {"alg":"HS256"}
        assert!(is_jwt("eyJhbGciOiJIUzI1NiJ9.e30.x"));
        assert!(!is_jwt("eyJmb28iOjF9.e30.x"));
        assert!(!is_jwt("eyJ.x"));
    }

    #[test]
    fn tw_mobile_canonical() {
        assert_eq!(
            canonical(CanonicalKind::TwMobile, "+886 912 345 678"),
            "0912345678"
        );
        assert_eq!(
            canonical(CanonicalKind::TwMobile, "886 0912 345 678"),
            "0912345678"
        );
        assert_eq!(
            canonical(CanonicalKind::TwMobile, "0912-345-678"),
            "0912345678"
        );
    }
}
