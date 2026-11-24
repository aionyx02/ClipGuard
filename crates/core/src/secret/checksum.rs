//! Check-digit and plausibility checks for single numbers (legacy `Checksums`).
//!
//! Inputs are assumed to be already stripped of spaces and dashes. Every function
//! is total: any string (including non-ASCII) simply returns `false`.

/// Taiwan ID letter order: the two-digit code is `10 + index`. Note I, O, W–Z are
/// not in alphabetical order.
const ID_LETTERS: &[u8; 26] = b"ABCDEFGHJKLMNPQRSTUVXYWZIO";

fn letter_code(c: u8) -> Option<u32> {
    let up = c.to_ascii_uppercase();
    ID_LETTERS
        .iter()
        .position(|&l| l == up)
        .map(|i| 10 + i as u32)
}

fn digit(c: u8) -> Option<u32> {
    c.is_ascii_digit().then(|| u32::from(c - b'0'))
}

fn all_digits(s: &[u8]) -> bool {
    s.iter().all(u8::is_ascii_digit)
}

/// Taiwan national ID, new-style resident certificate (2nd char 8/9, since 2021) and
/// old-style resident certificate (2nd char A–D). The first letter is case-insensitive.
pub fn is_valid_taiwan_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 10 || !id.is_ascii() {
        return false;
    }
    let Some(first) = letter_code(b[0]) else {
        return false;
    };
    let c1 = b[1].to_ascii_uppercase();
    let second = match c1 {
        b'1' | b'2' | b'8' | b'9' => u32::from(c1 - b'0'),
        b'A'..=b'D' => match letter_code(c1) {
            Some(code) => code % 10,
            None => return false,
        },
        _ => return false,
    };
    let mut sum = first / 10 + first % 10 * 9 + second * 8;
    for (i, &c) in b.iter().enumerate().skip(2) {
        let Some(d) = digit(c) else {
            return false;
        };
        let weight = if i == 9 { 1 } else { 9 - i as u32 };
        sum += d * weight;
    }
    sum % 10 == 0
}

/// Taiwan business ID (UBN): weights 1,2,1,2,1,2,4,1 with digit sums; since 2023 the
/// sum must be divisible by 5 (was 10). When the 7th digit is 7, `sum + 1` also counts.
pub fn is_valid_business_id(ban: &str) -> bool {
    let b = ban.as_bytes();
    if b.len() != 8 || !all_digits(b) {
        return false;
    }
    const W: [u32; 8] = [1, 2, 1, 2, 1, 2, 4, 1];
    let sum: u32 = b
        .iter()
        .zip(W)
        .map(|(&c, w)| {
            let p = u32::from(c - b'0') * w;
            p / 10 + p % 10
        })
        .sum();
    sum.is_multiple_of(5) || (b[6] == b'7' && (sum + 1).is_multiple_of(5))
}

/// Luhn (mod 10) for card numbers; fewer than 2 digits is never valid.
pub fn is_valid_luhn(digits: &str) -> bool {
    let b = digits.as_bytes();
    if b.len() < 2 || !all_digits(b) {
        return false;
    }
    let mut sum = 0u32;
    for (i, &c) in b.iter().rev().enumerate() {
        let mut d = u32::from(c - b'0');
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum.is_multiple_of(10)
}

/// IBAN length per country (SWIFT IBAN Registry); unknown countries never validate.
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AL", 28),
    ("AT", 20),
    ("AZ", 28),
    ("BA", 20),
    ("BE", 16),
    ("BG", 22),
    ("BH", 22),
    ("BI", 27),
    ("BR", 29),
    ("BY", 28),
    ("CH", 21),
    ("CR", 22),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DJ", 27),
    ("DK", 18),
    ("DO", 28),
    ("EE", 20),
    ("EG", 29),
    ("ES", 24),
    ("FI", 18),
    ("FK", 18),
    ("FO", 18),
    ("FR", 27),
    ("GB", 22),
    ("GE", 22),
    ("GI", 23),
    ("GL", 18),
    ("GR", 27),
    ("GT", 28),
    ("HN", 28),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IL", 23),
    ("IQ", 23),
    ("IS", 26),
    ("IT", 27),
    ("JO", 30),
    ("KW", 30),
    ("KZ", 20),
    ("LB", 28),
    ("LC", 32),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("LY", 25),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("MK", 19),
    ("MN", 20),
    ("MR", 27),
    ("MT", 31),
    ("MU", 30),
    ("NI", 28),
    ("NL", 18),
    ("NO", 15),
    ("OM", 23),
    ("PK", 24),
    ("PL", 28),
    ("PS", 29),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("RS", 22),
    ("RU", 33),
    ("SA", 24),
    ("SC", 31),
    ("SD", 18),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("SM", 27),
    ("SO", 23),
    ("ST", 25),
    ("SV", 28),
    ("TL", 23),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("VA", 22),
    ("VG", 24),
    ("XK", 20),
    ("YE", 30),
];

/// IBAN (ISO 13616): known country, exact length, check digits 02–98, mod 97 = 1.
/// Upper case only, no spaces.
pub fn is_valid_iban(iban: &str) -> bool {
    let b = iban.as_bytes();
    if b.len() < 4 || !iban.is_ascii() {
        return false;
    }
    let Some(&(_, len)) = IBAN_LENGTHS.iter().find(|(c, _)| c.as_bytes() == &b[..2]) else {
        return false;
    };
    if b.len() != len {
        return false;
    }
    let (Some(c2), Some(c3)) = (digit(b[2]), digit(b[3])) else {
        return false;
    };
    if !(2..=98).contains(&(c2 * 10 + c3)) {
        return false;
    }
    let mut m = 0u32;
    for k in 0..b.len() {
        let c = b[(k + 4) % b.len()];
        if c.is_ascii_digit() {
            m = (m * 10 + u32::from(c - b'0')) % 97;
        } else if c.is_ascii_uppercase() {
            m = (m * 100 + u32::from(c - b'A') + 10) % 97;
        } else {
            return false;
        }
    }
    m == 1
}

/// China resident ID (GB 11643-1999, ISO 7064 MOD 11-2) plus a real birth date.
pub fn is_valid_china_resident_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 18 || !id.is_ascii() || !all_digits(&b[..17]) {
        return false;
    }
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let sum: u32 = b.iter().zip(W).map(|(&c, w)| u32::from(c - b'0') * w).sum();
    let check = b"10X98765432"[(sum % 11) as usize];
    if check != b[17].to_ascii_uppercase() {
        return false;
    }
    let num =
        |r: std::ops::Range<usize>| b[r].iter().fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
    is_date(num(6..10), num(10..12), num(12..14))
}

/// Japan My Number (12 digits, check digit per the enforcement order art. 8).
pub fn is_valid_my_number(digits: &str) -> bool {
    let b = digits.as_bytes();
    if b.len() != 12 || !all_digits(b) {
        return false;
    }
    let mut sum = 0u32;
    for n in 1..=11usize {
        let q = if n <= 6 { n + 1 } else { n - 5 } as u32;
        sum += u32::from(b[11 - n] - b'0') * q;
    }
    let r = sum % 11;
    u32::from(b[11] - b'0') == if r <= 1 { 0 } else { 11 - r }
}

/// Hong Kong ID: 1–2 upper-case letters, 6 digits, check digit 0–9 or A (no brackets).
pub fn is_valid_hong_kong_id(id: &str) -> bool {
    let b = id.as_bytes();
    if !(b.len() == 8 || b.len() == 9) || !id.is_ascii() {
        return false;
    }
    let letters = b.len() - 7;
    let mut sum: u32 = if letters == 1 { 36 * 9 } else { 0 };
    for (i, &c) in b.iter().take(letters).enumerate() {
        if !c.is_ascii_uppercase() {
            return false;
        }
        let w = if letters == 1 { 8 } else { 9 - i as u32 };
        sum += (u32::from(c - b'A') + 10) * w;
    }
    for i in 0..6 {
        let Some(d) = digit(b[letters + i]) else {
            return false;
        };
        sum += d * (7 - i as u32);
    }
    let last = b[b.len() - 1];
    let check = if last == b'A' {
        10
    } else if let Some(d) = digit(last) {
        d
    } else {
        return false;
    };
    (sum + check).is_multiple_of(11)
}

/// Singapore NRIC / FIN (S, T, F, G, M series).
pub fn is_valid_singapore_nric(id: &str) -> bool {
    let b = id.as_bytes();
    if b.len() != 9 || !id.is_ascii() || !all_digits(&b[1..8]) {
        return false;
    }
    const W: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];
    let sum: u32 = b[1..8]
        .iter()
        .zip(W)
        .map(|(&c, w)| u32::from(c - b'0') * w)
        .sum();
    let (offset, table): (u32, &[u8; 11]) = match b[0] {
        b'S' => (0, b"JZIHGFEDCBA"),
        b'T' => (4, b"JZIHGFEDCBA"),
        b'F' => (0, b"XWUTRQPNMLK"),
        b'G' => (4, b"XWUTRQPNMLK"),
        b'M' => (3, b"XWUTRQPNJLK"),
        _ => return false,
    };
    table[((sum + offset) % 11) as usize] == b[8]
}

/// US SSN plausibility (no check digit): 9 digits, area not 000/666/900–999, group
/// not 00, serial not 0000.
pub fn is_plausible_us_ssn(digits: &str) -> bool {
    let b = digits.as_bytes();
    if b.len() != 9 || !all_digits(b) {
        return false;
    }
    let area = b[..3]
        .iter()
        .fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
    area != 0 && area != 666 && area < 900 && &b[3..5] != b"00" && &b[5..] != b"0000"
}

/// Assigned two-digit ITU-T E.164 country codes (1 and 7 are handled separately).
const COUNTRY_CODES_2: &[&str] = &[
    "20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45", "46", "47",
    "48", "49", "51", "52", "53", "54", "55", "56", "57", "58", "60", "61", "62", "63", "64", "65",
    "66", "81", "82", "84", "86", "90", "91", "92", "93", "94", "95", "98",
];

/// Assigned three-digit country codes: single codes and inclusive ranges.
const COUNTRY_CODES_3: &[(u32, u32)] = &[
    (211, 213),
    (216, 216),
    (218, 218),
    (220, 258),
    (260, 269),
    (290, 291),
    (297, 299),
    (350, 359),
    (370, 383),
    (385, 387),
    (389, 389),
    (420, 421),
    (423, 423),
    (500, 509),
    (590, 599),
    (670, 670),
    (672, 683),
    (685, 692),
    (800, 800),
    (808, 808),
    (850, 850),
    (852, 853),
    (855, 856),
    (870, 870),
    (878, 878),
    (880, 883),
    (886, 886),
    (888, 888),
    (960, 968),
    (970, 977),
    (979, 979),
    (992, 996),
    (998, 998),
];

/// International phone number digits (after `+`): assigned country code, 8–15 digits;
/// +1 and +7 are exactly 11 digits and the North American area code starts 2–9.
pub fn is_plausible_e164(digits: &str) -> bool {
    let b = digits.as_bytes();
    if !(8..=15).contains(&b.len()) || !all_digits(b) {
        return false;
    }
    match b[0] {
        b'1' => b.len() == 11 && b[1] >= b'2',
        b'7' => b.len() == 11,
        _ => {
            let cc3 = b[..3]
                .iter()
                .fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
            COUNTRY_CODES_2.iter().any(|c| c.as_bytes() == &b[..2])
                || COUNTRY_CODES_3
                    .iter()
                    .any(|&(lo, hi)| (lo..=hi).contains(&cc3))
        }
    }
}

fn is_date(year: u32, month: u32, day: u32) -> bool {
    if !(1800..=2199).contains(&year) || !(1..=12).contains(&month) || day < 1 {
        return false;
    }
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= days
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taiwan_ids() {
        assert!(is_valid_taiwan_id("A123456789"));
        assert!(is_valid_taiwan_id("a123456789"));
        assert!(!is_valid_taiwan_id("A123456788"));
        assert!(!is_valid_taiwan_id("A12345678"));
        assert!(!is_valid_taiwan_id("Ａ123456789"));
    }

    #[test]
    fn luhn_and_iban() {
        assert!(is_valid_luhn("4111111111111111"));
        assert!(!is_valid_luhn("4111111111111112"));
        assert!(!is_valid_luhn("0"));
        assert!(is_valid_iban("DE89370400440532013000"));
        assert!(!is_valid_iban("de89370400440532013000"));
    }

    #[test]
    fn e164_codes() {
        assert!(is_plausible_e164("12025550123"));
        assert!(!is_plausible_e164("11025550123"));
        assert!(is_plausible_e164("886912345678"));
        assert!(!is_plausible_e164("999123456"));
    }

    #[test]
    fn dates() {
        assert!(is_date(2000, 2, 29));
        assert!(!is_date(1900, 2, 29));
    }
}
