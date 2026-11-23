// 個資規則包（#27）用到、regex 寫不出來的部分：各格式的檢查碼（規則檔的 validate）、信用卡分組（finder）、
// 遮罩前的標準寫法（mask.canonical）和遮罩本身。每一個名稱在 C# 的 PiiFormats／Checksums／SecretMasker 都有同樣的實作。
// 純函式、無 DOM。

// ---------- 檢查碼 ----------

// 身分證首字母對應的兩位數代碼。注意 I、O、W、X、Y、Z 不是照字母順序排。
const ID_LETTERS = 'ABCDEFGHJKLMNPQRSTUVXYWZIO';
const letterCode = (c) => {
  const i = ID_LETTERS.indexOf(c.toUpperCase());
  return i < 0 ? -1 : 10 + i;
};

/**
 * 國民身分證、新式居留證（第 2 碼 8/9）、舊式居留證（第 2 碼 A–D，取字母代碼的個位數）。
 * 首字母轉兩位數 n1n2，n1×1 + n2×9 + 後面依序 ×8..1 + 檢查碼 ×1，總和被 10 整除。與 C# 的 Checksums.IsValidTaiwanId 相同。
 */
export function isValidTaiwanId(id) {
  if (id.length !== 10) return false;
  const first = letterCode(id[0]);
  if (first < 0) return false;
  const c1 = id[1].toUpperCase();
  let second;
  if ('1289'.includes(c1)) second = Number(c1);
  else if (c1 >= 'A' && c1 <= 'D') second = letterCode(c1) % 10;
  else return false;
  let sum = Math.floor(first / 10) + (first % 10) * 9 + second * 8;
  for (let i = 2; i < 10; i++) {
    if (!/[0-9]/.test(id[i])) return false;
    sum += Number(id[i]) * (i === 9 ? 1 : 9 - i);
  }
  return sum % 10 === 0;
}

/**
 * 營利事業統一編號。權重 1,2,1,2,1,2,4,1，各乘積的「十位數＋個位數」加總。
 * 財政部財政資訊中心〈營利事業統一編號檢查碼邏輯修正說明〉（110-12-22 公告）：判斷由「可被 10 整除」改為「可被 5 整除」，
 * 新規則是舊規則的超集合。第 7 碼為 7 時，7×4=28 → 2+8=10，可取 1 或 0，兩種總和任一可被 5 整除即合法。
 * https://www.fia.gov.tw/singlehtml/3?cntId=c4d9cff38c8642ef8872774ee9987283
 */
export function isValidUbn(ubn) {
  if (!/^\d{8}$/.test(ubn)) return false;
  const weights = [1, 2, 1, 2, 1, 2, 4, 1];
  let sum = 0;
  for (let i = 0; i < 8; i++) {
    const p = Number(ubn[i]) * weights[i];
    sum += Math.floor(p / 10) + (p % 10);
  }
  return sum % 5 === 0 || (ubn[6] === '7' && (sum + 1) % 5 === 0);
}

/** Luhn 檢查（信用卡）。 */
export function isValidLuhn(digits) {
  if (digits.length < 2 || !/^\d+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** IBAN 各國的總長度（SWIFT IBAN Registry）。與 C# 的 Checksums.IbanLengths 相同。 */
export const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BI: 27, BR: 29, BY: 28, CH: 21, CR: 22,
  CY: 28, CZ: 24, DE: 22, DJ: 27, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FK: 18, FO: 18, FR: 27, GB: 22,
  GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HN: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30,
  KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20, LU: 20, LV: 21, LY: 25, MC: 27, MD: 24, ME: 22, MK: 19, MN: 20,
  MR: 27, MT: 31, MU: 30, NI: 28, NL: 18, NO: 15, OM: 23, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22,
  RU: 33, SA: 24, SC: 31, SD: 18, SE: 24, SI: 19, SK: 24, SM: 27, SO: 23, ST: 25, SV: 28, TL: 23, TN: 24, TR: 26,
  UA: 29, VA: 22, VG: 24, XK: 20, YE: 30,
};

/** IBAN（ISO 13616）：國家、長度、檢查碼 02–98、mod 97 = 1。輸入要先去掉空白、轉大寫。 */
export function isValidIban(iban) {
  if (iban.length < 4 || IBAN_LENGTHS[iban.slice(0, 2)] !== iban.length) return false;
  if (!/^[0-9]{2}$/.test(iban.slice(2, 4))) return false;
  const check = Number(iban.slice(2, 4));
  if (check < 2 || check > 98) return false;
  let mod = 0;
  for (let k = 0; k < iban.length; k++) {
    const c = iban[(k + 4) % iban.length];
    if (c >= '0' && c <= '9') mod = (mod * 10 + Number(c)) % 97;
    else if (c >= 'A' && c <= 'Z') mod = (mod * 100 + c.charCodeAt(0) - 55) % 97;
    else return false;
  }
  return mod === 1;
}

const isDate = (y, m, d) => y >= 1800 && y <= 2199 && m >= 1 && m <= 12 && d >= 1 && d <= new Date(Date.UTC(y, m, 0)).getUTCDate();

/** 中國居民身分證（GB 11643-1999）：ISO 7064 MOD 11-2 檢查碼，加上出生日期是真的日期。 */
export function isValidChinaResidentId(id) {
  if (!/^[0-9]{17}[0-9Xx]$/.test(id)) return false;
  const w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(id[i]) * w[i];
  if ('10X98765432'[sum % 11] !== id[17].toUpperCase()) return false;
  return isDate(Number(id.slice(6, 10)), Number(id.slice(10, 12)), Number(id.slice(12, 14)));
}

/** 日本個人番號：從右邊數第 n 碼乘 Qn（n ≤ 6 時 n+1，否則 n−5），mod 11 ≤ 1 時檢查碼 0，否則 11 − 餘數。 */
export function isValidMyNumber(digits) {
  if (!/^[0-9]{12}$/.test(digits)) return false;
  let sum = 0;
  for (let n = 1; n <= 11; n++) sum += Number(digits[11 - n]) * (n <= 6 ? n + 1 : n - 5);
  const r = sum % 11;
  return Number(digits[11]) === (r <= 1 ? 0 : 11 - r);
}

/** 香港身分證：1–2 個字母（A–Z = 10–35，單字母前面補 36）+ 6 碼 + 檢查碼（A = 10），權重 9..1，被 11 整除。 */
export function isValidHongKongId(id) {
  if (!/^[A-Z]{1,2}[0-9]{6}[0-9A]$/.test(id)) return false;
  const letters = id.length - 7;
  let sum = letters === 1 ? 36 * 9 : 0;
  for (let i = 0; i < letters; i++) sum += (id.charCodeAt(i) - 55) * (letters === 1 ? 8 : 9 - i);
  for (let i = 0; i < 6; i++) sum += Number(id[letters + i]) * (7 - i);
  const last = id[id.length - 1];
  return (sum + (last === 'A' ? 10 : Number(last))) % 11 === 0;
}

/** 新加坡 NRIC／FIN：權重 2,7,6,5,4,3,2，T、G 加 4，M 加 3，mod 11 查表。 */
export function isValidSingaporeNric(id) {
  if (!/^[STFGM][0-9]{7}[A-Z]$/.test(id)) return false;
  const w = [2, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 7; i++) sum += Number(id[i + 1]) * w[i];
  const [offset, table] = {
    S: [0, 'JZIHGFEDCBA'], T: [4, 'JZIHGFEDCBA'], F: [0, 'XWUTRQPNMLK'], G: [4, 'XWUTRQPNMLK'], M: [3, 'XWUTRQPNJLK'],
  }[id[0]];
  return table[(sum + offset) % 11] === id[8];
}

/** 美國 SSN：沒有檢查碼，只排除不會發的範圍（區碼 000、666、9xx，組號 00，序號 0000）。 */
export function isPlausibleUsSsn(digits) {
  if (!/^[0-9]{9}$/.test(digits)) return false;
  const area = Number(digits.slice(0, 3));
  return area !== 0 && area !== 666 && area < 900 && digits.slice(3, 5) !== '00' && digits.slice(5) !== '0000';
}

// ITU-T E.164 已分配的國碼。與 C# 的 Checksums.CountryCodes2／CountryCodes3 相同。
const CC2 = new Set(('20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 54 55 56 57 58 60 61 62 63 64 65 66 '
  + '81 82 84 86 90 91 92 93 94 95 98').split(' '));
const CC3 = (() => {
  const set = new Set();
  const range = (a, b) => { for (let c = a; c <= b; c++) set.add(String(c)); };
  for (const c of [211, 212, 213, 216, 218, 290, 291, 297, 298, 299, 389, 420, 421, 423, 670, 800, 808, 850, 852, 853,
    855, 856, 870, 878, 880, 881, 882, 883, 886, 888, 979, 998]) range(c, c);
  range(220, 258); range(260, 269); range(350, 359); range(370, 383); range(385, 387);
  range(500, 509); range(590, 599); range(672, 683); range(685, 692); range(960, 968); range(970, 977); range(992, 996);
  return set;
})();

/** 國際電話（+ 後面的數字）：國碼已分配、8–15 碼；+1、+7 一定 11 碼，北美區碼第一碼 2–9。 */
export function isPlausibleE164(digits) {
  if (digits.length < 8 || digits.length > 15 || !/^[0-9]+$/.test(digits)) return false;
  if (digits[0] === '1') return digits.length === 11 && digits[1] >= '2';
  if (digits[0] === '7') return digits.length === 11;
  return CC2.has(digits.slice(0, 2)) || CC3.has(digits.slice(0, 3));
}

// ---------- mask.canonical ----------

export const digitsOf = (s) => s.replace(/[^0-9]/g, '');
export const alnumUpper = (s) => s.replace(/[^A-Za-z0-9]/g, '').toUpperCase();

function twMobile(s) {
  const d = digitsOf(s);
  return d.startsWith('886') ? `0${d.slice(d[3] === '0' ? 4 : 3)}` : d;
}

export const CANONICAL = {
  'alnum-upper': alnumUpper,
  digits: digitsOf,
  'tw-mobile': twMobile,
  e164: (s) => `+${digitsOf(s)}`,
};

// ---------- validate ----------

// 身分證、居留證：分隔符號最多 3 個（A 123 456 789），\r\n 算一個。
function isTaiwanIdLoose(s) {
  const id = alnumUpper(s);
  const seps = s.length - id.length - (s.match(/\r/g) || []).length;
  return seps <= 3 && isValidTaiwanId(id);
}

// SSN 的兩個分隔符號要一樣，或都沒有。
function isUsSsnLoose(s) {
  const d = digitsOf(s);
  if (d.length !== 9 || !(s.length === 9 || s.length === 11)) return false;
  if (s.length === 11 && s[3] !== s[6]) return false;
  return isPlausibleUsSsn(d);
}

/** 規則檔 validate 的名稱（jwt-header 在 rules.js）。 */
export const PII_VALIDATORS = {
  'tw-id': isTaiwanIdLoose,
  'tw-ubn': isValidUbn,
  iban: (s) => isValidIban(alnumUpper(s)),
  e164: (s) => isPlausibleE164(digitsOf(s)),
  'cn-id': (s) => isValidChinaResidentId(alnumUpper(s)),
  'jp-my-number': (s) => isValidMyNumber(digitsOf(s)),
  'hk-id': (s) => isValidHongKongId(alnumUpper(s)),
  'sg-nric': (s) => isValidSingaporeNric(alnumUpper(s)),
  'us-ssn': isUsSsnLoose,
};

// ---------- finder：信用卡分組 ----------

/** 主要發卡組織的號碼開頭與長度（ISO/IEC 7812 IIN）。與 C# 的 PiiFormats.IsCardPrefix 相同。 */
function isCardPrefix(d) {
  const p = (n) => Number(d.slice(0, n));
  const len = d.length;
  switch (d[0]) {
    case '4': return len === 13 || len === 16 || len === 19; // Visa
    case '5': return p(2) >= 51 && p(2) <= 55 && len === 16; // Mastercard
    case '2': return p(4) >= 2221 && p(4) <= 2720 && len === 16; // Mastercard 2-series
    case '3':
      return ((p(2) === 34 || p(2) === 37) && len === 15) // Amex
        || (p(4) >= 3528 && p(4) <= 3589 && len >= 16 && len <= 19) // JCB
        || ((p(2) === 36 || p(2) === 38 || (p(3) >= 300 && p(3) <= 305)) && len >= 14 && len <= 19); // Diners
    case '6':
      return (d.startsWith('6011') || d.startsWith('65') || (p(3) >= 644 && p(3) <= 649) || d.startsWith('62'))
        && len >= 16 && len <= 19; // Discover / UnionPay
    default: return false;
  }
}

/**
 * 找出用單一分隔符號接起來的數字組，再從裡面找連續幾組合起來像卡號的：
 * 4-4-4-4（最後一組 1–4 碼）、Amex 4-6-5、Diners 4-6-4，分隔符號一致（換行可取代任何一種）。
 * 日期清單、IP、版本號碼這類組合不會被硬湊成卡號。與 C# 的 PiiFormats.CardCandidates 相同。
 * @returns {Iterable<[number, number]>} [start, end]
 */
function* cardCandidates(text) {
  const isDigit = (i) => i < text.length && text.charCodeAt(i) >= 48 && text.charCodeAt(i) <= 57;
  const sepAt = (p) => {
    const c = text[p];
    if (c === ' ' || c === '.' || c === '-') return isDigit(p + 1) ? [c, p + 1] : null;
    if (c === '\n') return isDigit(p + 1) ? ['\n', p + 1] : null;
    if (c === '\r' && text[p + 1] === '\n') return isDigit(p + 2) ? ['\n', p + 2] : null;
    return null;
  };
  let i = 0;
  while (i < text.length) {
    if (!isDigit(i)) { i++; continue; }
    const groups = [];
    let sep = '';
    for (;;) {
      const s = i;
      while (isDigit(i)) i++;
      groups.push({ start: s, end: i, sep });
      const next = sepAt(i);
      if (!next) break;
      [sep, i] = next;
    }
    const len = (k) => groups[k].end - groups[k].start;
    for (let g = 0; g < groups.length; g++) {
      let total = 0;
      for (let h = g; h < groups.length; h++) {
        total += len(h);
        if (total > 19) break;
        if (h > g) {
          const prev = len(h - 1);
          if (prev !== 4 && !(h - 1 === g + 1 && prev === 6)) break;
        }
        if (total < 13 || !isCardGrouping(groups, g, h, len)) continue;
        const digits = groups.slice(g, h + 1).map((x) => text.slice(x.start, x.end)).join('');
        if (!isCardPrefix(digits) || !isValidLuhn(digits)) continue;
        yield [groups[g].start, groups[h].end];
        g = h;
        break;
      }
    }
  }
}

function isCardGrouping(groups, first, last, len) {
  if (first === last) return true;
  let sep = '';
  for (let k = first + 1; k <= last; k++) {
    const s = groups[k].sep;
    if (s === '\n') continue;
    if (!sep) sep = s;
    else if (sep !== s) return false;
  }
  if (last - first === 2 && len(first) === 4 && len(first + 1) === 6 && (len(last) === 4 || len(last) === 5)) return true;
  for (let k = first; k < last; k++) if (len(k) !== 4) return false;
  return len(last) >= 1 && len(last) <= 4;
}

export const FINDERS = { 'card-groups': cardCandidates };

// ---------- 遮罩 ----------

// 星號最多顯示幾個（不透露長度）、至少遮住幾個字。與 C# 的 SecretMasker 相同。
const MAX_STARS = 8;
const MIN_HIDDEN = 4;

/**
 * 頭尾各保留幾個字，中間換成星號（最多 8 個）。保留的字數會隨長度縮減，確保至少遮住 4 個字。
 * 與 C# 的 SecretMasker.Mask 相同（#27 起兩邊的遮罩字串一樣）。
 */
export function maskValue(value, keepStart = 3, keepEnd = 3) {
  if (!value) return '';
  const maxKeep = Math.max(0, value.length - MIN_HIDDEN);
  while (keepStart + keepEnd > maxKeep && (keepStart > 0 || keepEnd > 0)) {
    // 先縮尾端：開頭通常是前綴或類別資訊，比尾端更不敏感。
    if (keepEnd >= keepStart && keepEnd > 0) keepEnd--;
    else keepStart--;
  }
  const hidden = value.length - keepStart - keepEnd;
  return value.slice(0, keepStart) + '*'.repeat(Math.min(hidden, MAX_STARS)) + value.slice(value.length - keepEnd);
}
