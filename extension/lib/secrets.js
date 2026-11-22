// 機密格式偵測與遮罩。純函式、無 DOM、無外部相依，content script 與 node --test 共用。
//
// 每個偵測器回傳 { type, label, start, end, value }，start/end 是在原字串中的位置。
// 只靠 regex 抓「長得像」的字串會很吵，所以有檢查碼的格式一律再驗證檢查碼。

// ---------- 檢查碼 ----------

// 身分證／新式居留證第一碼英文字母對應的兩位數（內政部規則）。
const LETTER_CODES = {
  A: 10, B: 11, C: 12, D: 13, E: 14, F: 15, G: 16, H: 17, I: 34, J: 18,
  K: 19, L: 20, M: 21, N: 22, O: 35, P: 23, Q: 24, R: 25, S: 26, T: 27,
  U: 28, V: 29, W: 32, X: 30, Y: 31, Z: 33,
};

/**
 * 身分證字號（第二碼 1/2）與 2021 年起的新式居留證（第二碼 8/9）共用同一套檢查碼：
 * 字母轉兩位數 n1n2，n1×1 + n2×9 + 後面 8 碼依序 ×8,7,6,5,4,3,2,1 + 檢查碼 ×1，總和可被 10 整除。
 */
export function isValidTaiwanId(id) {
  if (!/^[A-Z][1289]\d{8}$/.test(id)) return false;
  const code = LETTER_CODES[id[0]];
  let sum = Math.floor(code / 10) + (code % 10) * 9;
  const weights = [8, 7, 6, 5, 4, 3, 2, 1];
  for (let i = 0; i < 8; i++) sum += Number(id[i + 1]) * weights[i];
  sum += Number(id[9]);
  return sum % 10 === 0;
}

/**
 * 營利事業統一編號。權重 1,2,1,2,1,2,4,1，各乘積的「十位數＋個位數」加總。
 * 財政部財政資訊中心〈營利事業統一編號檢查碼邏輯修正說明〉（110-12-22 公告）：
 * 判斷由「可被 10 整除」改為「可被 5 整除」，各機關需於 112-03-31 前完成修改，
 * 112 年 4 月起陸續釋出新號碼。新規則是舊規則的超集合，舊號碼照樣通過。
 * 第 7 碼為 7 時，7×4=28 → 2+8=10，可取 1 或 0，兩種總和任一可被 5 整除即合法。
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
  if (sum % 5 === 0) return true;
  // 第 7 碼為 7：上面把 28 算成 10（≡ 0 mod 5，相當於取 0），另一種取法是 1，也就是總和 +1。
  return ubn[6] === '7' && (sum + 1) % 5 === 0;
}

/** Luhn 檢查（信用卡）。 */
export function isValidLuhn(digits) {
  if (!/^\d+$/.test(digits)) return false;
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

// 主要發卡組織的卡號開頭（IIN）與長度。只過 Luhn 的話，任意 16 位數有 1/10 機率誤判。
function looksLikeCardIin(digits) {
  const n = digits.length;
  const p2 = Number(digits.slice(0, 2));
  const p4 = Number(digits.slice(0, 4));
  if (digits[0] === '4') return n === 13 || n === 16 || n === 19; // Visa
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return n === 16; // Mastercard
  if (p2 === 34 || p2 === 37) return n === 15; // American Express
  if (p2 === 35 && p4 >= 3528 && p4 <= 3589) return n >= 16 && n <= 19; // JCB
  if (p4 === 6011 || p2 === 65 || (p4 >= 6440 && p4 <= 6499)) return n >= 16 && n <= 19; // Discover
  if (p2 === 62) return n >= 16 && n <= 19; // UnionPay
  if (p2 === 36 || (p4 >= 3000 && p4 <= 3059) || p2 === 38 || p2 === 39) return n >= 14 && n <= 19; // Diners
  return false;
}

// ---------- 偵測器 ----------

const NOT_ALNUM_BEFORE = '(?<![A-Za-z0-9])';
const NOT_ALNUM_AFTER = '(?![A-Za-z0-9])';

/** @type {{type: string, label: string, pattern: RegExp, normalize?: (s: string) => string, validate?: (s: string, text: string, index: number) => boolean}[]} */
const DETECTORS = [
  {
    type: 'tw-id',
    label: '身分證／居留證號',
    pattern: new RegExp(`${NOT_ALNUM_BEFORE}[A-Za-z][1289]\\d{8}${NOT_ALNUM_AFTER}`, 'g'),
    validate: (s) => isValidTaiwanId(s.toUpperCase()),
  },
  {
    type: 'ubn',
    label: '統一編號',
    pattern: /(?<!\d)\d{8}(?!\d)/g,
    // 新規則下隨機 8 位數約 1/5 會通過檢查碼，日期、訂單號碼會大量誤判，
    // 所以統編還要求前面 12 字內出現「統編／統一編號／稅籍／Tax ID／VAT」等字樣。
    validate: (s, text, index) =>
      isValidUbn(s) && /(統一?編號?|統編|稅籍|tax\s*id|vat|ubn)/i.test(text.slice(Math.max(0, index - 12), index)),
  },
  {
    type: 'credit-card',
    label: '信用卡號',
    // 13–19 位數，允許每位之間有一個空白或連字號（4111 1111 1111 1111、4111-1111-...）。
    pattern: /(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d])/g,
    validate: (s) => {
      const digits = s.replace(/[ -]/g, '');
      return digits.length >= 13 && digits.length <= 19 && looksLikeCardIin(digits) && isValidLuhn(digits);
    },
  },
  {
    type: 'tw-mobile',
    label: '手機號碼',
    pattern: /(?<![\d+])(?:\+886[- ]?|0)9\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)/g,
  },
  // API key：前綴很有辨識度，誤判率低。順序有意義：sk-ant- 要排在 sk- 前面。
  {
    type: 'api-key',
    label: 'GitHub Token',
    pattern: new RegExp(`${NOT_ALNUM_BEFORE}(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})${NOT_ALNUM_AFTER}`, 'g'),
  },
  {
    type: 'api-key',
    label: 'Anthropic API Key',
    pattern: new RegExp(`${NOT_ALNUM_BEFORE}sk-ant-[A-Za-z0-9_-]{20,}`, 'g'),
  },
  {
    type: 'api-key',
    label: 'OpenAI API Key',
    pattern: new RegExp(`${NOT_ALNUM_BEFORE}sk-(?!ant-)[A-Za-z0-9_-]{20,}`, 'g'),
  },
  {
    type: 'api-key',
    label: 'AWS Access Key',
    pattern: new RegExp(`${NOT_ALNUM_BEFORE}(?:AKIA|ASIA)[0-9A-Z]{16}${NOT_ALNUM_AFTER}`, 'g'),
  },
  {
    type: 'api-key',
    label: 'Slack Token',
    pattern: new RegExp(`${NOT_ALNUM_BEFORE}xox[abposr]-[A-Za-z0-9-]{10,}`, 'g'),
  },
  {
    type: 'api-key',
    label: 'Google API Key',
    pattern: new RegExp(`${NOT_ALNUM_BEFORE}AIza[0-9A-Za-z_-]{35}${NOT_ALNUM_AFTER}`, 'g'),
  },
];

// 太長的貼上（整份文件、log）照樣掃，但設上限避免在巨大字串上跑 regex 卡住頁面。
export const MAX_SCAN_LENGTH = 200_000;

/**
 * 找出文字中的機密。回傳依出現位置排序、互不重疊的結果。
 * @param {string} text
 * @returns {{type: string, label: string, start: number, end: number, value: string}[]}
 */
export function findSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const scanned = text.length > MAX_SCAN_LENGTH ? text.slice(0, MAX_SCAN_LENGTH) : text;
  const hits = [];
  for (const d of DETECTORS) {
    d.pattern.lastIndex = 0;
    for (const m of scanned.matchAll(d.pattern)) {
      if (d.validate && !d.validate(m[0], scanned, m.index)) continue;
      hits.push({ type: d.type, label: d.label, start: m.index, end: m.index + m[0].length, value: m[0] });
    }
  }
  // 重疊時保留較早出現、同起點取較長者（例如卡號裡剛好藏著一段像手機的數字）。
  hits.sort((a, b) => a.start - b.start || b.end - a.end);
  const result = [];
  let lastEnd = -1;
  for (const h of hits) {
    if (h.start >= lastEnd) {
      result.push(h);
      lastEnd = h.end;
    }
  }
  return result;
}

// ---------- 遮罩 ----------

// 只遮英數字，保留空白、連字號等分隔符號，讓遮罩後的格式還看得出來是什麼。
function maskMiddle(value, keepStart, keepEnd, maxStars = Infinity) {
  const chars = [...value];
  const alnumIdx = chars.map((c, i) => (/[A-Za-z0-9]/.test(c) ? i : -1)).filter((i) => i >= 0);
  const n = alnumIdx.length;
  if (n <= keepStart + keepEnd) return '*'.repeat(chars.length);
  const hidden = new Set(alnumIdx.slice(keepStart, n - keepEnd));
  if (maxStars === Infinity) return chars.map((c, i) => (hidden.has(i) ? '*' : c)).join('');
  // API key 很長，整串星號沒意義；壓成固定長度。
  const head = chars.slice(0, alnumIdx[keepStart]).join('');
  const tail = chars.slice(alnumIdx[n - keepEnd]).join('');
  return head + '*'.repeat(Math.min(maxStars, hidden.size)) + tail;
}

const API_KEY_PREFIX = /^(github_pat_|gh[pousr]_|sk-ant-|sk-proj-|sk-|AKIA|ASIA|xox[abposr]-|AIza)/;

/**
 * 遮罩單一機密：A123456789 → A12****789。
 * @param {{type: string, value: string}} finding
 */
export function maskSecret(finding) {
  const v = finding.value;
  switch (finding.type) {
    case 'tw-id':
      return maskMiddle(v, 3, 3); // A12****789
    case 'ubn':
      return maskMiddle(v, 2, 2); // 12****56
    case 'credit-card':
      return maskMiddle(v, 0, 4); // **** **** **** 1111
    case 'tw-mobile':
      return maskMiddle(v, v.startsWith('+') ? 6 : 4, 3); // 0912***678
    case 'api-key': {
      const prefix = (v.match(API_KEY_PREFIX) || [''])[0];
      return prefix + maskMiddle(v.slice(prefix.length), 0, 4, 8); // ghp_********abcd
    }
    default:
      return maskMiddle(v, 0, 0);
  }
}

/**
 * 把文字中所有偵測到的機密換成遮罩版本。
 * @param {string} text
 * @param {ReturnType<typeof findSecrets>} [findings]
 */
export function maskText(text, findings = findSecrets(text)) {
  let out = '';
  let pos = 0;
  for (const f of findings) {
    out += text.slice(pos, f.start) + maskSecret(f);
    pos = f.end;
  }
  return out + text.slice(pos);
}
