// 機密格式偵測與遮罩。純函式、無 DOM、無外部相依，content script 與 node --test 共用。
//
// 每個偵測器回傳 { type, label, start, end, value }，start/end 是在原字串中的位置。
// 只靠 regex 抓「長得像」的字串會很吵，所以有檢查碼的格式一律再驗證檢查碼。
//
// API key、JWT、PEM、上下文＋亂度的規則來自共用規則檔 rules/*.json（與桌面版相同，#26），
// 由 tools/build-extension-rules.mjs 產生 rules.generated.js，比對引擎在 rules.js。格式見 docs/detection-rules.md §5.4。

import { RULES, asciiView, keywordsPresent, scanRule } from './rules.js';

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
// 號碼中間允許的分隔：單一的空白、點、連字號，或一個換行（#22）。零寬字元在正規化時已經刪掉。
const SEP = '(?:[ .\\-]|\\r?\\n)';

// ---------- 正規化（#22） ----------

const NFKC_CACHE = new Map();
const ZERO_WIDTH = new Set(['​', '‌', '‍', '⁠', '﻿', '­']);

/**
 * 逐字 NFKC（全形轉半形）、dash 變體換成 -、刪掉零寬字元，並記住每個字來自原文哪裡。
 * 與 C# 的 SecretTextNormalizer 相同。
 * @returns {{text: string, start: number[], end: number[]}}
 */
export function normalizeForSecrets(text, from = 0, to = text.length) {
  let out = '';
  const start = [];
  const end = [];
  const push = (s, a, b) => {
    for (const c of s) {
      // c 可能是 surrogate pair（數學字母等）：每個 UTF-16 單位都要有一筆位置。
      for (let k = 0; k < c.length; k++) { start.push(a); end.push(b); }
      out += c;
    }
  };
  for (let i = from; i < to; i++) {
    const code = text.charCodeAt(i);
    const c = text[i];
    if (code < 0x80 || (code >= 0x3400 && code <= 0x9fff) || (code >= 0xac00 && code <= 0xd7a3)) {
      out += c; start.push(i); end.push(i + 1);
      continue;
    }
    if (ZERO_WIDTH.has(c)) continue;
    if ((code >= 0x2010 && code <= 0x2015) || code === 0x2212 || code === 0xfe58) {
      out += '-'; start.push(i); end.push(i + 1);
      continue;
    }
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < to) {
      const low = text.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        push(text.slice(i, i + 2).normalize('NFKC'), i, i + 2);
        i++;
        continue;
      }
    }
    if (code >= 0xd800 && code <= 0xdfff) { out += c; start.push(i); end.push(i + 1); continue; }
    let mapped = NFKC_CACHE.get(c);
    if (mapped === undefined) { mapped = c.normalize('NFKC'); NFKC_CACHE.set(c, mapped); }
    push(mapped, i, i + 1);
  }
  return { text: out, start, end };
}

// ---------- 信用卡分組 ----------

/**
 * 找出用單一分隔符號接起來的數字組，再從裡面找連續幾組合起來像卡號的：
 * 4-4-4-4（最後一組 1–4 碼）、Amex 4-6-5、Diners 4-6-4，分隔符號一致（換行可取代任何一種）。
 * 日期清單、IP、版本號碼這類組合不會被硬湊成卡號。與 C# 的 CardCandidates 相同。
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
        if (!looksLikeCardIin(digits) || !isValidLuhn(digits)) continue;
        yield { start: groups[g].start, end: groups[h].end };
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

// 個資（有檢查碼或要特殊分組的）還留在程式裡，#27 再拆到規則檔。API key、JWT、PEM 在共用規則檔（RULES）。
/** @type {{type: string, label: string, pattern?: RegExp, find?: (text: string) => Iterable<{start: number, end: number}>, validate?: (s: string, text: string, index: number, m: RegExpMatchArray) => boolean}[]} */
const DETECTORS = [
  {
    type: 'tw-id',
    label: '身分證／居留證號',
    pattern: new RegExp(`${NOT_ALNUM_BEFORE}[A-Za-z]${SEP}?[1289](?:${SEP}?[0-9]){8}${NOT_ALNUM_AFTER}`, 'g'),
    // 分隔符號最多 3 個（A 123 456 789）；\r\n 算一個。
    validate: (s) => {
      const id = s.replace(/[^A-Za-z0-9]/g, '');
      const seps = s.replace(/\r\n/g, '\n').length - id.length;
      return seps <= 3 && isValidTaiwanId(id.toUpperCase());
    },
  },
  {
    type: 'ubn',
    label: '統一編號',
    pattern: /(?<![0-9])[0-9]{8}(?![0-9])/g,
    // 新規則下隨機 8 位數約 1/5 會通過檢查碼，日期、訂單號碼會大量誤判，
    // 所以統編還要求前面 12 字內出現「統編／統一編號／稅籍／Tax ID／VAT」等字樣。
    validate: (s, text, index) =>
      isValidUbn(s) && /(統一?編號?|統編|稅籍|tax\s*id|vat|ubn)/i.test(text.slice(Math.max(0, index - 12), index)),
  },
  {
    type: 'credit-card',
    label: '信用卡號',
    // 13–19 位數，分組方式要像卡號（見 cardCandidates），開頭與 Luhn 都要對。
    find: cardCandidates,
  },
  {
    type: 'tw-mobile',
    label: '手機號碼',
    // 09 加 8 碼、+886／886 開頭（可以多寫一個 0）、(09)55666777。
    pattern: new RegExp(
      `(?<![0-9+])(?:(?:\\+?886${SEP}?0?|0)9[0-9]{2}${SEP}?[0-9]{3}${SEP}?[0-9]{3}`
      + `|\\(09\\)${SEP}?(?:[0-9]{4}${SEP}?[0-9]{4}|[0-9]{2}${SEP}?[0-9]{3}${SEP}?[0-9]{3}))(?![0-9])`, 'g'),
  },
];

// 太長的貼上（整份文件、log）最多分析這麼多字；超過時分析開頭和結尾各一半，中間不分析，
// 避免在巨大字串上卡住頁面。與 C# 的 SecretDetector.MaxScanLength 相同。
export const MAX_SCAN_LENGTH = 1 << 20;
// 每段往後多看的字數（機密最長不超過這個長度，例如 JWT 的上限）與往前多看的字數（lookbehind、統編關鍵字）。
const OVERLAP = 8 * 1024;
const CONTEXT = 64;

function scanRanges(length) {
  if (length <= MAX_SCAN_LENGTH) return [[0, length]];
  return [[0, MAX_SCAN_LENGTH / 2], [length - MAX_SCAN_LENGTH / 2, length]];
}

/**
 * 找出文字中的機密。回傳依出現位置排序、互不重疊的結果。
 * 比對前先正規化（全形轉半形、去零寬字元）；start/end 是原文的位置，value 是正規化後的字串（給遮罩用）。
 * @param {string} text
 * @returns {{type: string, label: string, start: number, end: number, value: string}[]}
 */
export function findSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const hits = [];
  for (const [from, to] of scanRanges(text.length)) {
    const segStart = Math.max(0, from - CONTEXT);
    const segEnd = Math.min(text.length, to + OVERLAP);
    const norm = normalizeForSecrets(text, segStart, segEnd);
    const scanned = norm.text;
    const add = (d, s, e, extra) => {
      const start = norm.start[s];
      const end = norm.end[e - 1];
      if (start < from || start >= to) return;
      if (segEnd < text.length && end >= segEnd) return; // 可能被切斷
      hits.push({ type: d.type, label: d.label, start, end, value: scanned.slice(s, e), ...extra });
    };
    // 共用規則檔：在 ASCII 版本上比對（位置不變），先用 keywords 篩掉不可能命中的規則。排在個資前面，
    // 同起點、同長度時以規則檔的結果為準（排序是穩定的）。
    const ascii = asciiView(scanned);
    const lower = ascii.toLowerCase();
    for (const rule of RULES) {
      if (!keywordsPresent(rule, lower)) continue;
      for (const [s, e] of scanRule(rule, ascii, scanned)) {
        add(rule, s, e, { rule: rule.id, keepStart: rule.keepStart, ...(rule.pemBlock ? { pemBlock: true } : {}) });
      }
    }
    for (const d of DETECTORS) {
      if (d.find) {
        for (const c of d.find(scanned)) add(d, c.start, c.end);
        continue;
      }
      d.pattern.lastIndex = 0;
      for (const m of scanned.matchAll(d.pattern)) {
        if (d.validate && !d.validate(m[0], scanned, m.index, m)) continue;
        add(d, m.index, m.index + m[0].length);
      }
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

const API_KEY_PREFIX = /^(eyJ|github_pat_|gh[pousr]_|sk-ant-|sk-proj-|sk-|AKIA|ASIA|xox[abposr]-|AIza)/;

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
      if (finding.pemBlock) return v; // PEM 標頭本身不是機密；maskText 會把後面的內容遮掉
      // 規則檔的命中帶有 keepStart（保留的前綴長度）；直接傳 {type, value} 進來時依前綴猜。
      const prefix = finding.keepStart !== undefined ? v.slice(0, finding.keepStart) : (v.match(API_KEY_PREFIX) || [''])[0];
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
    if (f.start < pos) continue; // 落在已經遮掉的 PEM 內容裡
    out += text.slice(pos, f.start) + maskSecret(f);
    pos = f.end;
    if (f.pemBlock) {
      // PEM 只比對到標頭，真正的機密在標頭後面：一路遮到 END 行（沒有 END 就遮到結尾）。與 C# 的 PasteGuard 相同。
      out += `\n${PEM_BODY_MASK}\n`;
      const end = text.indexOf('-----END ', pos);
      pos = end < 0 ? text.length : end;
    }
  }
  return out + text.slice(pos);
}

/** 貼遮罩版時，PEM 私鑰內容換成的文字。與 C# 的 PasteGuard.PemBodyMask 相同。 */
export const PEM_BODY_MASK = '（私鑰內容已遮罩）';
