// 機密格式偵測與遮罩。純函式、無 DOM、無外部相依，content script 與 node --test 共用。
//
// findSecrets 回傳 { type, label, start, end, value, rule, mask }，start/end 是在原字串中的位置。
// 所有規則（API key、JWT、PEM、上下文＋亂度，以及 #27 起的個資包）都來自共用規則檔 rules/*.json，
// 跟桌面版相同；由 tools/build-extension-rules.mjs 產生 rules.generated.js，比對引擎在 rules.js，
// 檢查碼、信用卡分組、遮罩在 pii.js。格式見 docs/detection-rules.md §5.4。

import {
  RULES, DEFAULT_PACKS, UNIVERSAL, asciiView, asciiLower, keywordsPresent, contextPresentAnywhere, scanRule,
} from './rules.js';
import { CANONICAL, maskValue } from './pii.js';

// 檢查碼以前寫在這裡，測試和其他程式還從這裡 import。
export {
  isValidTaiwanId, isValidUbn, isValidLuhn, isValidIban, isValidChinaResidentId, isValidMyNumber,
  isValidHongKongId, isValidSingaporeNric, isPlausibleUsSsn, isPlausibleE164, maskValue,
} from './pii.js';
export { packsForLocales, countryOf, COUNTRIES, DEFAULT_PACKS } from './rules.js';

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

// 太長的貼上（整份文件、log）最多分析這麼多字；超過時分析開頭和結尾各一半，中間不分析，
// 避免在巨大字串上卡住頁面。與 C# 的 SecretDetector.MaxScanLength 相同。
export const MAX_SCAN_LENGTH = 1 << 20;
// 每段往後多看的字數（機密最長不超過這個長度，例如 JWT 的上限）與往前多看的字數（notPrecededBy、上下文關鍵字）。
const OVERLAP = 8 * 1024;
const CONTEXT = 64;

function scanRanges(length) {
  if (length <= MAX_SCAN_LENGTH) return [[0, length]];
  return [[0, MAX_SCAN_LENGTH / 2], [length - MAX_SCAN_LENGTH / 2, length]];
}

/**
 * 把下一條規則的結果併進已保留的清單：兩份都依位置排序、各自不重疊，跟已保留的重疊就丟掉。
 * 優先順序就是規則的順序（檔案 priority → 檔名 → 檔案內的順序），與 C# 的 SecretDetector.Merge 相同。
 */
function merge(kept, next) {
  if (!next.length) return kept;
  const result = [];
  let k = 0;
  for (const m of next) {
    while (k < kept.length && kept[k].end <= m.start) result.push(kept[k++]);
    if (k < kept.length && kept[k].start < m.end) continue;
    if (result.length && result[result.length - 1].end > m.start) continue;
    result.push(m);
  }
  while (k < kept.length) result.push(kept[k++]);
  return result;
}

/**
 * 找出文字中的機密。回傳依出現位置排序、互不重疊的結果。
 * 比對前先正規化（全形轉半形、去零寬字元）；start/end 是原文的位置，value 是正規化後的字串（給遮罩用）。
 * @param {string} text
 * @param {{packs?: Set<string>}} [options] 要開的規則包；通用包一律開啟。預設是通用包＋台灣包（同 C#）。
 * @returns {{type: string, label: string, start: number, end: number, value: string, rule: string, mask: object}[]}
 */
export function findSecrets(text, { packs = DEFAULT_PACKS } = {}) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const active = RULES.map((r) => r.pack === UNIVERSAL || packs.has(r.pack));
  const byRank = RULES.map(() => []);
  for (const [from, to] of scanRanges(text.length)) {
    const segStart = Math.max(0, from - CONTEXT);
    const segEnd = Math.min(text.length, to + OVERLAP);
    const norm = normalizeForSecrets(text, segStart, segEnd);
    const scanned = norm.text;
    // 在 ASCII 版本上比對（位置不變），先用 keywords 篩掉不可能命中的規則；上下文關鍵字在正規化後的文字上找。
    const ascii = asciiView(scanned);
    const lower = ascii.toLowerCase();
    let contextLower = null;
    RULES.forEach((rule, k) => {
      if (!active[k] || !keywordsPresent(rule, lower)) return;
      if (rule.context) {
        contextLower ??= asciiLower(scanned);
        if (!contextPresentAnywhere(rule, contextLower)) return;
      }
      for (const [s, e] of scanRule(rule, ascii, scanned, contextLower)) {
        const start = norm.start[s];
        const end = norm.end[e - 1];
        if (start < from || start >= to) continue;
        if (segEnd < text.length && end >= segEnd) continue; // 可能被切斷
        byRank[k].push({
          type: rule.type, label: rule.label, start, end, value: scanned.slice(s, e), rule: rule.id, mask: rule.mask,
          ...(rule.pemBlock ? { pemBlock: true } : {}),
        });
      }
    });
  }
  return byRank.reduce(merge, []);
}

// ---------- 遮罩 ----------

const API_KEY_PREFIX = /^(eyJ|github_pat_|gh[pousr]_|sk-ant-|sk-proj-|sk-|AKIA|ASIA|xox[abposr]-|AIza)/;

/**
 * 遮罩單一機密：A123456789 → A12****789、4111 1111 1111 1111 → 4111********1111。
 * 遮罩方式來自規則檔的 mask（findSecrets 的結果帶著）；直接傳 {type, value} 時用同一種 type 的第一條規則。
 * #27 起與 C# 的遮罩字串完全一樣（先換成標準寫法，再保留頭尾）。
 * @param {{type: string, value: string, mask?: {keepStart: number, keepEnd: number, canonical: string|null}, pemBlock?: boolean}} finding
 */
export function maskSecret(finding) {
  const v = finding.value;
  if (finding.pemBlock) return v; // PEM 標頭本身不是機密；maskText 會把後面的內容遮掉
  let spec = finding.mask;
  if (!spec && finding.type === 'api-key') {
    spec = { keepStart: (v.match(API_KEY_PREFIX) || [''])[0].length, keepEnd: 3, canonical: null };
  }
  spec ??= RULES.find((r) => r.type === finding.type)?.mask || { keepStart: 0, keepEnd: 0, canonical: null };
  const value = spec.canonical ? CANONICAL[spec.canonical](v) : v;
  return maskValue(value, spec.keepStart, spec.keepEnd);
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
