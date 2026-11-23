// 共用規則檔的比對引擎（#26）。規則本身在 repo 根目錄的 rules/*.json，桌面版（C# 的 SecretRules）讀同一份；
// 插件執行時不能讀 extension/ 以外的檔案，所以由 tools/build-extension-rules.mjs 產生 rules.generated.js。
// 格式與語法限制見 docs/detection-rules.md §5.4。純函式、無 DOM。

import RULE_FILES from './rules.generated.js';
import { PII_VALIDATORS, FINDERS, CANONICAL } from './pii.js';

/** JWT：header（第一個句點之前）要能解成 JSON 物件，而且有字串型別的 alg。 */
export function isJwt(token) {
  const segment = token.split('.')[0];
  if (segment.length % 4 === 1) return false;
  try {
    const b64 = segment.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return json !== null && typeof json === 'object' && !Array.isArray(json) && typeof json.alg === 'string';
  } catch {
    return false;
  }
}

const VALIDATORS = { 'jwt-header': isJwt, ...PII_VALIDATORS };
// 規則檔的 kind → 結果的 type。與 C# 的 SecretKind 一一對應（#27 起個資也在規則檔裡）。
const KINDS = {
  'api-key': 'api-key',
  'national-id': 'national-id',
  'resident-certificate': 'resident-certificate',
  'business-id': 'business-id',
  'credit-card': 'credit-card',
  'mobile-phone': 'mobile-phone',
  'phone-number': 'phone-number',
  'bank-account': 'bank-account',
};

/** 遮罩時預設保留的結尾字數。與 C# 的 SecretRules.DefaultKeepEnd 相同（#27 起兩邊都是 3）。 */
export const DEFAULT_KEEP_END = 3;
export const UNIVERSAL = 'universal';
// 上下文往前／往後看的上限與關鍵字長度上限。與 C# 的 ContextSpec 相同。
const MAX_WINDOW = 32;
const MAX_KEYWORD_LENGTH = 24;

/** Shannon entropy（每個字元幾 bit），與 C# 的 SecretValidators.Entropy、gitleaks 相同。 */
export function shannonEntropy(s) {
  if (!s.length) return 0;
  const counts = new Map();
  for (let i = 0; i < s.length; i++) counts.set(s[i], (counts.get(s[i]) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function charset(s) {
  if (/^[0-9a-fA-F-]+$/.test(s)) return 'hex'; // UUID 這種「hex 加連字號」也算 hex
  if (/^[0-9a-z]+$/.test(s) || /^[0-9A-Z]+$/.test(s)) return 'base36';
  return 'base64';
}

/** 亂度門檻：固定值（gitleaks），或依字元組成分類的 min(cap, a + b·log2(長度))。 */
export function entropyThreshold(spec, secret) {
  if (typeof spec === 'number') return spec;
  const [a, b, cap] = spec[charset(secret)];
  return Math.min(cap, a + b * Math.log2(secret.length));
}

/** 一半以上的相鄰字元是相同或連號（aaaa、0123456789abcdef），不像隨機產生的 key。 */
export function isSequential(s) {
  if (s.length < 2) return true;
  let close = 0;
  for (let i = 1; i < s.length; i++) if (Math.abs(s.charCodeAt(i) - s.charCodeAt(i - 1)) <= 1) close++;
  return close * 2 >= s.length - 1;
}

const KEY_CHAR = /[A-Za-z0-9_.-]/;

/** 金鑰名稱：群組 1 往前延伸到整個識別字（最多 40 字）。與 C# 的 SecretRule.KeyOf 相同。 */
function keyOf(text, m) {
  const g = m.indices[1] || [m.index, m.index + m[0].length];
  let start = g[0];
  const limit = Math.max(0, start - 40);
  while (start > limit && KEY_CHAR.test(text[start - 1])) start--;
  return text.slice(start, g[1]);
}

function lineOf(text, start, end) {
  const a = start > 0 ? text.lastIndexOf('\n', start - 1) + 1 : 0;
  const b = text.indexOf('\n', end);
  return text.slice(a, b < 0 ? text.length : b);
}

function compileExclusions(list = []) {
  return list.map((x) => {
    if (x.target && !['secret', 'match', 'line', 'key'].includes(x.target)) throw new Error(`exclude 的 target 不認得：${x.target}`);
    return { re: new RegExp(x.regex), ignoreCase: !!x.ignoreCase, target: x.target || 'secret' };
  });
}

function compileContext(id, c) {
  if (!c) return null;
  const keywords = c.keywords || [];
  if (!keywords.length || keywords.some((k) => !k.length || k.length > MAX_KEYWORD_LENGTH || k !== asciiLower(k))) {
    throw new Error(`${id}: context.keywords 要是 1–${MAX_KEYWORD_LENGTH} 字、英文小寫`);
  }
  const before = c.before || 0;
  const after = c.after || 0;
  if (before < 0 || before > MAX_WINDOW || after < 0 || after > MAX_WINDOW || before + after === 0) {
    throw new Error(`${id}: context.before／after 要在 0–${MAX_WINDOW}，而且不能都是 0`);
  }
  return { keywords, before, after };
}

function compileMask(id, mask) {
  if (mask === undefined) return { keepStart: 0, keepEnd: DEFAULT_KEEP_END, canonical: null };
  if (typeof mask === 'string') {
    if (mask !== 'pem-block') throw new Error(`${id}: mask 不認得`);
    return { keepStart: 0, keepEnd: DEFAULT_KEEP_END, canonical: null };
  }
  if (mask.canonical && !CANONICAL[mask.canonical]) throw new Error(`${id}: mask.canonical 不認得：${mask.canonical}`);
  return { keepStart: mask.keepStart || 0, keepEnd: mask.keepEnd ?? DEFAULT_KEEP_END, canonical: mask.canonical || null };
}

/** 把規則檔編譯成可以直接用的物件；順序依檔案 priority、再依檔名、再依檔案內的順序（同 C#）。 */
export function compileRules(files) {
  const sorted = [...files].sort((a, b) => a.priority - b.priority || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const rules = [];
  const ids = new Set();
  for (const file of sorted) {
    if (file.format !== 1) throw new Error(`${file.name}: 不支援的 format`);
    const pack = file.pack ?? UNIVERSAL;
    if (pack !== UNIVERSAL && !/^[A-Z]{2}$/.test(pack)) throw new Error(`${file.name}: pack 要是 universal 或兩個大寫字母的國家代碼`);
    const fileExclude = compileExclusions(file.exclude);
    for (const r of file.rules) {
      if (ids.has(r.id)) throw new Error(`規則 id 重複：${r.id}`);
      ids.add(r.id);
      if (!KINDS[r.kind]) throw new Error(`${r.id}: kind 不認得：${r.kind}`);
      if (r.validate && !VALIDATORS[r.validate]) throw new Error(`${r.id}: validate 不認得：${r.validate}`);
      if ((r.regex === undefined) === (r.finder === undefined)) throw new Error(`${r.id}: 要有 regex 或 finder 其中一個`);
      if (r.finder !== undefined && !FINDERS[r.finder]) throw new Error(`${r.id}: finder 不認得：${r.finder}`);
      rules.push({
        id: r.id,
        pack,
        type: KINDS[r.kind],
        label: r.label,
        // d 旗標：要知道群組的位置（機密不一定是整段比對結果）。
        pattern: r.regex === undefined ? null : new RegExp(r.regex, 'gd' + (r.ignoreCase ? 'i' : '')),
        finder: r.finder === undefined ? null : FINDERS[r.finder],
        context: compileContext(r.id, r.context),
        secretGroup: r.secretGroup,
        keywords: r.keywords || [],
        notPrecededBy: r.notPrecededBy ? new RegExp(`^(?:${r.notPrecededBy})$`) : null,
        notFollowedBy: r.notFollowedBy ? new RegExp(`(?:${r.notFollowedBy})`, 'y') : null,
        minLength: r.minLength ?? 1,
        maxLength: r.maxLength ?? Infinity,
        entropy: r.entropy,
        digitRequiredBelow: r.digitRequiredBelow || 0,
        rejectSequential: !!r.rejectSequential,
        exclude: [...compileExclusions(r.exclude), ...fileExclude],
        stopwords: [...(r.stopwords || []), ...(file.stopwords || [])],
        validate: r.validate ? VALIDATORS[r.validate] : null,
        mask: compileMask(r.id, r.mask),
        pemBlock: r.mask === 'pem-block',
      });
    }
  }
  return rules;
}

export const RULES = compileRules(RULE_FILES);

/**
 * 比對用的 ASCII 版本：非 ASCII 字元換成 U+001A，長度不變（沒有 u 旗標時，代理對的兩半各換一個）。
 * 規則的 \b、\w、i 旗標在 .NET 認 Unicode、在 JS 只認 ASCII；只給它們 ASCII 就兩邊一樣。與 C# 的 SecretRules.AsciiView 相同。
 */
export const asciiView = (text) => text.replace(/[^\x00-\x7f]/g, '\x1a');

/**
 * 只把 A–Z 轉小寫，長度不變（上下文關鍵字用）。與 C# 的 ContextSpec.AsciiLower 相同。
 * toLowerCase 比較快；它只在極少數字元（İ）改變長度，正規化（NFKC）之後也不會把其他非 ASCII 字變成 ASCII，所以長度不變時結果一樣。
 */
export function asciiLower(text) {
  const lower = text.toLowerCase();
  if (lower.length === text.length) return lower;
  return text.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) | 32));
}

const isAsciiLetter = (c) => c !== undefined && /[A-Za-z]/.test(c);

/** 開頭或結尾是英文字母的關鍵字，不能緊貼著其他英文字母（vat 不會比到 private）。 */
function isWord(s, start, length) {
  const end = start + length;
  if (/[a-z]/.test(s[start]) && isAsciiLetter(s[start - 1])) return false;
  if (/[a-z]/.test(s[end - 1]) && isAsciiLetter(s[end])) return false;
  return true;
}

/** 上下文的預先篩選：lower（asciiLower 過的正規化文字）裡有沒有任何一個關鍵字。 */
export function contextPresentAnywhere(rule, lower) {
  return !rule.context || rule.context.keywords.some((k) => lower.includes(k));
}

/** 機密 [start, end) 前面 before 字內（關鍵字的結尾）或後面 after 字內（關鍵字的開頭）有沒有關鍵字。與 C# 的 ContextSpec.Present 相同。 */
function contextPresent(ctx, lower, start, end) {
  for (const k of ctx.keywords) {
    if (ctx.before > 0) {
      const from = Math.max(0, start - ctx.before - k.length);
      const window = lower.slice(from, start);
      for (let p = window.indexOf(k); p >= 0; p = window.indexOf(k, p + 1)) {
        if (isWord(lower, from + p, k.length)) return true;
      }
    }
    if (ctx.after > 0 && end < lower.length) {
      const window = lower.slice(end, Math.min(lower.length, end + ctx.after + k.length));
      for (let p = window.indexOf(k); p >= 0; p = window.indexOf(k, p + 1)) {
        if (isWord(lower, end + p, k.length)) return true;
      }
    }
  }
  return false;
}

/** 機密是哪個群組：secretGroup，或第一個有比對到、不是空字串的群組，沒有群組就是整段（同 gitleaks、C#）。 */
function secretRange(rule, m) {
  if (rule.secretGroup !== undefined) return m.indices[rule.secretGroup] || [m.index, m.index];
  for (let k = 1; k < m.length; k++) {
    const g = m.indices[k];
    if (g && g[1] > g[0]) return g;
  }
  return [m.index, m.index + m[0].length];
}

function accept(rule, secret, m, ascii, range, contextLower) {
  if (rule.entropy !== undefined && shannonEntropy(secret) <= entropyThreshold(rule.entropy, secret)) return false;
  if (rule.digitRequiredBelow && secret.length < rule.digitRequiredBelow && !/[0-9]/.test(secret)) return false;
  if (rule.rejectSequential && isSequential(secret)) return false;
  if (rule.stopwords.length) {
    const lower = secret.toLowerCase();
    if (rule.stopwords.some((w) => lower.includes(w))) return false;
  }
  for (const e of rule.exclude) {
    let target;
    if (e.target === 'match') target = m ? m[0] : secret;
    else if (e.target === 'line') target = m ? lineOf(ascii, m.index, m.index + m[0].length) : lineOf(ascii, range[0], range[1]);
    else if (e.target === 'key') target = m ? keyOf(ascii, m) : secret;
    else target = secret;
    if (e.ignoreCase) target = target.toLowerCase();
    if (e.re.test(target)) return false;
  }
  if (rule.validate && !rule.validate(secret)) return false;
  return !rule.context || contextPresent(rule.context, contextLower, range[0], range[1]);
}

/** 這條規則的 keywords 有沒有出現在 lower（ASCII 版本轉小寫）裡；沒有 keywords 的規則一律要跑。 */
export function keywordsPresent(rule, lower) {
  return rule.keywords.length === 0 || rule.keywords.some((k) => lower.includes(k));
}

/**
 * 一條規則在 ascii（asciiView 的結果）裡的命中：[start, end]，是機密本身的位置。
 * 機密字串從 text（同長度的正規化文字）取，用來算亂度和驗證。
 */
export function* scanRule(rule, ascii, text, contextLower = rule.context ? asciiLower(text) : null) {
  if (rule.finder) {
    for (const [s, e] of rule.finder(ascii)) {
      if (e - s < rule.minLength || e - s > rule.maxLength) continue;
      if (!accept(rule, text.slice(s, e), null, ascii, [s, e], contextLower)) continue;
      yield [s, e];
    }
    return;
  }
  rule.pattern.lastIndex = 0;
  for (const m of ascii.matchAll(rule.pattern)) {
    const end = m.index + m[0].length;
    if (rule.notPrecededBy && m.index > 0 && rule.notPrecededBy.test(ascii[m.index - 1])) continue;
    if (rule.notFollowedBy && end < ascii.length) {
      rule.notFollowedBy.lastIndex = end;
      if (rule.notFollowedBy.test(ascii)) continue;
    }
    const [s, e] = secretRange(rule, m);
    if (e - s < rule.minLength || e - s > rule.maxLength) continue;
    if (!accept(rule, text.slice(s, e), m, ascii, [s, e], contextLower)) continue;
    yield [s, e];
  }
}

// ---------- 規則包（#27） ----------

/** 沒有指定時用的包：通用包＋台灣包（#27 之前的行為）。與 C# 的 SecretPacks.Default 相同。 */
export const DEFAULT_PACKS = new Set([UNIVERSAL, 'TW']);

/** 規則檔裡所有的國家包，依代碼排序。 */
export const COUNTRIES = [...new Set(RULES.map((r) => r.pack).filter((p) => p !== UNIVERSAL))].sort();

// 只有語言、沒有地區的寫法（navigator.language 常見的 ja、ko）。與 C# 的 SecretPacks 相同。
const LANGUAGE_ONLY = { ja: 'JP', ko: 'KR' };

/** 地區或語系名稱（zh-TW、en-US、zh-Hant-HK、ja）對應的國家包；沒有就回傳 null。與 C# 的 SecretPacks.CountryOf 相同。 */
export function countryOf(locale) {
  if (typeof locale !== 'string' || !locale.trim()) return null;
  const parts = locale.trim().split(/[-_]/);
  let region = null;
  if (parts.length === 1) {
    if (/^[A-Z]{2}$/.test(parts[0])) region = parts[0];
    else region = LANGUAGE_ONLY[parts[0].toLowerCase()] || null;
  } else {
    const sub = parts.slice(1).find((p) => /^[A-Za-z]{2}$/.test(p));
    region = sub ? sub.toUpperCase() : LANGUAGE_ONLY[parts[0].toLowerCase()] || null;
  }
  return region && COUNTRIES.includes(region) ? region : null;
}

/**
 * 插件要開的包：通用包，加上瀏覽器偏好語言（navigator.languages）對應的國家包。插件沒有設定畫面，
 * 所以不像桌面版只看一個地區設定，而是每個偏好語言都算（zh-TW、en-US 都列著就開 TW 和 US）。
 */
export function packsForLocales(locales) {
  const packs = new Set([UNIVERSAL]);
  for (const l of locales || []) {
    const c = countryOf(l);
    if (c) packs.add(c);
  }
  return packs;
}
