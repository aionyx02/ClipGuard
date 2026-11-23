#!/usr/bin/env node
// 把 gitleaks 的預設規則（config/gitleaks.toml，MIT）轉成 ClipGuard 的共用規則檔 rules/gitleaks.json。
//
// 用法（toml 先另外下載，這支程式不連網）：
//   gh api -H "Accept: application/vnd.github.raw" repos/gitleaks/gitleaks/contents/config/gitleaks.toml?ref=<commit> > gitleaks.toml
//   node tools/convert-gitleaks.mjs gitleaks.toml <版本，例如 v8.30.1> <commit SHA>
//   node tools/build-extension-rules.mjs
//
// 轉換重點（細節見 docs/detection-rules.md §5.4）：
// - Go RE2 → .NET 與 JS 都一樣的子集合：\w \d \s . 展開成明確的 ASCII 字元類別；(?i) 只出現在開頭時
//   改成整條規則的 ignoreCase，其他位置的 (?i) / (?-i:…) 直接展開成 [aA] 這種大小寫類別；
//   (?P<name>…) 改成一般的捕獲群組（編號不變）；POSIX 類別展開。不支援的語法整條略過並記錄原因。
// - 開頭的 [\w.-]{0,50}? 拿掉：它只是讓比對結果多包住變數名稱，拿掉不影響找到的機密，但可以省很多時間。
// - 只看路徑的規則、client ID 這類不算機密的規則、跟手寫規則重複的規則都略過，原因寫進輸出檔的 skipped。
// - allowlist 裡「本身就是一把完整 key」的範例字串不收（推上 GitHub 會被 push protection 擋，也會被當成外洩）。

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// ---------- 迷你 TOML 解析器（只支援 gitleaks.toml 用到的語法） ----------

export function parseToml(src) {
  const root = {};
  let current = root;
  let i = 0;
  const n = src.length;

  const skipWs = () => {
    for (;;) {
      while (i < n && /[ \t\r\n,]/.test(src[i])) i++;
      if (src[i] === '#') { while (i < n && src[i] !== '\n') i++; continue; }
      break;
    }
  };

  const readValue = () => {
    skipWs();
    if (src.startsWith("'''", i)) {
      const end = src.indexOf("'''", i + 3);
      const v = src.slice(i + 3, end);
      i = end + 3;
      return v;
    }
    if (src[i] === "'") {
      const end = src.indexOf("'", i + 1);
      const v = src.slice(i + 1, end);
      i = end + 1;
      return v;
    }
    if (src[i] === '"') {
      let v = '';
      i++;
      while (src[i] !== '"') {
        if (src[i] === '\\') {
          const e = src[i + 1];
          v += { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\' }[e] ?? e;
          i += 2;
        } else v += src[i++];
      }
      i++;
      return v;
    }
    if (src[i] === '[') {
      i++;
      const arr = [];
      for (;;) {
        skipWs();
        if (src[i] === ']') { i++; return arr; }
        arr.push(readValue());
      }
    }
    const m = /^[^\s,\]#]+/.exec(src.slice(i, i + 64));
    i += m[0].length;
    if (m[0] === 'true') return true;
    if (m[0] === 'false') return false;
    return Number(m[0]);
  };

  while (i < n) {
    skipWs();
    if (i >= n) break;
    if (src.startsWith('[[', i)) {
      const end = src.indexOf(']]', i);
      const path = src.slice(i + 2, end).trim().split('.');
      i = end + 2;
      let parent = root;
      for (let k = 0; k < path.length - 1; k++) {
        const arr = parent[path[k]];
        parent = Array.isArray(arr) ? arr[arr.length - 1] : (parent[path[k]] ??= {});
      }
      const last = path[path.length - 1];
      (parent[last] ??= []).push((current = {}));
      continue;
    }
    if (src[i] === '[') {
      const end = src.indexOf(']', i);
      const name = src.slice(i + 1, end).trim();
      i = end + 1;
      current = root[name] = {};
      continue;
    }
    const eq = src.indexOf('=', i);
    const key = src.slice(i, eq).trim();
    i = eq + 1;
    current[key] = readValue();
  }
  return root;
}

// ---------- RE2 → 共用子集合 ----------

class Unsupported extends Error {}

const SPACE = [[9, 10], [12, 13], [32, 32]];       // RE2 的 \s：\t \n \f \r 空白（不含 \v）
const DIGIT = [[48, 57]];
const WORD = [[48, 57], [65, 90], [95, 95], [97, 122]];
const POSIX = {
  alnum: [[48, 57], [65, 90], [97, 122]],
  alpha: [[65, 90], [97, 122]],
  digit: DIGIT,
  lower: [[97, 122]],
  upper: [[65, 90]],
  space: [[9, 13], [32, 32]],
  xdigit: [[48, 57], [65, 70], [97, 102]],
  word: WORD,
  punct: [[33, 47], [58, 64], [91, 96], [123, 126]],
};

function normalizeRanges(ranges) {
  const r = ranges.map(([a, b]) => [a, b]).sort((x, y) => x[0] - y[0]);
  const out = [];
  for (const x of r) {
    const last = out[out.length - 1];
    if (last && x[0] <= last[1] + 1) last[1] = Math.max(last[1], x[1]);
    else out.push(x);
  }
  return out;
}

function foldCase(ranges) {
  const extra = [];
  for (const [a, b] of ranges) {
    const lo = Math.max(a, 97), hi = Math.min(b, 122);
    if (lo <= hi) extra.push([lo - 32, hi - 32]);
    const LO = Math.max(a, 65), HI = Math.min(b, 90);
    if (LO <= HI) extra.push([LO + 32, HI + 32]);
  }
  return normalizeRanges([...ranges, ...extra]);
}

function classChar(c) {
  if (/[A-Za-z0-9]/.test(String.fromCharCode(c))) return String.fromCharCode(c);
  if (c === 9) return '\\t';
  if (c === 10) return '\\n';
  if (c === 13) return '\\r';
  if (c === 12) return '\\f';
  if (c === 11) return '\\v';
  if (c > 32 && c < 127) {
    const ch = String.fromCharCode(c);
    return '\\]^-['.includes(ch) ? '\\' + ch : ch;
  }
  if (c === 32) return ' ';
  if (c <= 0xff) return '\\x' + c.toString(16).padStart(2, '0');
  return '\\u' + c.toString(16).padStart(4, '0');
}

function renderClass(ranges, negated) {
  const r = normalizeRanges(ranges);
  if (!negated && r.length === 1 && r[0][0] === 0 && r[0][1] >= 0xffff) return '[\\s\\S]';
  // 英數字用範圍表示，標點符號一個一個列出來（[+/0-9] 而不是 [+/-9]），比較好讀。
  const BLOCKS = [[48, 57], [65, 90], [97, 122]];
  let body = '';
  for (const [a, b] of r) {
    let c = a;
    while (c <= b) {
      const block = BLOCKS.find(([lo, hi]) => c >= lo && c <= hi);
      if (block) {
        const end = Math.min(b, block[1]);
        body += end === c ? classChar(c) : end === c + 1 ? classChar(c) + classChar(end) : classChar(c) + '-' + classChar(end);
        c = end + 1;
      } else if (c > 126 || c < 32) {
        // 控制字元或非 ASCII：連續的一段用範圍表示。
        let end = c;
        while (end < b && (end + 1 > 126 || end + 1 < 32)) end++;
        if (end - c >= 3) body += classChar(c) + '-' + classChar(end);
        else for (let k = c; k <= end; k++) body += classChar(k);
        c = end + 1;
      } else {
        body += classChar(c);
        c++;
      }
    }
  }
  return `[${negated ? '^' : ''}${body}]`;
}

/**
 * 轉換一條 RE2 regex。
 * @returns {{regex: string, ignoreCase: boolean, groups: number, groupStarts: number[]}}
 *   groupStarts[k] 是第 k 個捕獲群組內容在原始 pattern 裡的起點（算前綴長度用）。
 */
export function convertRegex(src) {
  let pattern = src;
  let ignoreCase = false;
  // 只有開頭的 (?i)，後面沒有其他大小寫切換：整條規則 ignoreCase，不必展開。
  if (pattern.startsWith('(?i)') && !/\(\?-?[a-z]*i/.test(pattern.slice(4))) {
    ignoreCase = true;
    pattern = pattern.slice(4);
  }
  let i = 0;
  let groups = 0;
  const groupStarts = [];
  const offset = src.length - pattern.length;

  const parseClass = (flags) => {
    // 進來時 pattern[i] === '['
    i++;
    let negated = false;
    if (pattern[i] === '^') { negated = true; i++; }
    const ranges = [];
    let first = true;
    const readAtom = () => {
      // 回傳單一字元碼，或 {set: ranges}
      const c = pattern[i];
      if (c === '[' && pattern[i + 1] === ':') {
        const end = pattern.indexOf(':]', i);
        const name = pattern.slice(i + 2, end);
        if (!POSIX[name]) throw new Unsupported(`POSIX 類別 ${name}`);
        i = end + 2;
        return { set: POSIX[name] };
      }
      if (c === '\\') {
        const e = pattern[i + 1];
        i += 2;
        switch (e) {
          case 'd': return { set: DIGIT };
          case 'w': return { set: WORD };
          case 's': return { set: SPACE };
          case 'D': case 'W': case 'S': throw new Unsupported(`字元類別裡的 \\${e}`);
          case 'n': return 10;
          case 'r': return 13;
          case 't': return 9;
          case 'f': return 12;
          case 'v': return 11;
          case 'x': {
            if (pattern[i] === '{') {
              const end = pattern.indexOf('}', i);
              const v = parseInt(pattern.slice(i + 1, end), 16);
              i = end + 1;
              return v;
            }
            const v = parseInt(pattern.slice(i, i + 2), 16);
            i += 2;
            return v;
          }
          case 'p': case 'P': throw new Unsupported('Unicode 類別 \\p');
          default:
            if (/[A-Za-z0-9]/.test(e)) throw new Unsupported(`跳脫字元 \\${e}`);
            return e.charCodeAt(0);
        }
      }
      i++;
      return c.charCodeAt(0);
    };
    while (first || pattern[i] !== ']') {
      if (i >= pattern.length) throw new Unsupported('字元類別沒有結束');
      first = false;
      const a = readAtom();
      if (typeof a === 'object') { ranges.push(...a.set); continue; }
      if (pattern[i] === '-' && pattern[i + 1] !== ']') {
        i++;
        const b = readAtom();
        if (typeof b === 'object') throw new Unsupported('範圍的終點是類別');
        ranges.push([a, b]);
      } else ranges.push([a, a]);
    }
    i++; // ]
    if (ranges.length === 0) throw new Unsupported('空的字元類別');
    return renderClass(flags.i && !ignoreCase ? foldCase(ranges) : ranges, negated);
  };

  const parseQuantifier = () => {
    const c = pattern[i];
    let q = '';
    if (c === '*' || c === '+' || c === '?') { q = c; i++; }
    else if (c === '{') {
      const m = /^\{(\d*)(,?)(\d*)\}/.exec(pattern.slice(i));
      if (!m || (m[1] === '' && m[3] === '')) return null;
      if (m[1] === '') throw new Unsupported('{,n} 量詞');
      q = m[0];
      i += m[0].length;
    } else return null;
    if (pattern[i] === '?') { q += '?'; i++; }
    if (pattern[i] === '+') throw new Unsupported('possessive 量詞');
    return q;
  };

  const parseSeq = (flags) => {
    let out = '';
    while (i < pattern.length) {
      const c = pattern[i];
      if (c === ')') return out;
      if (c === '|') { out += '|'; i++; continue; }
      let atom;
      if (c === '(') {
        if (pattern.startsWith('(?', i)) {
          const m = /^\(\?(P?<[A-Za-z_][A-Za-z0-9_]*>|[a-zA-Z]*(?:-[a-zA-Z]*)?[:)])/.exec(pattern.slice(i));
          if (!m) throw new Unsupported(`群組語法 ${pattern.slice(i, i + 6)}`);
          const tok = m[1];
          if (tok.endsWith('>')) {
            groups++;
            i += m[0].length;
            groupStarts.push(i + offset);
            atom = '(' + parseSeq({ ...flags }) + ')';
          } else {
            const body = tok.slice(0, -1);
            const [on, off = ''] = body.split('-');
            for (const f of on + off) if (!'is'.includes(f)) throw new Unsupported(`旗標 ${f}`);
            const next = { ...flags };
            for (const f of on) next[f] = true;
            for (const f of off) next[f] = false;
            i += m[0].length;
            if (tok.endsWith(')')) {
              // (?i) 這種：改變目前群組剩下部分的旗標。
              Object.assign(flags, next);
              continue;
            }
            if (ignoreCase && off.includes('i')) throw new Unsupported('(?-i) 出現在整條 ignoreCase 的規則裡');
            atom = '(?:' + parseSeq(next) + ')';
          }
        } else {
          groups++;
          i++;
          groupStarts.push(i + offset);
          atom = '(' + parseSeq({ ...flags }) + ')';
        }
        if (pattern[i] !== ')') throw new Unsupported('括號沒有結束');
        i++;
      } else if (c === '[') {
        atom = parseClass(flags);
      } else if (c === '\\') {
        const e = pattern[i + 1];
        i += 2;
        switch (e) {
          case 'd': atom = '[0-9]'; break;
          case 'D': atom = '[^0-9]'; break;
          case 'w': atom = '[A-Za-z0-9_]'; break;
          case 'W': atom = '[^A-Za-z0-9_]'; break;
          case 's': atom = renderClass(SPACE, false); break;
          case 'S': atom = renderClass(SPACE, true); break;
          case 'b': atom = '\\b'; break;
          case 'B': atom = '\\B'; break;
          case 'z': atom = '$'; break;
          case 'A': atom = '^'; break;
          case 'n': atom = '\\n'; break;
          case 'r': atom = '\\r'; break;
          case 't': atom = '\\t'; break;
          case 'f': atom = '\\f'; break;
          case 'x': {
            let v;
            if (pattern[i] === '{') {
              const end = pattern.indexOf('}', i);
              v = parseInt(pattern.slice(i + 1, end), 16);
              i = end + 1;
            } else {
              v = parseInt(pattern.slice(i, i + 2), 16);
              i += 2;
            }
            atom = renderClass([[v, v]], false);
            break;
          }
          default:
            if (/[A-Za-z0-9]/.test(e)) throw new Unsupported(`跳脫字元 \\${e}`);
            atom = '\\' + e;
        }
      } else if (c === '.') {
        atom = flags.s ? '[\\s\\S]' : '[^\\n]';
        i++;
      } else if (c === '^' || c === '$') {
        atom = c;
        i++;
      } else if (c === '*' || c === '+' || c === '?') {
        throw new Unsupported('量詞前面沒有東西');
      } else if (c === '{' || c === '}') {
        atom = '\\' + c;
        i++;
      } else {
        i++;
        if (flags.i && !ignoreCase && /[A-Za-z]/.test(c)) atom = `[${c.toUpperCase()}${c.toLowerCase()}]`;
        else atom = /[A-Za-z0-9 _\-:=,;'"`<>@#%&~!/]/.test(c) ? c : renderClass([[c.charCodeAt(0), c.charCodeAt(0)]], false);
      }
      const q = parseQuantifier();
      if (q !== null && (atom === '^' || atom === '$' || atom === '\\b' || atom === '\\B')) throw new Unsupported('錨點加量詞');
      out += atom + (q ?? '');
    }
    return out;
  };

  const flags = { i: ignoreCase, s: false };
  const regex = parseSeq(flags);
  if (i !== pattern.length) throw new Unsupported('多出來的右括號');
  return { regex, ignoreCase, groups, groupStarts };
}

// ---------- 規則轉換 ----------

// 拿掉開頭只用來包住變數名稱的 [\w.-]{0,50}?（見檔頭說明）。
const LEADING_NAME = '[\\w.-]{0,50}?';

const WORDS = {
  api: 'API', aws: 'AWS', gcp: 'GCP', pat: 'PAT', id: 'ID', url: 'URL', sdk: 'SDK', jwt: 'JWT',
  oauth: 'OAuth', github: 'GitHub', gitlab: 'GitLab', npm: 'npm', pypi: 'PyPI', ssh: 'SSH',
  dsn: 'DSN', smtp: 'SMTP', ai: 'AI', iam: 'IAM', ci: 'CI', cli: 'CLI', hmac: 'HMAC', rsa: 'RSA',
  scm: 'SCM', sso: 'SSO', jfrog: 'JFrog', openai: 'OpenAI', huggingface: 'Hugging Face',
  digitalocean: 'DigitalOcean', newrelic: 'New Relic', sendgrid: 'SendGrid', sendinblue: 'Sendinblue',
  mailchimp: 'Mailchimp', mailgun: 'Mailgun', linkedin: 'LinkedIn', youtube: 'YouTube',
  pagerduty: 'PagerDuty', planetscale: 'PlanetScale', rubygems: 'RubyGems', dropbox: 'Dropbox',
  hashicorp: 'HashiCorp', mongodb: 'MongoDB', postman: 'Postman', twilio: 'Twilio', vault: 'Vault',
  '1password': '1Password', key: 'key', token: 'token', secret: 'secret', access: 'access', client: 'client', password: 'password',
  personal: 'personal', private: 'private', refresh: 'refresh', service: 'service', account: 'account',
  webhook: 'webhook', app: 'app', admin: 'admin', user: 'user', live: 'live', test: 'test',
};

// 自動產生的名稱不好懂時改用這裡的。
const LABELS = {
  'npm-access-token': 'npm token',
};

export function labelFromId(id) {
  if (LABELS[id]) return LABELS[id];
  const parts = id.split('-');
  return parts.map((p, k) => {
    if (WORDS[p] !== undefined) return k === 0 && /^[a-z]/.test(WORDS[p]) ? WORDS[p][0].toUpperCase() + WORDS[p].slice(1) : WORDS[p];
    return k === 0 ? p[0].toUpperCase() + p.slice(1) : p;
  }).join(' ');
}

// 手寫規則（rules/api-keys.json）已經涵蓋，而且手寫的有更嚴的邊界或額外驗證。
const COVERED = {
  'github-pat': 'api-keys.json 的 github-token 已涵蓋（ghp_）',
  'github-oauth': 'api-keys.json 的 github-token 已涵蓋（gho_）',
  'github-app-token': 'api-keys.json 的 github-token 已涵蓋（ghu_、ghs_）',
  'github-refresh-token': 'api-keys.json 的 github-token 已涵蓋（ghr_）',
  'github-fine-grained-pat': 'api-keys.json 的 github-fine-grained-pat 已涵蓋',
  jwt: 'api-keys.json 的 jwt 已涵蓋，而且會驗 header',
  'private-key': 'api-keys.json 的 private-key-pem 已涵蓋；gitleaks 的版本往後掃到 END 行，沒有長度上限',
};

const SKIP = {
  'generic-api-key': '上下文＋亂度的通用規則由 rules/context.json（第 2 層）負責',
  'curl-auth-header': '[^\n]* 往後最多跨 6 行，在 JS 的回溯引擎上遇到一行裡很多個 curl 會變成 O(n²)；curl -H "Authorization: …" 由第 2 層的 context-authorization 負責',
  'sourcegraph-access-token': '其中一個分支是單獨的 40 位 hex，文字裡只要出現 sourcegraph 就會把 git commit SHA 當成 token（誤報樣本會擋）',
  'curl-auth-user': '同 curl-auth-header（O(n²)）；curl -u 帳號:密碼 目前不偵測',
};

// 不收 allowlist 裡長得像完整 key 的範例字串：純字面字串（沒有 regex 語法）而且長度 ≥ 20。
const isLiteralSample = (re) => re.length >= 20 && !/[\\[\](){}*+?|^$]/.test(re.replace(/\\\./g, ''));

function literalPrefixLength(src, start) {
  // 從 start 開始的字面字元數（遇到 regex 語法就停）。
  let k = start;
  let n = 0;
  while (k < src.length) {
    const c = src[k];
    if (c === '\\') {
      const e = src[k + 1];
      if (/[A-Za-z0-9]/.test(e)) break;
      k += 2; n++;
      continue;
    }
    if ('[](){}*+?|^$.'.includes(c)) break;
    k++; n++;
  }
  // 後面接量詞時，最後一個字不算前綴。
  if (n > 0 && /[*+?{]/.test(src[k] ?? '')) n--;
  return n;
}

function convertExclusions(allowlists, skippedNotes) {
  const exclude = [];
  const stopwords = [];
  for (const a of allowlists ?? []) {
    if (a.paths && (a.condition ?? 'OR').toUpperCase() === 'AND') continue; // 要同時符合路徑：剪貼簿沒有路徑，永遠不成立
    const target = a.regexTarget ?? 'secret';
    for (const re of a.regexes ?? []) {
      if (isLiteralSample(re)) { skippedNotes.push('allowlist 的完整 key 範例沒有收錄'); continue; }
      try {
        const c = convertRegex(re);
        exclude.push({ regex: c.regex, ...(c.ignoreCase ? { ignoreCase: true } : {}), ...(target !== 'secret' ? { target } : {}) });
      } catch (e) {
        if (!(e instanceof Unsupported)) throw e;
        skippedNotes.push(`allowlist regex 無法轉換（${e.message}）`);
      }
    }
    for (const w of a.stopwords ?? []) stopwords.push(w.toLowerCase());
  }
  return { exclude, stopwords };
}

export function convertConfig(toml, source) {
  const rules = [];
  const skipped = [];
  for (const r of toml.rules) {
    const skip = (reason) => skipped.push({ id: r.id, reason });
    if (SKIP[r.id]) { skip(SKIP[r.id]); continue; }
    if (COVERED[r.id]) { skip(COVERED[r.id]); continue; }
    if (!r.regex) { skip('只比對檔名（path），剪貼簿沒有檔名'); continue; }
    if (r.path) { skip('只在特定檔案類型（path）才成立，剪貼簿沒有檔名，套用到所有文字誤報太高'); continue; }
    if (/-client-id$/.test(r.id)) { skip('client ID 是公開的識別碼，不是機密'); continue; }
    if (!r.keywords?.length) { skip('沒有 keywords，無法預先篩選，每段文字都要跑'); continue; }

    let regex = r.regex;
    // 去掉 (?i) 後面或最前面的變數名稱前綴。
    // 有些規則寫成 [\w.-]{0,50}?(?i:[\w.-]{0,50}?…)：兩層都拿掉（群組裡沒有最上層的 |，結果相同）。
    if (regex.startsWith(LEADING_NAME + '(?i:' + LEADING_NAME)) regex = '(?i:' + regex.slice(2 * LEADING_NAME.length + 4);
    else if (regex.startsWith('(?i)' + LEADING_NAME)) { regex = '(?i)' + regex.slice(4 + LEADING_NAME.length); }
    else if (regex.startsWith(LEADING_NAME)) { regex = regex.slice(LEADING_NAME.length); }

    let c;
    try {
      c = convertRegex(regex);
    } catch (e) {
      if (!(e instanceof Unsupported)) throw e;
      skip(`regex 無法轉成 .NET 與 JS 共用的語法：${e.message}`);
      continue;
    }

    const notes = [];
    const { exclude, stopwords } = convertExclusions(r.allowlists, notes);
    const secretGroup = r.secretGroup ?? undefined;
    const groupIndex = secretGroup ?? (c.groups > 0 ? 1 : 0);
    // 遮罩保留的前綴：機密開頭的字面字串（例如 LTAI、sk-ant-admin01-），本身不是機密。
    let start = groupIndex > 0 ? c.groupStarts[groupIndex - 1] : 0;
    if (groupIndex === 0 && regex.startsWith('\\b')) start = 2;
    const keepStart = Math.min(16, literalPrefixLength(regex, start));

    const rule = {
      id: `gitleaks.${r.id}`,
      kind: 'api-key',
      label: labelFromId(r.id),
      regex: c.regex,
      ...(c.ignoreCase ? { ignoreCase: true } : {}),
      ...(secretGroup !== undefined ? { secretGroup } : {}),
      keywords: [...new Set(r.keywords.map((k) => k.toLowerCase()))],
      ...(r.entropy ? { entropy: r.entropy } : {}),
      ...(exclude.length ? { exclude } : {}),
      ...(stopwords.length ? { stopwords } : {}),
      mask: { keepStart },
    };
    if (notes.length) rule.notes = [...new Set(notes)];
    rules.push(rule);
  }

  const global = convertExclusions([toml.allowlist], []);
  return {
    format: 1,
    name: 'gitleaks',
    priority: 20,
    description: '由 tools/convert-gitleaks.mjs 從 gitleaks 預設規則轉換產生，不要手動修改。授權見 THIRD_PARTY_NOTICES.md。',
    source: { project: 'https://github.com/gitleaks/gitleaks', file: 'config/gitleaks.toml', license: 'MIT', ...source },
    exclude: global.exclude,
    stopwords: global.stopwords,
    skipped,
    rules,
  };
}

// ---------- 主程式 ----------

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [tomlPath, version, commit] = process.argv.slice(2);
  if (!tomlPath || !version || !commit) {
    console.error('用法：node tools/convert-gitleaks.mjs <gitleaks.toml> <版本> <commit SHA>');
    process.exit(2);
  }
  const toml = parseToml(readFileSync(tomlPath, 'utf8'));
  const out = convertConfig(toml, { version, commit });
  // 兩邊的 regex 引擎都要能編譯；JS 這邊先檢查一次。
  for (const r of out.rules) new RegExp(r.regex, r.ignoreCase ? 'gi' : 'g');
  const target = join(dirname(fileURLToPath(import.meta.url)), '..', 'rules', 'gitleaks.json');
  writeFileSync(target, JSON.stringify(out, null, 2) + '\n');
  console.log(`收錄 ${out.rules.length} 條，略過 ${out.skipped.length} 條 → ${target}`);
}
