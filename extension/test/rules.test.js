// 共用規則檔（rules/*.json，#26）：產生的檔案是否最新、三層偵測、誤報樣本、效能。
// 像 key 的樣本一律在執行時用固定種子的亂數產生（與 C# 的 SecretRulesTests 相同），不把完整的 key 寫進檔案。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { RULES, scanRule, asciiView } from '../lib/rules.js';
import { findSecrets, maskText, PEM_BODY_MASK } from '../lib/secrets.js';
import { render, OUTPUT } from '../../tools/build-extension-rules.mjs';
import { convertRegex } from '../../tools/convert-gitleaks.mjs';

const here = dirname(fileURLToPath(import.meta.url));

// ---------- 測試資料產生（與 C# 的 Gen 相同） ----------

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';
const LOWER = 'abcdefghijklmnopqrstuvwxyz0123456789';

function gen(seed) {
  let state = seed;
  return (charset, length) => {
    let s = '';
    for (let i = 0; i < length; i++) {
      state = (Math.imul(state, 1103515245) + 12345) & 0x7fffffff;
      s += charset[(state >>> 8) % charset.length];
    }
    return s;
  };
}

const apiKeys = (text) => findSecrets(text).filter((f) => f.type === 'api-key');

// ---------- 產生的檔案、載入 ----------

test('rules.generated.js 是最新的（改了 rules/ 要執行 node tools/build-extension-rules.mjs）', () => {
  const actual = readFileSync(OUTPUT, 'utf8').replace(/\r\n/g, '\n');
  assert.equal(actual, render());
});

test('規則都編譯得起來、id 不重複、順序與 C# 相同', () => {
  assert.ok(RULES.length > 200, `${RULES.length}`);
  assert.equal(new Set(RULES.map((r) => r.id)).size, RULES.length);
  assert.equal(RULES[0].id, 'jwt');
  assert.match(RULES[RULES.length - 1].id, /^context-/);
  for (const r of RULES) for (const k of r.keywords) assert.equal(k, k.toLowerCase(), r.id);
});

test('ASCII 版本長度不變', () => {
  const t = '金鑰ghp_x😀y';
  assert.equal(asciiView(t), '\x1a\x1aghp_x\x1a\x1ay');
});

test('$ 只在整段結尾成立', () => {
  const rule = RULES.find((r) => r.id === 'gitleaks.digitalocean-pat');
  const key = `dop_v1_${gen(7)(HEX, 64)}`;
  assert.equal([...scanRule(rule, key, key)].length, 1);
});

// ---------- RE2 轉換 ----------

test('convert-gitleaks：RE2 語法轉成兩邊都一樣的子集合', () => {
  assert.deepEqual(convertRegex('(?i)abc').regex, 'abc');
  assert.equal(convertRegex('(?i)abc').ignoreCase, true);
  assert.equal(convertRegex('x(?i)ab').regex, 'x[Aa][Bb]');
  assert.equal(convertRegex('(?i)a(?-i:B)c').regex, '[Aa](?:B)[Cc]');
  assert.equal(convertRegex('\\w\\d\\s.').regex, '[A-Za-z0-9_][0-9][\\t\\n\\f\\r ][^\\n]');
  assert.equal(convertRegex('(?s:.)').regex, '(?:[\\s\\S])');
  assert.equal(convertRegex('[[:alnum:]]').regex, '[0-9A-Za-z]');
  assert.equal(convertRegex('(?P<x>a)(b)').groups, 2);
  assert.equal(convertRegex('\\x60\\z').regex, '[`]$');
  assert.throws(() => convertRegex('\\pL'));
  assert.throws(() => convertRegex('[\\S-]'));
});

// ---------- 第 1 層 ----------

test('gitleaks 規則（與 C# 相同的樣本）', () => {
  const g = gen(26);
  const samples = [
    [`shpat_${g(HEX, 32)}`, 'Shopify access token'],
    [`dop_v1_${g(HEX, 64)}`, 'DigitalOcean PAT'],
    [`lin_api_${g(ALNUM, 40)}`, 'Linear API key'],
    [`pplx-${g(ALNUM, 48)}`, 'Perplexity API key'],
    [`PMAK-${g(HEX, 24)}-${g(HEX, 34)}`, 'Postman API token'],
    [`SK${g(HEX, 32)}`, 'Twilio API key'],
    [`ADAFRUIT_IO_KEY=${g(LOWER, 32)}`, 'Adafruit API key'],
  ];
  for (const [sample, label] of samples) {
    const found = apiKeys(`config:\n  ${sample}\n`);
    assert.equal(found.length, 1, sample);
    assert.equal(found[0].label, label, sample);
    const secret = sample.slice(sample.indexOf('=') + 1);
    assert.ok(!maskText(sample).includes(secret), sample);
  }
});

test('手寫規則排在 gitleaks 前面', () => {
  const key = `sk-ant-api03-${gen(3)(ALNUM, 93)}AA`;
  assert.equal(apiKeys(key)[0].label, 'Anthropic API key');
});

test('中文緊貼著 key 也找得到', () => {
  const key = `dop_v1_${gen(7)(HEX, 64)}`;
  assert.deepEqual(apiKeys(`金鑰${key} 請保管`).map((f) => f.label), ['DigitalOcean PAT']);
});

test('PEM：通知顯示標頭，貼遮罩版遮到 END 行（以前只有桌面版有）', () => {
  const body = gen(5)(ALNUM, 64);
  const text = `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}\n-----END OPENSSH PRIVATE KEY-----\nafter`;
  const f = apiKeys(text);
  assert.deepEqual(f.map((x) => x.label), ['私鑰（PEM）']);
  const masked = maskText(text);
  assert.ok(!masked.includes(body));
  assert.ok(masked.includes(PEM_BODY_MASK));
  assert.ok(masked.endsWith('-----END OPENSSH PRIVATE KEY-----\nafter'));
});

// ---------- 第 2 層 ----------

test('上下文加亂度：.env、curl、JSON、YAML 等（與 C# 相同的樣本）', () => {
  const g = gen(2026);
  const R = (n) => g(ALNUM, n);
  const samples = [
    [`# .env\nAPI_KEY=${R(32)}\nDEBUG=false\n`, '疑似金鑰或密碼'],
    [`DB_PASSWORD="${R(20)}"\n`, '疑似金鑰或密碼'],
    [`curl -H "Authorization: Bearer ${R(40)}" https://api.example.invalid/v1/items`, 'Authorization 權杖'],
    [`curl -H 'X-API-Key: ${R(32)}' https://api.example.invalid/`, '疑似金鑰或密碼'],
    [`{"name": "demo", "apiKey": "${R(32)}"}`, '疑似金鑰或密碼'],
    [`secret_key: ${g(HEX, 40)}\n`, '疑似金鑰或密碼'],
    [`api_key = "${g(LOWER, 32)}"`, '疑似金鑰或密碼'],
    [`$env:SERVICE_TOKEN = "${R(24)}"`, '疑似金鑰或密碼'],
    [`client_secret=${R(16)}&grant_type=client_credentials`, '疑似金鑰或密碼'],
  ];
  for (const [text, label] of samples) {
    const f = apiKeys(text);
    assert.equal(f.length, 1, text);
    assert.equal(f[0].label, label, text);
    const secret = text.slice(f[0].start, f[0].end);
    assert.ok(secret.length >= 16);
    assert.ok(!maskText(text).includes(secret), text);
  }
});

test('有明確的金鑰名稱時 UUID 和 SHA 也算；沒有或名稱是 id、commit 不算', () => {
  assert.equal(apiKeys('token: 9f1b6c2e-4d3a-4b8e-a1f0-7c2d5e6f8a9b').length, 1);
  assert.equal(apiKeys('secret=3f2a9c1e7b4d6a8f0e2c5b9d1a3e7f6c4b8d2a0e').length, 1);
  assert.deepEqual(apiKeys('id: 9f1b6c2e-4d3a-4b8e-a1f0-7c2d5e6f8a9b'), []);
  assert.deepEqual(apiKeys('token_id: 9f1b6c2e-4d3a-4b8e-a1f0-7c2d5e6f8a9b'), []);
  assert.deepEqual(apiKeys('commit: 3f2a9c1e7b4d6a8f0e2c5b9d1a3e7f6c4b8d2a0e'), []);
});

test('上下文加亂度：不算的情況', () => {
  for (const t of ['secret=Ab1Ab1Ab1Ab1Ab1Ab1', 'token=accessTokenFromStorage', 'password=short1',
    'api_key=1234567890123456789', 'token = GetToken()', 'password = input()']) {
    assert.deepEqual(apiKeys(t), [], t);
  }
});

// ---------- 誤報樣本（與 C# 共用） ----------

test('誤報樣本：hash、UUID、git SHA、Base64 圖片、程式碼、lockfile、minified JS 都不算', () => {
  const fixture = JSON.parse(readFileSync(join(here, '..', '..', 'tests', 'fixtures', 'secret-false-positives.json'), 'utf8'));
  for (const s of fixture.samples) {
    const f = apiKeys(s.text);
    assert.deepEqual(f.map((x) => `${x.label} ${x.value}`), [], s.name);
  }
});

// ---------- 效能 ----------

const N = 1 << 20;
const fill = (unit, n = N) => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);

test('每條規則在 1 Mi 病態輸入上都是線性時間', () => {
  let worst = [0, '', -1];
  let total = 0;
  for (const r of RULES) {
    const kw = r.keywords[0] || 'key';
    const inputs = [fill(`${kw} `), fill(`${kw}=`), fill(`${kw} = "`), fill(`${kw}${'a'.repeat(40)} `), kw + 'a'.repeat(N - kw.length)];
    inputs.forEach((input, i) => {
      const t = performance.now();
      for (const _ of scanRule(r, input, input)); // eslint-disable-line no-unused-vars
      const ms = performance.now() - t;
      total += ms;
      if (ms > worst[0]) worst = [ms, r.id, i];
    });
  }
  console.log(`${RULES.length} 條規則 × 5 種輸入：合計 ${total.toFixed(0)} ms，最慢 ${worst[0].toFixed(0)} ms（${worst[1]}，輸入 ${worst[2]}）`);
  assert.ok(worst[0] < 500, `${worst[1]} took ${worst[0]} ms`);
});

test('所有關鍵字都出現時 1 Mi 也不會卡住', () => {
  const kws = [...new Set(RULES.flatMap((r) => r.keywords))];
  const cases = [
    ['所有關鍵字', fill(kws.join(' = "') + ` = "${gen(9)(ALNUM, 40)}"\n`)],
    ['滿滿的 .env', fill(`API_TOKEN=${gen(1)(ALNUM, 32)}\n`)],
    ['滿滿的 Authorization', fill('Authorization: Bearer ')],
    ['minified 單行', fill('var token=e.token,secret=t.secret||"",apiKey=null;')],
  ];
  for (const [name, text] of cases) {
    const t = performance.now();
    const found = findSecrets(text);
    const ms = performance.now() - t;
    console.log(`${name}: ${text.length} 字，${found.length} 筆，${ms.toFixed(0)} ms`);
    assert.ok(ms < 3000, `${name} took ${ms} ms`);
  }
});
