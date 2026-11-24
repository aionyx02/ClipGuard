// @vitest-environment node
// The examples against the real engine (@paste-warden/core, WASM build loaded from dist/), so a
// rule change that silently breaks a playground example fails here, not in front of a visitor.
import * as core from '@paste-warden/core';
import { beforeAll, describe, expect, it } from 'vitest';
import { analyzeText, showOnion } from '../src/lib/analysis';
import { buildExample, type ExampleId } from '../src/lib/samples';
import { BIP39_ENGLISH } from '../src/lib/wordlist';

beforeAll(async () => {
  await core.init();
});

const run = (id: ExampleId, locale: 'zh-TW' | 'en' = 'en') =>
  analyzeText(core, buildExample(id, locale, BIP39_ENGLISH), locale);

describe.each(['zh-TW', 'en'] as const)('examples (%s)', (locale) => {
  it('ClickFix is quarantined and names the download host', () => {
    const { report } = run('clickfix', locale);
    expect(report.action).toBe('quarantine');
    expect(report.command.level).toBe('malicious');
    expect(report.command.hosts).toContain('example.invalid');
    expect(showOnion(report)).toBe(true);
  });

  it('the obfuscated variant peels into at least 3 onion layers', () => {
    const { report } = run('obfuscated', locale);
    expect(report.action).toBe('quarantine');
    const kinds = report.command.trace.map((s) => s.kind);
    expect(kinds.length).toBeGreaterThanOrEqual(3);
    expect(kinds).toEqual(expect.arrayContaining(['caret', 'encoded_command', 'concat']));
    expect(report.command.trace.at(-1)?.preview).toContain('example.invalid');
  });

  it('fake PII is found and masked', () => {
    const text = buildExample('pii', locale, BIP39_ENGLISH);
    const { report, masked } = analyzeText(core, text, locale);
    const kinds = report.secrets.map((s) => s.kind);
    expect(kinds).toEqual(expect.arrayContaining(['national_id', 'mobile_phone', 'credit_card']));
    expect(masked).toBeDefined();
    for (const s of report.secrets) {
      const [start, length] = s.span_utf16;
      const plain = text.slice(start, start + length);
      expect(plain.length).toBe(length);
      expect(masked).not.toContain(plain);
      expect(JSON.stringify(report)).not.toContain(plain);
    }
  });

  it('the runtime API key is found; the report and the masked text never hold it', () => {
    const text = buildExample('apikey', locale, BIP39_ENGLISH);
    const token = text.match(/ghp_\w+/)?.[0] as string;
    const { report, masked } = analyzeText(core, text, locale);
    expect(report.secrets.map((s) => s.kind)).toEqual(['api_key']);
    expect(JSON.stringify(report)).not.toContain(token);
    expect(masked).not.toContain(token);
  });

  it('seed phrase: valid checksum → mnemonic; broken checksum → nothing', () => {
    expect(run('seed-valid', locale).report.secrets.map((s) => s.kind)).toEqual(['mnemonic']);
    const bad = run('seed-invalid', locale).report;
    expect(bad.secrets).toEqual([]);
    expect(bad.action).toBe('allow');
  });

  it('ordinary text is allowed without an onion view', () => {
    const { report, masked } = run('clean', locale);
    expect(report.action).toBe('allow');
    expect(masked).toBeUndefined();
    expect(showOnion(report)).toBe(false);
  });
});

it('reasons come back in the requested language', () => {
  const zh = run('clickfix', 'zh-TW').report.command.reasons[0]?.text ?? '';
  const en = run('clickfix', 'en').report.command.reasons[0]?.text ?? '';
  expect(zh).not.toBe(en);
  expect(en).toMatch(/[a-z]/i);
});
