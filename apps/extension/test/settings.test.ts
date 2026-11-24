import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SETTINGS,
  engineSettings,
  isAllowlisted,
  isBlockRecord,
  normalizeHost,
  normalizeSettings,
  packsForLanguages,
} from '../src/lib/settings';
import { resolveLocale, translator } from '../src/lib/strings';

describe('PII packs from navigator.languages (detection-rules §5.6)', () => {
  it('maps regions, ja/ko without a region, union of all languages', () => {
    expect(packsForLanguages(['zh-TW'])).toEqual(['universal', 'tw']);
    expect(packsForLanguages(['zh-TW', 'en-US'])).toEqual(['universal', 'tw', 'us']);
    expect(packsForLanguages(['zh-Hant-HK'])).toEqual(['universal', 'hk']);
    expect(packsForLanguages(['zh_CN'])).toEqual(['universal', 'cn']);
    expect(packsForLanguages(['ja', 'ko'])).toEqual(['universal', 'jp', 'kr']);
    expect(packsForLanguages(['en', 'zh', 'fr-FR'])).toEqual(['universal']);
    expect(packsForLanguages(undefined)).toEqual(['universal']);
  });

  it('auto (null) follows the languages, an explicit list wins', () => {
    expect(engineSettings(DEFAULT_SETTINGS, ['en-SG']).packs).toEqual(['universal', 'sg']);
    const s = normalizeSettings({ packs: ['jp'] });
    expect(s.packs).toEqual(['universal', 'jp']);
    expect(engineSettings(s, ['zh-TW']).packs).toEqual(['universal', 'jp']);
  });
});

describe('settings', () => {
  it('fills defaults (strict) and drops junk', () => {
    expect(normalizeSettings(undefined)).toEqual(DEFAULT_SETTINGS);
    const s = normalizeSettings({
      enabled: 'yes',
      detect_secrets: false,
      packs: ['tw', 'xx', 3],
      locale: 'fr',
      theme: 'dark',
      allowlist: ['HTTPS://Intra.Example.com/path', 'bad host', 7, 'a.example', 'a.example'],
    });
    expect(s.enabled).toBe(true);
    expect(s.detect_secrets).toBe(false);
    expect(s.packs).toEqual(['universal', 'tw']);
    expect(s.locale).toBe('system');
    expect(s.theme).toBe('dark');
    expect(s.allowlist).toEqual(['intra.example.com', 'a.example']);
  });

  it('never turns AI on', () => {
    expect(engineSettings(DEFAULT_SETTINGS, []).ai.explain_commands).toBe(false);
  });

  it('allowlist covers subdomains, not look-alikes', () => {
    expect(isAllowlisted('intra.example.com', ['example.com'])).toBe(true);
    expect(isAllowlisted('example.com', ['example.com'])).toBe(true);
    expect(isAllowlisted('badexample.com', ['example.com'])).toBe(false);
    expect(isAllowlisted('example.com.evil.invalid', ['example.com'])).toBe(false);
    expect(isAllowlisted('', ['example.com'])).toBe(false);
  });

  it('normalizes typed hostnames', () => {
    expect(normalizeHost(' *.Example.COM ')).toBe('example.com');
    expect(normalizeHost('http://localhost:8080/x')).toBe('localhost');
    expect(normalizeHost('example.com/path')).toBe('example.com');
    expect(normalizeHost('ex ample.com')).toBe('');
    expect(normalizeHost('..')).toBe('');
  });

  it('block records carry no clipboard text fields', () => {
    expect(isBlockRecord({ domain: 'a', time: 1, kind: 'command', masked: '' })).toBe(true);
    expect(isBlockRecord({ domain: 'a', time: 1, kind: 'other', masked: '' })).toBe(false);
  });
});

describe('strings', () => {
  it('system locale follows the browser languages; manual choice wins', () => {
    expect(resolveLocale('system', ['zh-HK'])).toBe('zh-TW');
    expect(resolveLocale('system', ['de-DE', 'en'])).toBe('en');
    expect(resolveLocale('en', ['zh-TW'])).toBe('en');
  });

  it('has every ui-ext string in both languages', () => {
    const en = translator('en');
    const zh = translator('zh-TW');
    for (const id of [
      'ui-ext-clipboard-notice',
      'ui-ext-toast-warn-title',
      'ui-ext-popup-status-on',
    ]) {
      expect(en(id)).not.toBe(id);
      expect(zh(id)).not.toBe(id);
      expect(zh(id)).not.toBe(en(id));
    }
    expect(en('ui-ext-popup-page-stats', { blocked: 2, warned: 1 })).toContain('2');
  });
});
