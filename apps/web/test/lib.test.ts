import { LOCALE_STORAGE_KEY, localPreferenceStore } from '@paste-warden/ui';
import { describe, expect, it } from 'vitest';
import { demoMnemonics, entropyToMnemonic, isValidMnemonic } from '../src/lib/bip39';
import { parseLang, urlLocaleStore, withLang } from '../src/lib/lang';
import { docsUrl } from '../src/lib/links';
import {
  buildExample,
  EXAMPLE_IDS,
  encodePowerShell,
  fakeToken,
  isLuhnValid,
  luhn,
  twNationalId,
} from '../src/lib/samples';
import { sha256, toHex } from '../src/lib/sha256';
import { BIP39_ENGLISH } from '../src/lib/wordlist';

describe('sha256', () => {
  it('matches the FIPS 180-4 test vectors', () => {
    expect(toHex(sha256(''))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(toHex(sha256('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(toHex(sha256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))).toBe(
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    );
    expect(toHex(sha256('a'.repeat(1000)))).toBe(
      '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3',
    );
  });
});

describe('bip39', () => {
  it('loads the 2048-word list', () => {
    expect(BIP39_ENGLISH).toHaveLength(2048);
    expect(BIP39_ENGLISH[0]).toBe('abandon');
    expect(BIP39_ENGLISH[2047]).toBe('zoo');
  });

  it('reproduces the official BIP-39 vectors', () => {
    const zero = new Uint8Array(16);
    expect(entropyToMnemonic(zero, BIP39_ENGLISH).join(' ')).toBe(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    );
    const ff = new Uint8Array(16).fill(0xff);
    expect(entropyToMnemonic(ff, BIP39_ENGLISH).join(' ')).toBe(
      'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
    );
    const sevenF = new Uint8Array(32).fill(0x7f);
    expect(entropyToMnemonic(sevenF, BIP39_ENGLISH).at(-1)).toBe('title');
  });

  it('demo phrases: same first 11 words, only one has a valid checksum', () => {
    const { valid, invalid } = demoMnemonics(BIP39_ENGLISH);
    const v = valid.split(' ');
    const i = invalid.split(' ');
    expect(v).toHaveLength(12);
    expect(i.slice(0, 11)).toEqual(v.slice(0, 11));
    expect(i[11]).not.toBe(v[11]);
    expect(isValidMnemonic(v, BIP39_ENGLISH)).toBe(true);
    expect(isValidMnemonic(i, BIP39_ENGLISH)).toBe(false);
  });

  it('rejects unknown words and wrong lengths', () => {
    expect(isValidMnemonic(['abandon'], BIP39_ENGLISH)).toBe(false);
    expect(isValidMnemonic(Array(12).fill('notaword'), BIP39_ENGLISH)).toBe(false);
  });
});

describe('fake data generators', () => {
  it('Taiwan national ID check digit', () => {
    // Published worked example: A123456789.
    expect(twNationalId('A12345678')).toBe('A123456789');
    expect(() => twNationalId('A32345678')).toThrow();
  });

  it('Luhn', () => {
    expect(luhn('411111111111111')).toBe('4111111111111111');
    expect(isLuhnValid(luhn('400000123456789'))).toBe(true);
    expect(isLuhnValid('4111 1111 1111 1111')).toBe(true);
    expect(isLuhnValid('4111 1111 1111 1112')).toBe(false);
  });

  it('seeded token is stable and alphanumeric', () => {
    expect(fakeToken(1, 36)).toBe(fakeToken(1, 36));
    expect(fakeToken(1, 36)).not.toBe(fakeToken(2, 36));
    expect(fakeToken(1, 36)).toMatch(/^[A-Za-z0-9]{36}$/);
  });

  it('-EncodedCommand is Base64 of UTF-16LE', () => {
    expect(encodePowerShell('ab')).toBe('YQBiAA==');
  });

  it('every example builds in both languages; commands are defanged', () => {
    for (const locale of ['zh-TW', 'en'] as const) {
      for (const id of EXAMPLE_IDS) {
        const text = buildExample(id, locale, BIP39_ENGLISH);
        expect(text.length).toBeGreaterThan(10);
        for (const url of text.match(/https?:\/\/[^\s/'"]+/g) ?? []) {
          expect(url).toMatch(/example\.invalid$/);
        }
      }
    }
  });
});

describe('?lang=', () => {
  it('parses loose values', () => {
    expect(parseLang('en')).toBe('en');
    expect(parseLang('EN-us')).toBe('en');
    expect(parseLang('zh')).toBe('zh-TW');
    expect(parseLang('zh-Hant')).toBe('zh-TW');
    expect(parseLang('fr')).toBeUndefined();
    expect(parseLang(null)).toBeUndefined();
  });

  it('rewrites only the lang parameter', () => {
    expect(withLang('https://x.test/a/?q=1#d', 'en')).toBe('https://x.test/a/?q=1&lang=en#d');
    expect(withLang('https://x.test/?lang=en', 'system')).toBe('https://x.test/');
  });

  it('the URL wins over storage and is written back on change', () => {
    localStorage.setItem(LOCALE_STORAGE_KEY, 'zh-TW');
    window.history.replaceState(null, '', '/?lang=en');
    const store = urlLocaleStore(localPreferenceStore);
    expect(store.get(LOCALE_STORAGE_KEY)).toBe('en');
    store.set(LOCALE_STORAGE_KEY, 'zh-TW');
    expect(window.location.search).toBe('?lang=zh-TW');
    expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('zh-TW');
    store.set(LOCALE_STORAGE_KEY, 'system');
    expect(window.location.search).toBe('');
    // Other keys pass straight through.
    store.set('paste-warden:theme', 'dark');
    expect(store.get('paste-warden:theme')).toBe('dark');
    expect(window.location.search).toBe('');
  });
});

describe('docs links', () => {
  it('are relative and per language', () => {
    expect(docsUrl('zh-TW', 'user/install/firefox/')).toBe('./docs/user/install/firefox/');
    expect(docsUrl('en', '/user/install/firefox/')).toBe('./docs/en/user/install/firefox/');
  });
});
