// BIP-39 test vectors generated on the page — never a real wallet. The entropy is SHA-256 of a
// public label, so anyone can reproduce (and nobody should fund) these phrases.
import { sha256 } from './sha256';

/** Entropy → mnemonic (BIP-39: entropy bits + SHA-256 checksum bits, split into 11-bit indices). */
export function entropyToMnemonic(entropy: Uint8Array, wordlist: readonly string[]): string[] {
  if (wordlist.length !== 2048) throw new Error('BIP-39 word list must have 2048 words');
  const ent = entropy.length * 8;
  if (ent < 128 || ent > 256 || ent % 32 !== 0) throw new Error('entropy must be 16–32 bytes');
  const csBits = ent / 32;
  const hash = sha256(entropy);
  let bits = '';
  for (const b of entropy) bits += b.toString(2).padStart(8, '0');
  bits += (hash[0] as number).toString(2).padStart(8, '0').slice(0, csBits);
  const words: string[] = [];
  for (let i = 0; i < bits.length; i += 11) {
    words.push(wordlist[Number.parseInt(bits.slice(i, i + 11), 2)] as string);
  }
  return words;
}

/** True when the words are all in the list and the checksum matches. */
export function isValidMnemonic(words: readonly string[], wordlist: readonly string[]): boolean {
  if (![12, 15, 18, 21, 24].includes(words.length)) return false;
  const index = new Map(wordlist.map((w, i) => [w, i]));
  let bits = '';
  for (const w of words) {
    const i = index.get(w);
    if (i === undefined) return false;
    bits += i.toString(2).padStart(11, '0');
  }
  const csBits = words.length / 3;
  const entBits = bits.length - csBits;
  const entropy = new Uint8Array(entBits / 8);
  for (let i = 0; i < entropy.length; i++) {
    entropy[i] = Number.parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  const want = (sha256(entropy)[0] as number).toString(2).padStart(8, '0').slice(0, csBits);
  return bits.slice(entBits) === want;
}

export const DEMO_ENTROPY_LABEL = 'paste-warden playground bip39 demo (not a wallet)';

/**
 * Two 12-word phrases that differ only in the last word: `valid` has a correct checksum (the
 * engine flags it as a seed phrase), `invalid` does not (the engine must stay quiet: it is just
 * a list of English words).
 */
export function demoMnemonics(wordlist: readonly string[]): { valid: string; invalid: string } {
  const entropy = sha256(DEMO_ENTROPY_LABEL).slice(0, 16);
  const words = entropyToMnemonic(entropy, wordlist);
  const index = new Map(wordlist.map((w, i) => [w, i]));
  const last = index.get(words[11] as string) as number;
  // The low 4 bits of the last word are the checksum: flipping one always breaks it.
  const broken = [...words.slice(0, 11), wordlist[last ^ 1] as string];
  return { valid: words.join(' '), invalid: broken.join(' ') };
}
