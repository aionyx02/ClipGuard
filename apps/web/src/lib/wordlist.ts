// The engine's own BIP-39 English list (rules/secret/bip39-english.txt), inlined at build time.
// Loaded together with the engine (engine.ts) so picking an example never fetches anything.
import raw from '../../../../rules/secret/bip39-english.txt?raw';

export const BIP39_ENGLISH: readonly string[] = raw.split(/\r?\n/).filter((w) => w.length > 0);
