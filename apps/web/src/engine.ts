// Lazy engine loader. The page renders (with a skeleton) before any of this is fetched; the
// engine and the BIP-39 list arrive together so nothing is fetched again while analyzing.
//
// `init()` picks WebAssembly and falls back to the wasm2js build by itself when WebAssembly is
// missing or blocked (docs/integrations/wasm.md). `?engine=wasm2js` forces the fallback, for
// testing it on browsers that do support WebAssembly.

export type Core = typeof import('@paste-warden/core');

export interface LoadedEngine {
  core: Core;
  wordlist: readonly string[];
}

let pending: Promise<LoadedEngine> | undefined;

function requestedBackend(): 'auto' | 'wasm2js' {
  try {
    return new URLSearchParams(globalThis.location?.search).get('engine') === 'wasm2js'
      ? 'wasm2js'
      : 'auto';
  } catch {
    return 'auto';
  }
}

export function loadEngine(): Promise<LoadedEngine> {
  pending ??= Promise.all([import('@paste-warden/core'), import('./lib/wordlist')])
    .then(async ([core, words]) => {
      await core.init({ backend: requestedBackend() });
      // The first analyze compiles the rule set (~50 ms); pay that while the skeleton is up.
      core.analyze('warm-up', { locale: 'en' });
      return { core, wordlist: words.BIP39_ENGLISH };
    })
    .catch((err: unknown) => {
      pending = undefined;
      throw err;
    });
  return pending;
}
