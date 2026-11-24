// Loads @paste-warden/core in the isolated content script.
//
// WASM is the main path (S2: the isolated world isn't bound by the page CSP). If instantiating
// fails anyway, the wasm2js build is imported on demand from a separate web-accessible module,
// so its ~6 MB never ride along on every page.
import { analyze, backend, init, mask } from '@paste-warden/core';
import type { EngineApi } from './guard';

interface CoreModule {
  init(o: { backend: 'wasm2js' }): Promise<void>;
  analyze: EngineApi['analyze'];
  mask: EngineApi['mask'];
}

export async function loadEngine(wasmUrl: string, wasm2jsUrl: string | null): Promise<EngineApi> {
  try {
    await init({ backend: 'wasm', wasm: wasmUrl });
    return { backend: backend() ?? 'wasm', analyze, mask };
  } catch (wasmError) {
    if (!wasm2jsUrl) throw wasmError;
    const core = (await import(/* @vite-ignore */ wasm2jsUrl)) as CoreModule;
    await core.init({ backend: 'wasm2js' });
    return { backend: 'wasm2js', analyze: core.analyze, mask: core.mask };
  }
}
