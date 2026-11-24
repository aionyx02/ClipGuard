// The two engine builds behind one string-in / string-out interface.
//
// - wasm: wasm-bindgen `--target web` output in ./wasm/ (main build).
// - wasm2js: binaryen wasm2js of the `raw-abi` build in ./wasm2js/ (fallback; S2:
//   wasm-bindgen's externref output cannot be converted, so the fallback talks
//   to the C ABI of crates/wasm/src/raw.rs directly).

import type { Backend } from './types.js';

export interface Engine {
  kind: Backend;
  analyze(text: string, optsJson: string): string;
  mask(text: string, reportJson: string, locale: string): string;
  messages(locale: string): string;
  deobfuscate(text: string, locale: string): string;
  version(): string;
}

type WasmSource = URL | string | Response | BufferSource | WebAssembly.Module;

export async function loadWasm(source?: WasmSource): Promise<Engine> {
  const glue = await import('./wasm/paste_warden.js');
  let input: WasmSource = source ?? new URL('./wasm/paste_warden_bg.wasm', import.meta.url);
  if (input instanceof URL && input.protocol === 'file:') {
    // Node: fetch() cannot read file: URLs. Hidden from bundlers on purpose.
    const fsModule = 'node:fs/promises';
    const fs = (await import(/* @vite-ignore */ /* webpackIgnore: true */ fsModule)) as {
      readFile(u: URL): Promise<Uint8Array>;
    };
    input = await fs.readFile(input);
  }
  await glue.default({ module_or_path: input });
  return {
    kind: 'wasm',
    analyze: glue.analyze,
    mask: glue.mask,
    messages: glue.messages,
    deobfuscate: glue.deobfuscate,
    version: glue.engine_version,
  };
}

/** Exports of the raw C ABI (crates/wasm/src/raw.rs). */
interface RawExports {
  memory: { buffer: ArrayBuffer };
  pw_alloc(len: number): number;
  pw_free(ptr: number, len: number): void;
  pw_analyze(t: number, tl: number, o: number, ol: number): number;
  pw_mask(t: number, tl: number, r: number, rl: number, l: number, ll: number): number;
  pw_messages(l: number, ll: number): number;
  pw_deobfuscate(t: number, tl: number, l: number, ll: number): number;
  pw_engine_version(): number;
}

/** Header of a result buffer: u32 LE payload length + u8 status. */
const RESULT_HEADER = 5;

export function rawEngine(ex: RawExports, kind: Backend): Engine {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const call = (fn: (...args: number[]) => number, ...inputs: string[]): string => {
    const owned: [number, number][] = [];
    try {
      for (const s of inputs) {
        const bytes = encoder.encode(s);
        const ptr = ex.pw_alloc(bytes.length) >>> 0;
        owned.push([ptr, bytes.length]);
        new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
      }
      const out = fn(...owned.flat()) >>> 0;
      // Read the buffer again: the call may have grown memory.
      const len = new DataView(ex.memory.buffer).getUint32(out, true);
      const status = new Uint8Array(ex.memory.buffer, out + 4, 1)[0];
      const text = decoder.decode(new Uint8Array(ex.memory.buffer, out + RESULT_HEADER, len));
      ex.pw_free(out, RESULT_HEADER + len);
      if (status !== 0) throw new Error(text);
      return text;
    } finally {
      for (const [ptr, len] of owned) ex.pw_free(ptr, len);
    }
  };

  return {
    kind,
    analyze: (text, opts) => call(ex.pw_analyze, text, opts),
    mask: (text, report, locale) => call(ex.pw_mask, text, report, locale),
    messages: (locale) => call(ex.pw_messages, locale),
    deobfuscate: (text, locale) => call(ex.pw_deobfuscate, text, locale),
    version: () => call(ex.pw_engine_version),
  };
}

export async function loadRaw(): Promise<Engine> {
  const ex = (await import('./wasm2js/paste_warden_raw.js')) as unknown as RawExports;
  return rawEngine(ex, 'wasm2js');
}
