// @paste-warden/core: the PasteWarden engine for browsers, extensions,
// userscripts and Node (docs/plan/phase-2.md §2.6, docs/integrations/wasm.md).
//
// Call `await init()` once; afterwards every function is synchronous (S2: the
// MAIN world → content script CustomEvent path needs a synchronous verdict).

import { type Engine, loadRaw, loadWasm } from './backend.js';
import type {
  AnalyzeOptions,
  Backend,
  Deobfuscated,
  Locale,
  Report,
  SecretFinding,
} from './types.js';

export type * from './types.js';
export { ENGINE_VERSION } from './version.js';

export interface InitOptions {
  /**
   * `auto` (default): WebAssembly, falling back to the wasm2js build when
   * `WebAssembly` is missing or compiling is blocked (page CSP without
   * `'wasm-unsafe-eval'`). `wasm` / `wasm2js` force one build.
   */
  backend?: 'auto' | Backend;
  /**
   * Where to get the `.wasm` from instead of the default URL next to this file
   * (`new URL('./wasm/paste_warden_bg.wasm', import.meta.url)`), e.g. bytes from
   * a userscript `@resource`, an extension URL or a compiled module.
   */
  wasm?: URL | string | Response | BufferSource | WebAssembly.Module;
}

let engine: Engine | undefined;
let loading: Promise<void> | undefined;

/** Loads the engine (WASM, or the wasm2js fallback). Safe to call repeatedly. */
export function init(options: InitOptions = {}): Promise<void> {
  if (engine) return Promise.resolve();
  loading ??= load(options).then(
    (e) => {
      engine = e;
    },
    (err: unknown) => {
      loading = undefined;
      throw err;
    },
  );
  return loading;
}

async function load(options: InitOptions): Promise<Engine> {
  const want = options.backend ?? 'auto';
  if (want === 'wasm2js') return loadRaw();
  if (want === 'wasm') return loadWasm(options.wasm);
  if (typeof WebAssembly !== 'object') return loadRaw();
  try {
    return await loadWasm(options.wasm);
  } catch (wasmError) {
    try {
      return await loadRaw();
    } catch (rawError) {
      throw new AggregateError([wasmError, rawError], 'PasteWarden: could not load the engine');
    }
  }
}

function ready(): Engine {
  if (!engine) throw new Error('PasteWarden: call `await init()` first');
  return engine;
}

/** Which build is loaded (`undefined` before `init()`). */
export function backend(): Backend | undefined {
  return engine?.kind;
}

/** Analyzes clipboard text. Spans in the report are UTF-16 (JS string indices). */
export function analyze(text: string, opts: AnalyzeOptions = {}): Report {
  return JSON.parse(ready().analyze(text, JSON.stringify(opts))) as Report;
}

/**
 * "Paste masked": `text` with every secret of `report` replaced by its mask.
 * `report` must come from `analyze(text)` on the same text. `locale` renders
 * the placeholder of a private-key body.
 */
export function mask(
  text: string,
  report: Pick<Report, 'secrets'>,
  locale: Locale = 'zh-TW',
): string {
  const secrets: Pick<SecretFinding, 'kind' | 'masked' | 'span_utf16'>[] = report.secrets.map(
    ({ kind, masked, span_utf16 }) => ({ kind, masked, span_utf16 }),
  );
  return ready().mask(text, JSON.stringify({ secrets }), locale);
}

/** The `ui-*` strings of `locale` (`locales/<locale>/ui.ftl`). */
export function messages(locale: Locale): Record<string, string> {
  return JSON.parse(ready().messages(locale)) as Record<string, string>;
}

/** Deobfuscation trace and a masked preview of the peeled text. */
export function deobfuscate(text: string, locale: Locale = 'zh-TW'): Deobfuscated {
  return JSON.parse(ready().deobfuscate(text, locale)) as Deobfuscated;
}

/** Version reported by the loaded engine (equals `ENGINE_VERSION`). */
export function engineVersion(): string {
  return ready().version();
}
