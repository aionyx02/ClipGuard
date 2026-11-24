// Build plugins for the userscript (used by vite.config.ts; tested in test/build-plugins.test.ts).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { build, type Plugin } from 'vite';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/**
 * - `virtual:pw-page-hook`: src/page-hook.ts bundled to one IIFE string, injected into the page.
 * - `virtual:pw-wasm`: the engine's .wasm, gzip + base64 (decompressed with DecompressionStream).
 */
export function pasteWardenVirtuals(): Plugin {
  const ids = { hook: 'virtual:pw-page-hook', wasm: 'virtual:pw-wasm' };
  return {
    name: 'paste-warden:userscript-virtuals',
    resolveId(id) {
      return id === ids.hook || id === ids.wasm ? `\0${id}` : null;
    },
    async load(id) {
      if (id === `\0${ids.wasm}`) {
        const wasm = readFileSync(here('../../packages/core-js/dist/wasm/paste_warden_bg.wasm'));
        return `export default ${JSON.stringify(gzipSync(wasm, { level: 9 }).toString('base64'))};`;
      }
      if (id === `\0${ids.hook}`) {
        const out = await build({
          configFile: false,
          logLevel: 'silent',
          publicDir: false,
          build: {
            write: false,
            minify: true,
            target: 'es2022',
            lib: { entry: here('src/page-hook.ts'), formats: ['iife'], name: 'pwPageHook' },
          },
        });
        const outputs = Array.isArray(out) ? out : [out];
        const chunk = outputs
          .flatMap((o) => ('output' in o ? o.output : []))
          .find((c) => c.type === 'chunk');
        if (chunk?.type !== 'chunk') throw new Error('page hook build produced no chunk');
        // `var pwPageHook=(()=>{…})()` → a bare IIFE: no global left on the page.
        return `export default ${JSON.stringify(chunk.code.replace(/^var pwPageHook\s*=\s*/, ''))};`;
      }
      return null;
    },
  };
}

/**
 * vite-plugin-monkey wraps any bundle that still contains a dynamic import in SystemJS. Turn
 * core's two `await import()` into static imports; the wasm2js module becomes a function that
 * builds the engine only when called, so pages that run the WASM never pay for evaluating it.
 */
export function staticCoreImports(): Plugin {
  return {
    name: 'paste-warden:static-core-imports',
    enforce: 'pre',
    transform(code, id) {
      const file = id.replaceAll('\\', '/');
      if (file.endsWith('core-js/dist/backend.js')) {
        const out = code
          .replace("await import('./wasm/paste_warden.js')", '__pwGlue')
          .replace("await import('./wasm2js/paste_warden_raw.js')", '__pwRaw.instantiate()');
        if (!out.includes('__pwGlue') || !out.includes('__pwRaw.')) {
          throw new Error('core-js backend.js changed: update staticCoreImports()');
        }
        return {
          code: `import * as __pwGlue from './wasm/paste_warden.js';\nimport * as __pwRaw from './wasm2js/paste_warden_raw.js';\n${out}`,
          map: null,
        };
      }
      if (file.endsWith('core-js/dist/wasm2js/paste_warden_raw.js')) {
        const at = code.indexOf('var retasmFunc = asmFunc(');
        if (at < 0) throw new Error('wasm2js output changed: update staticCoreImports()');
        return {
          code: `${code.slice(0, at)}export function instantiate() { return asmFunc({}); }\n`,
          map: null,
        };
      }
      return null;
    },
  };
}
