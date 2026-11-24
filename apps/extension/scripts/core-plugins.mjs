// Vite plugins that control how @paste-warden/core is bundled (shared by wxt.config.ts,
// scripts/build-engine.mjs and apps/userscript/vite.config.ts).

const isCore = (id) => id.includes('core-js') || id.includes('@paste-warden/core');

/**
 * Drops `new URL('…paste_warden_bg.wasm', import.meta.url)`: the callers always pass the
 * `.wasm` explicitly, and the default would make Vite emit a second copy of it.
 * @returns {import('vite').Plugin}
 */
export function noDefaultWasmUrl() {
  return {
    name: 'paste-warden:no-default-wasm-url',
    enforce: 'pre',
    transform(code, id) {
      if (!isCore(id)) return null;
      const out = code.replace(
        /new URL\((['"])(?:\.\/wasm\/)?paste_warden_bg\.wasm\1,\s*import\.meta\.url\)/g,
        'undefined',
      );
      return out === code ? null : { code: out, map: null };
    },
  };
}

/**
 * Removes core's Node-only `import('node:fs/promises')` (only reached for `file:` URLs). A dynamic
 * import left in the bundle makes vite-plugin-monkey wrap the userscript in SystemJS.
 * @returns {import('vite').Plugin}
 */
export function noNodeFsImport() {
  return {
    name: 'paste-warden:no-node-fs-import',
    enforce: 'pre',
    transform(code, id) {
      if (!isCore(id)) return null;
      const out = code.replace(
        /import\(\s*(?:\/\*[^*]*\*\/\s*)*fsModule\s*\)/g,
        "Promise.reject(new Error('PasteWarden: no file system here'))",
      );
      return out === code ? null : { code: out, map: null };
    },
  };
}

/**
 * Replaces core's wasm2js module with a stub, so the 6 MB fallback never lands in a bundle that
 * loads it some other way (the extension's content script imports engine/w2j/ on demand).
 * @returns {import('vite').Plugin}
 */
export function noBundledWasm2js() {
  const STUB = '\0pw-wasm2js-stub';
  return {
    name: 'paste-warden:no-bundled-wasm2js',
    enforce: 'pre',
    resolveId(id, importer) {
      if (id.endsWith('wasm2js/paste_warden_raw.js') && importer && isCore(importer)) return STUB;
      return null;
    },
    load(id) {
      if (id === STUB) {
        return 'throw new Error("PasteWarden: the wasm2js engine is loaded separately");';
      }
      return null;
    },
  };
}
