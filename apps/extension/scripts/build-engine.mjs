// Builds the wasm2js fallback of @paste-warden/core as a standalone ES module directory
// (.engine/w2j/), which wxt.config.ts ships as web-accessible `engine/w2j/`. The content script
// imports it only if instantiating the WASM fails (S2), so it costs nothing on normal pages.
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { noDefaultWasmUrl } from './core-plugins.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

await build({
  root,
  configFile: false,
  publicDir: false,
  logLevel: 'warn',
  plugins: [noDefaultWasmUrl()],
  build: {
    outDir: '.engine/w2j',
    emptyOutDir: true,
    target: 'es2022',
    minify: true,
    reportCompressedSize: false,
    chunkSizeWarningLimit: 8192,
    lib: {
      entry: fileURLToPath(new URL('../src/engine-w2j.ts', import.meta.url)),
      formats: ['es'],
      fileName: () => 'index.js',
    },
    rollupOptions: {
      output: { chunkFileNames: '[name].js' },
    },
  },
});
console.log('built .engine/w2j');
