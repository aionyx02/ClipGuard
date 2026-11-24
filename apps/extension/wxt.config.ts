import { existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'wxt';
import { noBundledWasm2js, noDefaultWasmUrl, noNodeFsImport } from './scripts/core-plugins.mjs';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const repoRoot = here('../..');
const coreDist = here('../../packages/core-js/dist');
/** Output of scripts/build-engine.mjs: the wasm2js build as an on-demand ES module. */
const w2jDir = here('.engine/w2j');

// https://wxt.dev/api/config.html
export default defineConfig({
  srcDir: 'src',
  outDir: '.output',
  imports: false,
  vite: () => ({
    // The content script loads the .wasm from engine/ and wasm2js from engine/w2j/ on demand.
    plugins: [noBundledWasm2js(), noDefaultWasmUrl(), noNodeFsImport(), react(), tailwindcss()],
    // The Fluent loaders read ../../locales and ../../rules at build time.
    server: { fs: { allow: [repoRoot] } },
    build: { target: 'es2022', chunkSizeWarningLimit: 2048 },
  }),
  hooks: {
    // `imports: false` still leaves unimport's Vite plugin running, and it rewrites an unrelated
    // `storage` identifier in @paste-warden/ui into a WXT import. No auto-imports anywhere.
    'config:resolved': (wxt) => {
      (wxt.config.imports as { exclude?: RegExp[] }).exclude = [/./];
    },
    'build:publicAssets': (_wxt, files) => {
      const wasm = `${coreDist}/wasm/paste_warden_bg.wasm`;
      if (!existsSync(wasm)) {
        throw new Error('Build @paste-warden/core first: pnpm --filter @paste-warden/core build');
      }
      files.push({ absoluteSrc: wasm, relativeDest: 'engine/paste_warden_bg.wasm' });
      if (!existsSync(w2jDir))
        throw new Error('Run scripts/build-engine.mjs first (pnpm build does).');
      for (const name of readdirSync(w2jDir)) {
        files.push({ absoluteSrc: `${w2jDir}/${name}`, relativeDest: `engine/w2j/${name}` });
      }
    },
  },
  manifest: ({ browser }) => ({
    name: 'PasteWarden',
    description:
      'Clipboard guard: blocks commands websites slip onto your clipboard (ClickFix), confirms before pasting secrets, detects pastejacking. Runs entirely in your browser.',
    permissions: [
      'storage',
      // Fallback writes from the extension side: "allow once" when the page lost focus, and
      // overwriting a write that slipped through before the engine was ready (S2).
      'clipboardWrite',
      ...(browser === 'firefox' ? [] : ['offscreen']),
    ],
    content_security_policy: {
      // S2: background / offscreen need 'wasm-unsafe-eval' to instantiate WebAssembly.
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
    web_accessible_resources: [
      { resources: ['engine/*', 'engine/w2j/*'], matches: ['<all_urls>'] },
    ],
    action: { default_title: 'PasteWarden' },
    ...(browser === 'firefox'
      ? {
          browser_specific_settings: {
            gecko: {
              id: 'paste-warden@aionyx02.github.io',
              strict_min_version: '128.0',
              data_collection_permissions: { required: ['none'] },
            },
          },
        }
      : {}),
  }),
  zip: {
    artifactTemplate: 'paste-warden-{{browser}}.zip',
    sourcesTemplate: 'paste-warden-{{browser}}-sources.zip',
  },
});
