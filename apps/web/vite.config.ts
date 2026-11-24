import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

/**
 * The privacy promise, enforced by the browser: the built page may only talk to its own origin
 * (to fetch its own scripts and the .wasm). No third-party anything, no inline scripts.
 * `'wasm-unsafe-eval'` allows compiling WebAssembly; without it `init()` falls back to wasm2js.
 * Build only: Vite's dev server injects inline scripts.
 */
export const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

const csp = (): Plugin => ({
  name: 'paste-warden-csp',
  apply: 'build',
  transformIndexHtml: () => [
    {
      tag: 'meta',
      attrs: { 'http-equiv': 'Content-Security-Policy', content: CSP },
      injectTo: 'head-prepend',
    },
  ],
});

// The playground is served at `/` of the Pages site — or `/<repo>/` until a custom domain exists —
// so every URL is relative (`base: './'`), including the links to the docs at `./docs/`.
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss(), csp()],
  // Fluent sources (locales/*/ui*.ftl) and the BIP-39 word list (rules/secret) are read from the
  // repo root at build time.
  server: { fs: { allow: [repoRoot] } },
  build: {
    target: 'es2022',
    // The engine (WASM glue + wasm2js fallback) is split out by the dynamic import in engine.ts.
    chunkSizeWarningLimit: 4096,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.test.{ts,tsx}'],
  },
});
