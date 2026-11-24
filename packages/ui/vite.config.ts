import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

// `vite build` builds the demo page (demo/index.html) into dist/; the package itself is
// consumed as TypeScript source by the apps (all of them bundle with Vite).
export default defineConfig({
  root: 'demo',
  base: './',
  plugins: [react(), tailwindcss()],
  // The Fluent loader reads ../../locales/*/ui*.ftl at build time.
  server: { fs: { allow: [repoRoot] } },
  build: { outDir: '../dist', emptyOutDir: true },
  test: {
    root: fileURLToPath(new URL('.', import.meta.url)),
    environment: 'jsdom',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.test.{ts,tsx}'],
  },
});
