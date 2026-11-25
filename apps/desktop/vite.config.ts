import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));
const repoRoot = here('../..');

// Three windows, one page each (docs/plan/phase-4.md §4.7): the settings window is the main one
// (index.html), plus the paste confirmation and the first-run onboarding.
export default defineConfig({
  base: './',
  // No CSP meta tag here: Tauri sets the CSP (tauri.conf.json `app.security.csp`) and adds
  // hashes for the scripts it injects; a stricter meta tag would block those.
  plugins: [react(), tailwindcss()],
  // Tauri expects a fixed port and fails if it is taken.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    // Fluent sources (locales/*/*.ftl) are read from the repo root at build time.
    fs: { allow: [repoRoot] },
    watch: { ignored: ['**/src-tauri/**'] },
  },
  envPrefix: ['VITE_', 'TAURI_ENV_'],
  build: {
    target: 'es2022',
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        settings: here('index.html'),
        confirm: here('confirm.html'),
        onboarding: here('onboarding.html'),
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.test.{ts,tsx}'],
  },
});
