import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// Library build: one ES module the extension / userscript bundle in. Size budget: < 15 KB gzip
// (checked by scripts/size.mjs after the build).
export default defineConfig({
  build: {
    lib: {
      entry: fileURLToPath(new URL('src/index.ts', import.meta.url)),
      formats: ['es'],
      fileName: () => 'overlay.js',
    },
    target: 'es2022',
    minify: true,
    emptyOutDir: true,
  },
  test: {
    environment: 'happy-dom',
    include: ['test/**/*.test.ts'],
  },
});
