import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  // The Fluent loader and the pastejack port read ../../locales and ../../rules at build time.
  server: { fs: { allow: [fileURLToPath(new URL('../..', import.meta.url))] } },
  test: {
    environment: 'happy-dom',
    include: ['test/**/*.test.ts'],
  },
});
