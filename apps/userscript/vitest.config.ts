import { defineConfig } from 'vitest/config';

// Separate from vite.config.ts so vite-plugin-monkey's dev-server behaviour never runs in tests.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
