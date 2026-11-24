import { defineConfig } from '@playwright/test';

// Build first: `pnpm --filter @paste-warden/userscript build`. Uses Playwright's own browsers in
// fresh incognito contexts (never a real profile); the clipboard is read back inside the page.
export default defineConfig({
  testDir: './e2e',
  globalSetup: '../extension/e2e/global-setup.ts',
  timeout: 60_000,
  expect: { timeout: 5_000 },
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: { locale: 'zh-TW', headless: true },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium', permissions: ['clipboard-read', 'clipboard-write'] },
    },
    { name: 'firefox', use: { browserName: 'firefox' } },
  ],
});
