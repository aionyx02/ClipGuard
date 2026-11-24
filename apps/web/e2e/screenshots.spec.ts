import { fileURLToPath } from 'node:url';
import { test } from '@playwright/test';
import { pickExample, waitForEngine } from './helpers';

// PR screenshots (`pnpm --filter @paste-warden/web screenshots`), written to apps/web/screenshots/.
const out = (name: string) => fileURLToPath(new URL(`../screenshots/${name}.jpg`, import.meta.url));

test.use({ reducedMotion: 'reduce', deviceScaleFactor: 1 });

const SHOTS = [
  { name: 'desktop-light-zh-TW-obfuscated', lang: 'zh-TW', scheme: 'light', example: 'obfuscated' },
  { name: 'desktop-dark-en-obfuscated', lang: 'en', scheme: 'dark', example: 'obfuscated' },
  { name: 'desktop-light-en-pii', lang: 'en', scheme: 'light', example: 'pii' },
  { name: 'desktop-dark-zh-TW-seed', lang: 'zh-TW', scheme: 'dark', example: 'seed-valid' },
] as const;

for (const s of SHOTS) {
  test(s.name, async ({ page }) => {
    await page.emulateMedia({ colorScheme: s.scheme });
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto(`./?lang=${s.lang}`);
    await waitForEngine(page);
    await pickExample(page, s.example);
    await page.evaluate(() => document.getElementById('playground')?.scrollIntoView());
    await page.screenshot({ path: out(s.name), type: 'jpeg', quality: 82 });
  });
}

test('mobile-dark-zh-TW-clickfix', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('./?lang=zh-TW');
  await waitForEngine(page);
  await pickExample(page, 'clickfix');
  await page.getByTestId('results').scrollIntoViewIfNeeded();
  await page.screenshot({ path: out('mobile-dark-zh-TW-clickfix'), type: 'jpeg', quality: 82 });
});

test('desktop-light-en-download', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize({ width: 1280, height: 1000 });
  await page.goto('./?lang=en#download');
  await waitForEngine(page);
  await page.evaluate(() => document.getElementById('privacy')?.scrollIntoView());
  await page.screenshot({
    path: out('desktop-light-en-privacy-download'),
    type: 'jpeg',
    quality: 82,
  });
});
