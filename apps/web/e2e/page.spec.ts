import { expect, test } from '@playwright/test';
import { axeViolations, pickExample, waitForEngine } from './helpers';

const COPY = {
  'zh-TW': { quarantine: '已隔離', heroStart: '貼上任何文字' },
  en: { quarantine: 'Quarantined', heroStart: 'Paste anything' },
} as const;

for (const colorScheme of ['light', 'dark'] as const) {
  for (const lang of ['zh-TW', 'en'] as const) {
    test.describe(`${colorScheme} / ${lang}`, () => {
      test.use({ colorScheme, reducedMotion: 'reduce' });

      test('renders, analyzes and is axe-clean', async ({ page }) => {
        await page.goto(`./?lang=${lang}`);
        await expect(page.locator('html')).toHaveAttribute('lang', lang);
        await expect(page.locator('html')).toHaveAttribute('data-theme', colorScheme);
        await expect(page.getByRole('heading', { level: 1 })).toContainText(COPY[lang].heroStart);
        await waitForEngine(page);
        expect(await axeViolations(page), 'empty state').toEqual([]);

        await pickExample(page, 'obfuscated');
        await expect(page.locator('[data-action="quarantine"]')).toContainText(
          COPY[lang].quarantine,
        );
        expect(await axeViolations(page), 'quarantine + onion').toEqual([]);

        await pickExample(page, 'pii');
        await expect(page.getByTestId('copy-masked')).toBeVisible();
        expect(await axeViolations(page), 'secrets + mask preview').toEqual([]);
      });
    });
  }
}

test('?lang= wins, and switching language rewrites it', async ({ page }) => {
  await page.goto('./?lang=en');
  await waitForEngine(page);
  await page.getByText('繁體中文').click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-TW');
  await expect(page).toHaveURL(/[?&]lang=zh-TW/);
  await expect(page.getByRole('heading', { level: 1 })).toContainText('貼上任何文字');
  // System removes the parameter again.
  await page.getByRole('radio', { name: '系統' }).nth(1).check({ force: true });
  await expect(page).not.toHaveURL(/lang=/);
});

test('theme switch: system / light / dark', async ({ page }) => {
  await page.goto('./?lang=en');
  await page.getByText('Dark', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.reload();
  // Applied before first paint by boot.js, then kept by ThemeProvider.
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.getByText('Light', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
});

test('an example re-renders in the new language', async ({ page }) => {
  await page.goto('./?lang=en');
  await waitForEngine(page);
  await pickExample(page, 'pii');
  await expect(page.getByTestId('input')).toHaveValue(/Taiwan ID/);
  await page.getByText('繁體中文').click();
  await expect(page.getByTestId('input')).toHaveValue(/身分證字號/);
});

test('copy masked text writes only the masked version', async ({ page }) => {
  // Stub: never touch the real clipboard (repo rule); capture what would be written.
  await page.addInitScript(() => {
    const w = window as unknown as { __copied: string[] };
    w.__copied = [];
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (s: string) => {
          w.__copied.push(s);
        },
      },
    });
  });
  await page.goto('./?lang=en');
  await waitForEngine(page);
  await pickExample(page, 'apikey');
  const input = await page.getByTestId('input').inputValue();
  const token = input.match(/ghp_\w+/)?.[0];
  expect(token).toBeTruthy();
  await page.getByTestId('copy-masked').click();
  await expect(page.getByRole('status').filter({ hasText: 'copied' })).toBeVisible();
  const copied = await page.evaluate(() => (window as unknown as { __copied: string[] }).__copied);
  expect(copied).toHaveLength(1);
  expect(copied[0]).not.toContain(token as string);
  expect(copied[0]).toContain('ghp_');
  // The plaintext token is nowhere in the results either.
  await expect(page.getByTestId('results')).not.toContainText(token as string);
});

test('seed phrase: valid checksum is flagged, broken checksum is not', async ({ page }) => {
  await page.goto('./?lang=en');
  await waitForEngine(page);
  await pickExample(page, 'seed-valid');
  await expect(page.locator('[data-action="warn"]')).toBeVisible();
  await expect(page.locator('[data-kind="mnemonic"]')).toBeVisible();
  await pickExample(page, 'seed-invalid');
  await expect(page.locator('[data-action="allow"]')).toBeVisible();
  await expect(page.locator('[data-kind="mnemonic"]')).toHaveCount(0);
});

test.describe('mobile', () => {
  test.use({ viewport: { width: 375, height: 740 }, hasTouch: true, isMobile: true });

  test('no horizontal scrolling', async ({ page }) => {
    await page.goto('./?lang=zh-TW');
    await waitForEngine(page);
    await pickExample(page, 'obfuscated');
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(0);
  });
});

test('falls back to wasm2js when WebAssembly is unavailable', async ({ page }) => {
  await page.addInitScript(() => {
    // biome-ignore lint/suspicious/noExplicitAny: simulating a browser without WebAssembly
    delete (globalThis as any).WebAssembly;
  });
  await page.goto('./?lang=en');
  await waitForEngine(page);
  await expect(page.getByTestId('engine-info')).toContainText('JavaScript fallback');
  await pickExample(page, 'clickfix');
  await expect(page.locator('[data-action="quarantine"]')).toBeVisible();
});

test('layout does not shift when the engine arrives', async ({ page }) => {
  await page.addInitScript(() => {
    const w = window as unknown as { __cls: number };
    w.__cls = 0;
    new PerformanceObserver((list) => {
      for (const e of list.getEntries() as unknown as {
        value: number;
        hadRecentInput: boolean;
      }[]) {
        if (!e.hadRecentInput) w.__cls += e.value;
      }
    }).observe({ type: 'layout-shift', buffered: true });
  });
  await page.goto('./?lang=en');
  await waitForEngine(page);
  await page.waitForTimeout(300);
  const cls = await page.evaluate(() => (window as unknown as { __cls: number }).__cls);
  expect(cls).toBeLessThan(0.02);
});
