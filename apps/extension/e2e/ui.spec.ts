// Popup and options page (Chromium: extension pages have a known chrome-extension:// URL there),
// plus the allowlist and "allow once" end to end.
import type { BrowserContext, Page } from '@playwright/test';
import { expect, test } from './fixtures';

async function extensionId(ctx: BrowserContext): Promise<string> {
  const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
  return new URL(sw.url()).host;
}

async function readClipboard(page: Page): Promise<string> {
  const box = page.locator('#readback');
  await box.fill('');
  await box.focus();
  await page.keyboard.press('ControlOrMeta+V');
  await page.waitForTimeout(150);
  return box.inputValue();
}

test('allow once writes the original command back (explicit, trusted choice)', async ({
  page,
  site,
}) => {
  await page.goto(site.url('c'));
  await page.waitForFunction(() => (window as { __pwPageReady?: boolean }).__pwPageReady === true);
  await page.waitForTimeout(400);
  await page.click('#write-clickfix');
  await expect(page.locator('paste-warden-overlay')).toHaveCount(1);
  // The risky button is armed after 600 ms and only reacts to trusted input. Focus starts on
  // "keep blocked"; Shift+Tab reaches "allow once", Space activates it (Enter means keep).
  await page.waitForTimeout(700);
  await page.keyboard.press('Shift+Tab');
  await page.keyboard.press('Space');
  await expect(page.locator('paste-warden-overlay')).toHaveCount(0);
  await page.waitForTimeout(200);
  expect(await readClipboard(page)).toContain('example.invalid');
});

test.describe('extension pages', () => {
  test.skip(({ browserName }) => browserName !== 'chromium', 'chrome-extension:// URLs only');

  test('options: the allowlist turns PasteWarden off for a site; popup shows it', async ({
    page,
    site,
    extContext,
  }) => {
    const id = await extensionId(extContext);
    const options = await extContext.newPage();
    await options.goto(`chrome-extension://${id}/options.html`);
    await expect(options.getByRole('heading', { level: 1 })).toContainText('剪貼簿守門員');
    await options.getByLabel('網站主機名稱').fill('127.0.0.1');
    await options.getByRole('button', { name: '新增' }).click();
    await expect(options.getByText('127.0.0.1', { exact: true })).toBeVisible();

    await page.goto(site.url('a'));
    await page.waitForFunction(
      () => (window as { __pwPageReady?: boolean }).__pwPageReady === true,
    );
    await page.waitForTimeout(400);
    await page.click('#write-clickfix');
    await expect(page.locator('#log')).toContainText('writeText resolved');
    await expect(page.locator('paste-warden-overlay')).toHaveCount(0);
    expect(await readClipboard(page)).toContain('example.invalid');

    // Undo, so the other tests in this worker see a clean allowlist.
    await options.getByRole('button', { name: '移除 127.0.0.1' }).click();
    await expect(options.getByText('目前沒有網站。')).toBeVisible();
    await options.close();
  });

  test('popup renders, follows the theme setting, and lists recent blocks without text', async ({
    page,
    site,
    extContext,
  }) => {
    await page.goto(site.url('a'));
    await page.waitForFunction(
      () => (window as { __pwPageReady?: boolean }).__pwPageReady === true,
    );
    await page.waitForTimeout(400);
    await page.click('#write-clickfix');
    await expect(page.locator('paste-warden-overlay')).toHaveCount(1);
    await page.keyboard.press('Escape');

    const id = await extensionId(extContext);
    const popup = await extContext.newPage();
    await popup.goto(`chrome-extension://${id}/popup.html`);
    await expect(popup.getByRole('heading', { name: '最近的攔截紀錄' })).toBeVisible();
    const recent = popup.locator('li').filter({ hasText: '攔下指令' }).first();
    await expect(recent).toContainText('127.0.0.1');
    const html = await popup.content();
    expect(html).not.toContain('example.invalid');
    expect(html.toLowerCase()).not.toContain('iwr');

    // The stored records hold only domain / time / kind / masked.
    const stored = await popup.evaluate(async () => {
      const c = (
        globalThis as unknown as {
          chrome: { storage: { local: { get(k: string): Promise<Record<string, unknown>> } } };
        }
      ).chrome;
      return (await c.storage.local.get('recent')).recent as Array<Record<string, unknown>>;
    });
    expect(stored.length).toBeGreaterThan(0);
    for (const r of stored)
      expect(Object.keys(r).sort()).toEqual(['domain', 'kind', 'masked', 'time']);

    await popup.emulateMedia({ colorScheme: 'dark' });
    await expect(popup.locator('html')).toHaveAttribute('data-theme', 'dark');
    await popup.emulateMedia({ colorScheme: 'light' });
    await expect(popup.locator('html')).toHaveAttribute('data-theme', 'light');
    await popup.close();
  });
});
