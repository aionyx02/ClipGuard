// docs/plan/phase-3.md §3.7: the extension in Playwright's Chromium and Firefox against local
// pages with no CSP (a), `script-src 'self'` (b) and a strict nonce CSP (c).
//
// The clipboard is read inside the browser (a real paste into a textarea on the page), never
// from the OS. Headless Chromium on Linux and headless Firefox use an in-memory clipboard; on
// macOS, e2e/global-setup.ts backs up and restores the system pasteboard around the run.
import type { Frame, Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { VARIANTS } from './server';

const NOTICE_MARKER = 'PasteWarden';
const PASTE = 'ControlOrMeta+V';

async function open(page: Page, url: string) {
  await page.goto(url);
  await page.waitForFunction(() => (window as { __pwPageReady?: boolean }).__pwPageReady === true);
  // Let the content script finish instantiating the engine (a few ms; the hooks wait for it anyway).
  await page.waitForTimeout(400);
}

/** Pastes the browser clipboard into #readback and returns what arrived. */
async function readClipboard(page: Page): Promise<string> {
  const box = page.locator('#readback');
  await box.fill('');
  await box.focus();
  await page.keyboard.press(PASTE);
  await page.waitForTimeout(150);
  return box.inputValue();
}

/** Puts known text on the clipboard through the page (benign, so the extension lets it through). */
async function seedClipboard(page: Page) {
  await page.click('#write-benign');
  await expect(page.locator('#log')).toContainText('benign resolved');
}

const overlay = (page: Page) => page.locator('paste-warden-overlay');
const notice = (page: Page) => page.locator('paste-warden-notice');

async function expectBlocked(page: Page) {
  await expect(overlay(page)).toHaveCount(1);
  await page.keyboard.press('Escape'); // keep blocked
  await expect(overlay(page)).toHaveCount(0);
  const text = await readClipboard(page);
  expect(text).toContain(NOTICE_MARKER);
  expect(text.toLowerCase()).not.toContain('example.invalid');
}

for (const csp of VARIANTS) {
  test.describe(`CSP ${csp}`, () => {
    test('1. writeText of a ClickFix command is replaced and the blocked dialog shows', async ({
      page,
      site,
    }) => {
      await open(page, site.url(csp));
      await seedClipboard(page);
      await page.click('#write-clickfix');
      await expectBlocked(page);
      await expect(page.locator('#log')).toContainText('writeText resolved');
    });

    test('1b. navigator.clipboard.write(ClipboardItem) is replaced too', async ({ page, site }) => {
      await open(page, site.url(csp));
      await seedClipboard(page);
      await page.click('#write-item');
      await expect(page.locator('#log')).toContainText(/write (resolved|rejected)/);
      await expect(page.locator('#log')).toContainText('write resolved');
      await expectBlocked(page);
    });

    test("2a. hidden textarea + execCommand('copy') is replaced", async ({ page, site }) => {
      await open(page, site.url(csp));
      await seedClipboard(page);
      await page.click('#exec-copy');
      await expectBlocked(page);
    });

    test('2b. copy event clipboardData.setData is replaced', async ({ page, site }) => {
      await open(page, site.url(csp));
      await seedClipboard(page);
      await page.click('#copy-event');
      await expectBlocked(page);
    });

    test('3. pasting a fake national ID asks first: Enter pastes masked, Esc cancels', async ({
      page,
      site,
    }) => {
      await open(page, site.url(csp));
      await page.click('#write-id');
      await expect(page.locator('#log')).toContainText('id resolved');
      await expect(overlay(page)).toHaveCount(0); // a page writing a secret is not blocked

      const target = page.locator('#paste-target');
      await target.focus();
      await page.keyboard.press(PASTE);
      await expect(overlay(page)).toHaveCount(1);
      await page.keyboard.press('Enter');
      await expect(overlay(page)).toHaveCount(0);
      const masked = await target.inputValue();
      expect(masked).toContain('我的身分證');
      expect(masked).not.toContain(['A12', '3456', '789'].join(''));
      expect(masked).toMatch(/A\d*\*{3,}\d*/);

      await target.fill('');
      await target.focus();
      await page.keyboard.press(PASTE);
      await expect(overlay(page)).toHaveCount(1);
      await page.keyboard.press('Escape');
      await expect(overlay(page)).toHaveCount(0);
      await expect(target).toHaveValue('');

      // Password fields are never touched.
      const pw = page.locator('#password');
      await pw.focus();
      await page.keyboard.press(PASTE);
      await expect(overlay(page)).toHaveCount(0);
      expect((await pw.inputValue()).length).toBeGreaterThan(0);
    });

    test('4. ordinary text: no interference at all', async ({ page, site }) => {
      await open(page, site.url(csp));
      await page.click('#write-benign');
      await expect(page.locator('#log')).toContainText('benign resolved');
      await page.waitForTimeout(200);
      await expect(overlay(page)).toHaveCount(0);
      await expect(notice(page)).toHaveCount(0);
      expect(await readClipboard(page)).toBe('npm install left-pad');
      // A normal paste goes through untouched too.
      const target = page.locator('#paste-target');
      await target.focus();
      await page.keyboard.press(PASTE);
      await expect(overlay(page)).toHaveCount(0);
      await expect(target).toHaveValue('npm install left-pad');
    });

    for (const which of ['same', 'cross'] as const) {
      test(`5. writes inside a ${which}-origin iframe are intercepted`, async ({ page, site }) => {
        await open(page, site.url(csp));
        await seedClipboard(page);
        const frame = await frameOf(page, which);
        await frame.click('#write-clickfix');
        await expectBlocked(page);

        await seedClipboard(page);
        await frame.click('#exec-copy');
        await expectBlocked(page);
      });
    }
  });
}

async function frameOf(page: Page, id: 'same' | 'cross'): Promise<Frame> {
  const handle = await page.waitForSelector(`#${id}`);
  const frame = await handle.contentFrame();
  if (!frame) throw new Error(`no frame #${id}`);
  await frame.waitForFunction(() => (window as { __pwPageReady?: boolean }).__pwPageReady === true);
  await page.waitForTimeout(300);
  return frame;
}
