// The built userscript in Playwright's Chromium and Firefox (fresh incognito contexts), injected
// the way a manager does at document-start, with a minimal GM_* shim. It runs in the page world
// here (like `@inject-into page`), which is the hardest case: under CSP b and c the page blocks
// both the inline hook script and WebAssembly, so the script must hook directly and fall back to
// wasm2js. Same local pages as the extension tests (apps/extension/e2e/server.ts).
import { readFileSync } from 'node:fs';
import { expect, type Page, test } from '@playwright/test';
import { startSite, type TestSite, VARIANTS } from '../../extension/e2e/server';

const script = readFileSync(new URL('../dist/paste-warden.user.js', import.meta.url), 'utf8');
const SHIM = `
  (() => {
    const store = new Map();
    window.GM_getValue = (k, d) => (store.has(k) ? store.get(k) : d);
    window.GM_setValue = (k, v) => store.set(k, v);
    window.GM_setClipboard = () => {};
    window.GM_registerMenuCommand = () => {};
  })();
`;

const PASTE = 'ControlOrMeta+V';
let site: TestSite;

test.beforeAll(async () => {
  site = await startSite();
});
test.afterAll(async () => {
  await site.close();
});

test.beforeEach(async ({ context }) => {
  await context.addInitScript({ content: `${SHIM}\n${script}` });
});

/** Opens `url`; returns the engine builds the script reported (page, its frames, and the
 * initial about:blank document, which has no CSP). */
async function open(page: Page, url: string): Promise<string[]> {
  const backends: string[] = [];
  page.on('console', (m) => {
    const t = m.text();
    if (t.startsWith('[PasteWarden] engine:')) backends.push(t.split(':').pop()?.trim() ?? '');
  });
  await page.goto(url);
  await page.waitForFunction(() => (window as { __pwPageReady?: boolean }).__pwPageReady === true);
  // Page + two frames (+ about:blank): wait until they have all loaded an engine.
  await expect.poll(() => backends.length, { timeout: 15_000 }).toBeGreaterThanOrEqual(3);
  return backends;
}

async function readClipboard(page: Page): Promise<string> {
  const box = page.locator('#readback');
  await box.fill('');
  await box.focus();
  await page.keyboard.press(PASTE);
  await page.waitForTimeout(150);
  return box.inputValue();
}

const clearLog = (page: Page) =>
  page.evaluate(() => {
    const log = document.getElementById('log');
    if (log) log.textContent = '';
  });

async function seed(page: Page) {
  await clearLog(page);
  await page.click('#write-benign');
  await expect(page.locator('#log')).toContainText('benign resolved');
}

const overlay = (page: Page) => page.locator('paste-warden-overlay');

async function expectBlocked(page: Page) {
  await expect(overlay(page)).toHaveCount(1);
  await page.keyboard.press('Escape');
  await expect(overlay(page)).toHaveCount(0);
  const text = await readClipboard(page);
  expect(text).toContain('PasteWarden');
  expect(text.toLowerCase()).not.toContain('example.invalid');
}

for (const csp of VARIANTS) {
  test(`userscript, CSP ${csp}: blocks writes, confirms secret pastes, leaves text alone`, async ({
    page,
  }) => {
    const backends = await open(page, site.url(csp));
    test.info().annotations.push({ type: 'engine', description: backends.join(', ') });
    // Page world: WebAssembly only where the page CSP allows it, wasm2js elsewhere.
    if (csp === 'a') expect(backends.every((b) => b === 'wasm')).toBe(true);
    else expect(backends).toContain('wasm2js');

    // 4. ordinary text
    await page.click('#write-benign');
    await expect(page.locator('#log')).toContainText('benign resolved');
    expect(await readClipboard(page)).toBe('npm install left-pad');
    await expect(overlay(page)).toHaveCount(0);

    // 1. writeText
    await clearLog(page);
    await page.click('#write-clickfix');
    await expect(page.locator('#log')).toContainText('writeText resolved');
    await expectBlocked(page);
    // 2. execCommand('copy') and the copy event
    await seed(page);
    await page.click('#exec-copy');
    await expectBlocked(page);
    await seed(page);
    await page.click('#copy-event');
    await expectBlocked(page);

    // 3. secret paste
    await page.click('#write-id');
    await expect(page.locator('#log')).toContainText('id resolved');
    const target = page.locator('#paste-target');
    await target.focus();
    await page.keyboard.press(PASTE);
    await expect(overlay(page)).toHaveCount(1);
    await page.keyboard.press('Enter');
    await expect(overlay(page)).toHaveCount(0);
    expect(await target.inputValue()).not.toContain(['A12', '3456', '789'].join(''));
    expect(await target.inputValue()).toMatch(/A\d*\*{3,}\d*/);

    // 5. same-origin iframe
    await seed(page);
    const frame = await (await page.waitForSelector('#same')).contentFrame();
    if (!frame) throw new Error('no frame');
    await frame.waitForFunction(
      () => (window as { __pwPageReady?: boolean }).__pwPageReady === true,
    );
    await page.waitForTimeout(300);
    await frame.click('#write-clickfix');
    await expect(frame.locator('#log')).toContainText('writeText resolved');
    await expectBlocked(page);
  });
}
