// Real-browser check of the built overlay (dist/overlay.js) with trusted input, in Playwright's
// own Chromium and Firefox (no personal profile, no system clipboard).
// Run: pnpm --filter @paste-warden/overlay build && pnpm --filter @paste-warden/overlay test:browser
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { chromium, firefox } from 'playwright';
import { fixtureReports } from '../../ui/src/fixtures/reports.ts';

const bundle = readFileSync(new URL('../dist/overlay.js', import.meta.url), 'utf8');
const fixtures = fixtureReports('en');
const ORIGIN = 'http://overlay.test';

// The page forces a dark theme on itself; the overlay must still follow the OS (light here).
const html = `<!doctype html><html style="color-scheme:dark;background:#000;color:#fff"><head><meta charset="utf-8"></head>
<body><textarea id="field"></textarea><script type="module">
import * as overlay from '/overlay.js';
window.overlay = overlay;
window.fixtures = ${JSON.stringify(fixtures)};
</script></body></html>`;

async function run(browserType) {
  const browser = await browserType.launch();
  const context = await browser.newContext({ colorScheme: 'light', locale: 'en-US' });
  // Test-only: record shadow roots so assertions can look inside the closed root.
  await context.addInitScript(() => {
    const attach = Element.prototype.attachShadow;
    window.__roots = [];
    Element.prototype.attachShadow = function (init) {
      const root = attach.call(this, init);
      window.__roots.push({ root, mode: init.mode });
      return root;
    };
  });
  const page = await context.newPage();
  await page.route(`${ORIGIN}/**`, (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/overlay.js')
      return route.fulfill({ body: bundle, contentType: 'text/javascript' });
    return route.fulfill({ body: html, contentType: 'text/html' });
  });
  await page.goto(`${ORIGIN}/`);
  await page.waitForFunction(() => window.overlay);
  // Starts a dialog without awaiting it; `result()` awaits the stored promise.
  const open = (expr) => page.evaluate(`void (window.pending = ${expr})`);
  const result = () => page.evaluate(() => window.pending);
  const inRoot = (fn) => page.evaluate(`(${fn})(window.__roots.at(-1).root)`);

  const name = browserType.name();
  const checks = [];
  const check = async (label, fn) => {
    await fn();
    checks.push(label);
  };

  await check('closed shadow root, modal dialog in the top layer', async () => {
    await page.focus('#field');
    await open(`overlay.showPasteConfirm(fixtures.secrets, { locale: 'en', armDelayMs: 0 })`);
    assert.equal(await page.evaluate(() => window.__roots.at(-1).mode), 'closed');
    assert.equal(await inRoot((r) => r.querySelector('dialog').matches(':modal')), true);
  });
  await check('follows the OS colour scheme, not the page', async () => {
    const bg = await inRoot((r) => getComputedStyle(r.querySelector('dialog')).backgroundColor);
    assert.equal(bg, 'rgb(255, 255, 255)');
  });
  await check('Enter on a focused "Paste original" still pastes masked', async () => {
    await page.keyboard.press('Tab'); // masked → cancel
    await page.keyboard.press('Tab'); // cancel → original
    assert.equal(await inRoot((r) => r.activeElement?.textContent), 'Paste original');
    await page.keyboard.press('Enter');
    assert.equal(await result(), 'masked');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'field');
  });
  await check('Esc cancels', async () => {
    await open(`overlay.showPasteConfirm(fixtures.secrets, { locale: 'en', armDelayMs: 0 })`);
    await page.keyboard.press('Escape');
    assert.equal(await result(), 'cancel');
  });
  await check('a real click on "Paste original" works', async () => {
    await open(`overlay.showPasteConfirm(fixtures.secrets, { locale: 'en', armDelayMs: 0 })`);
    const box = await inRoot((r) => {
      const b = [...r.querySelectorAll('button')].find((x) => x.textContent === 'Paste original');
      const { x, y, width, height } = b.getBoundingClientRect();
      return { x: x + width / 2, y: y + height / 2 };
    });
    await page.mouse.click(box.x, box.y);
    assert.equal(await result(), 'original');
  });
  await check(
    'blocked dialog: Enter keeps it blocked, a page cannot click "allow once"',
    async () => {
      await open(
        `overlay.showClipboardBlocked(fixtures.clickfix, { locale: 'en', armDelayMs: 0, url: 'https://example.invalid/' })`,
      );
      // A page script that somehow got the button can only send untrusted clicks.
      await inRoot((r) => {
        [...r.querySelectorAll('button')]
          .find((x) => x.textContent.startsWith("I'm sure"))
          ?.click();
      });
      await page.keyboard.press('Enter');
      assert.equal(await result(), 'keep-blocked');
    },
  );

  await browser.close();
  console.log(`${name}: ${checks.length} checks passed\n  - ${checks.join('\n  - ')}`);
}

for (const browserType of [chromium, firefox]) await run(browserType);
