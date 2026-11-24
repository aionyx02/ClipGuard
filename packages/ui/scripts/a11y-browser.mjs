// axe-core in a real browser against the built demo (dist/), light and dark, zh-TW and en.
// Unlike the jsdom tests this includes colour contrast. Playwright's own Chromium; no profile.
// Run: pnpm --filter @paste-warden/ui build && pnpm --filter @paste-warden/ui test:browser
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const dist = fileURLToPath(new URL('../dist/', import.meta.url));
const axeSource = readFileSync(
  createRequire(import.meta.url).resolve('axe-core/axe.min.js'),
  'utf8',
);
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

const browser = await chromium.launch();
let failures = 0;
try {
  for (const colorScheme of ['light', 'dark']) {
    for (const locale of ['zh-TW', 'en-US']) {
      const context = await browser.newContext({ colorScheme, locale, reducedMotion: 'reduce' });
      const page = await context.newPage();
      await page.route('http://ui.test/**', (route) => {
        let path = new URL(route.request().url()).pathname.slice(1) || 'index.html';
        if (path.endsWith('/')) path += 'index.html';
        return route.fulfill({
          body: readFileSync(join(dist, path)),
          contentType: TYPES[extname(path)] ?? 'application/octet-stream',
        });
      });
      await page.goto('http://ui.test/');
      await page.waitForSelector('[data-action]');
      await page.addScriptTag({ content: axeSource });
      const violations = await page.evaluate(async () => {
        const result = await window.axe.run(document, {
          runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'best-practice'] },
        });
        return result.violations.map((v) => ({
          id: v.id,
          nodes: v.nodes.slice(0, 3).map((n) => `${n.target.join(' ')} — ${n.failureSummary}`),
        }));
      });
      const label = `${colorScheme}/${locale}`;
      if (violations.length === 0) {
        console.log(`${label}: no axe violations`);
      } else {
        failures += violations.length;
        console.error(`${label}:`, JSON.stringify(violations, null, 2));
      }
      await context.close();
    }
  }
} finally {
  await browser.close();
}
process.exit(failures > 0 ? 1 : 0);
