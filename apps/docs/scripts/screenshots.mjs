// Screenshots of the docs site, the @paste-warden/ui demo and the overlay, light and dark, for
// PR review. Prerequisite: `pnpm -r build`. Uses Playwright's own Chromium (never a personal
// browser profile) and does not touch the system clipboard.
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import sharp from 'sharp';
import { fixtureReports } from '../../../packages/ui/src/fixtures/reports.ts';
import { serve } from './serve.mjs';

const at = (p) => fileURLToPath(new URL(p, import.meta.url));
const out = at('../screenshots/');
mkdirSync(out, { recursive: true });

const fixtures = { 'zh-TW': fixtureReports('zh-TW'), en: fixtureReports('en') };
const overlayPage = `<!doctype html><html lang="zh-TW"><head><meta charset="utf-8">
<title>example.invalid</title><style>body{font:16px system-ui;margin:40px;background:#f7f7f7;color:#222}
.fake{max-width:520px;margin:auto;padding:32px;border:1px solid #ccc;background:#fff;border-radius:8px}</style></head>
<body><div class="fake"><h1>Verify you are human</h1><p>Press Win+R, paste, and press Enter.</p></div>
<script type="module">
import { showClipboardBlocked, showPasteConfirm } from '/overlay/overlay.js';
const f = ${JSON.stringify(fixtures)};
const p = new URLSearchParams(location.search);
const locale = p.get('lang') ?? 'zh-TW';
const opts = { locale, armDelayMs: 0 };
window.result = p.get('kind') === 'paste'
  ? showPasteConfirm(f[locale].secrets, opts)
  : showClipboardBlocked(f[locale].clickfix, { ...opts, url: 'https://example.invalid/captcha' });
</script></body></html>`;

const server = await serve(
  {
    '/docs/': at('../dist/'),
    '/ui/': at('../../../packages/ui/dist/'),
    '/overlay/': at('../../../packages/overlay/dist/'),
  },
  { '/page.html': { type: 'text/html; charset=utf-8', body: overlayPage } },
);

const shots = [
  { name: 'docs-home', path: '/docs/' },
  { name: 'docs-install', path: '/docs/user/install/chrome-edge/' },
  { name: 'docs-en-features', path: '/docs/en/user/features/', locale: 'en-US' },
  { name: 'ui-demo', path: '/ui/', height: 1180 },
  { name: 'overlay-blocked', path: '/page.html?kind=blocked', expand: true },
  { name: 'overlay-paste', path: '/page.html?kind=paste&lang=en', locale: 'en-US' },
];

const browser = await chromium.launch();
try {
  for (const scheme of ['light', 'dark']) {
    for (const shot of shots) {
      const context = await browser.newContext({
        colorScheme: scheme,
        locale: shot.locale ?? 'zh-TW',
        viewport: { width: 1200, height: shot.height ?? 760 },
        reducedMotion: 'reduce',
      });
      const page = await context.newPage();
      await page.goto(server.origin + shot.path, { waitUntil: 'networkidle' });
      if (shot.expand) {
        // The overlay's shadow root is closed, so open the onion view with the keyboard:
        // focus starts on "keep blocked" (last), Tab wraps to the <summary> (first).
        await page.keyboard.press('Tab');
        await page.keyboard.press('Space');
      }
      await page.waitForTimeout(250);
      const file = `${out}${shot.name}-${scheme}.png`;
      // Palette PNGs keep the committed screenshots small.
      const png = await page.screenshot();
      await sharp(png).png({ palette: true, quality: 85, compressionLevel: 9 }).toFile(file);
      console.log(`saved ${file}`);
      await context.close();
    }
  }
} finally {
  await browser.close();
  server.close();
}
