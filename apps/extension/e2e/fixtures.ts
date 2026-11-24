// Playwright fixtures: Playwright's own Chromium / Firefox with the built extension, in a fresh
// temporary profile per worker (never the developer's browsers or profiles).
//
// Chromium: --load-extension (needs Playwright's Chromium; branded Chrome dropped the flag).
// Firefox: start with the remote debugger and install .output/firefox-mv3 as a temporary add-on
// over RDP (web-ext's client), as in docs/spikes/s2-wasm-csp.md.
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { type BrowserContext, test as base, chromium, firefox, type Page } from '@playwright/test';
import { startSite, type TestSite } from './server';

const root = fileURLToPath(new URL('..', import.meta.url));
export const CHROME_EXT = join(root, '.output', 'chrome-mv3');
export const FIREFOX_EXT = join(root, '.output', 'firefox-mv3');

/** Browser UI language of the test profile: zh-TW, so the TW PII pack is on by default (§5.6). */
const LOCALE = 'zh-TW';

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as { port: number };
      srv.close(() => resolve(port));
    });
  });
}

interface RemoteFirefox {
  installTemporaryAddon(path: string): Promise<unknown>;
  disconnect(): void;
}

async function connectRdp(port: number): Promise<RemoteFirefox> {
  const require = createRequire(import.meta.url);
  const webExtDir = dirname(require.resolve('web-ext'));
  const remote = (await import(
    pathToFileURL(join(webExtDir, 'lib', 'firefox', 'remote.js')).href
  )) as {
    connectWithMaxRetries(o: { port: number }): Promise<RemoteFirefox>;
  };
  return remote.connectWithMaxRetries({ port });
}

export async function launchWithExtension(browserName: string): Promise<BrowserContext> {
  if (browserName === 'firefox') {
    if (!existsSync(join(FIREFOX_EXT, 'manifest.json'))) {
      throw new Error('Build the extension first: pnpm --filter @paste-warden/extension build');
    }
    const port = await freePort();
    const ctx = await firefox.launchPersistentContext('', {
      headless: true,
      locale: LOCALE,
      args: ['-start-debugger-server', String(port)],
      firefoxUserPrefs: {
        'devtools.debugger.remote-enabled': true,
        'devtools.debugger.prompt-connection': false,
        'devtools.chrome.enabled': true,
        'xpinstall.signatures.required': false,
        'extensions.manifestV3.enabled': true,
      },
    });
    const rdp = await connectRdp(port);
    await rdp.installTemporaryAddon(FIREFOX_EXT);
    rdp.disconnect();
    return ctx;
  }
  if (!existsSync(join(CHROME_EXT, 'manifest.json'))) {
    throw new Error('Build the extension first: pnpm --filter @paste-warden/extension build');
  }
  const ctx = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    headless: true,
    locale: LOCALE,
    args: [`--disable-extensions-except=${CHROME_EXT}`, `--load-extension=${CHROME_EXT}`],
  });
  if (ctx.serviceWorkers().length === 0) await ctx.waitForEvent('serviceworker');
  return ctx;
}

type WorkerFixtures = { extContext: BrowserContext; site: TestSite };
type TestFixtures = { page: Page };

export const test = base.extend<TestFixtures, WorkerFixtures>({
  site: [
    // biome-ignore lint/correctness/noEmptyPattern: Playwright fixture signature
    async ({}, use) => {
      const site = await startSite();
      await use(site);
      await site.close();
    },
    { scope: 'worker' },
  ],
  extContext: [
    async ({ browserName }, use) => {
      const ctx = await launchWithExtension(browserName);
      await use(ctx);
      await ctx.close();
    },
    { scope: 'worker', timeout: 60_000 },
  ],
  page: async ({ extContext }, use) => {
    const page = await extContext.newPage();
    await use(page);
    await page.close();
  },
});

export { expect } from '@playwright/test';
