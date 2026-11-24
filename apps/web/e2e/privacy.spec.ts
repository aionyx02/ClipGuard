import { expect, type Request, test } from '@playwright/test';
import { pickExample, waitForEngine } from './helpers';

// The page promises "everything runs in your browser; nothing is uploaded". These tests hold it
// to that: during loading only same-origin static files are fetched, and while analyzing there
// is no request at all — not to the origin, not anywhere.

test('loads only same-origin files, then makes zero requests while analyzing', async ({
  page,
  baseURL,
}) => {
  const origin = new URL(baseURL as string).origin;
  const requests: Request[] = [];
  page.on('request', (r) => requests.push(r));
  const sockets: string[] = [];
  page.on('websocket', (ws) => sockets.push(ws.url()));

  await page.goto('./?lang=en');
  await waitForEngine(page);
  await page.waitForLoadState('networkidle');

  const foreign = requests.map((r) => r.url()).filter((u) => new URL(u).origin !== origin);
  expect(foreign, 'third-party requests during load').toEqual([]);

  // Everything after this point is analysis.
  requests.length = 0;
  const input = page.getByTestId('input');
  await input.fill('');
  await input.pressSequentially('echo hello && calc', { delay: 5 });
  for (const id of ['clickfix', 'obfuscated', 'pii', 'apikey', 'seed-valid', 'seed-invalid']) {
    await pickExample(page, id);
  }
  await pickExample(page, 'obfuscated');
  await page.getByRole('button', { name: 'Reveal all' }).click();
  await page.getByText('繁體中文').click(); // re-analysis in another locale
  await input.fill('plain text again');
  await page.waitForTimeout(500);

  expect(
    requests.map((r) => `${r.method()} ${r.url()}`),
    'requests while analyzing',
  ).toEqual([]);
  expect(sockets).toEqual([]);
});

test('works offline once loaded', async ({ page, context }) => {
  await page.goto('./?lang=en');
  await waitForEngine(page);
  await context.setOffline(true);
  await pickExample(page, 'obfuscated');
  await expect(page.locator('[data-action="quarantine"]')).toBeVisible();
  await context.setOffline(false);
});

test('the content security policy only allows the page itself', async ({ page }) => {
  await page.goto('./');
  const csp = await page
    .locator('meta[http-equiv="Content-Security-Policy"]')
    .getAttribute('content');
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("connect-src 'self'");
  expect(csp).not.toMatch(/https?:/);
  // And it is enforced: a fetch to another origin is refused by the browser.
  const violated = await page.evaluate(async () => {
    const seen = new Promise<string>((resolve) =>
      document.addEventListener('securitypolicyviolation', (e) => resolve(e.effectiveDirective), {
        once: true,
      }),
    );
    await fetch('https://example.invalid/').catch(() => undefined);
    return Promise.race([seen, new Promise((r) => setTimeout(() => r('none'), 2000))]);
  });
  expect(violated).toBe('connect-src');
});

test('the text never ends up in the URL or in storage', async ({ page }) => {
  await page.goto('./?lang=en');
  await waitForEngine(page);
  await page.getByTestId('input').fill('my secret note A123456789');
  await expect(page.getByTestId('results')).toBeVisible();
  expect(page.url()).not.toContain('secret');
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).not.toContain('secret');
  expect(stored).not.toContain('A123456789');
});
