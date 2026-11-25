import { expect, test } from '@playwright/test';
import { pickExample, waitForEngine } from './helpers';

test.describe('onion view', () => {
  test.use({ reducedMotion: 'no-preference' });

  test('peels the obfuscated example layer by layer', async ({ page }) => {
    await page.goto('./?lang=en#/play');
    await waitForEngine(page);
    await pickExample(page, 'obfuscated');

    const layers = page.locator('[data-layer]');
    // Auto-play starts with the outer layer only…
    await expect(layers).toHaveCount(1);
    await expect(layers.first()).toHaveAttribute('data-kind', 'caret');
    // …and reveals the rest one by one.
    await expect(layers).toHaveCount(2);
    await expect(layers.nth(1)).toHaveAttribute('data-kind', 'encoded_command');
    await expect(layers).toHaveCount(4, { timeout: 10_000 });
    const kinds = await layers.evaluateAll((els) => els.map((e) => e.getAttribute('data-kind')));
    expect(kinds).toEqual(['caret', 'encoded_command', 'concat', 'unwrap']);
    // Each layer is nested inside the previous one.
    await expect(page.locator('[data-layer="1"] [data-layer="2"] [data-layer="3"]')).toHaveCount(1);
    // The innermost layer shows what actually runs, defanged host included.
    await expect(page.locator('[data-layer="4"] pre').first()).toContainText('example.invalid');
    await expect(page.getByText('4 of 4 layers revealed')).toBeVisible();
  });

  test('manual controls: replay, next, reveal all', async ({ page }) => {
    await page.goto('./?lang=en#/play');
    await waitForEngine(page);
    await pickExample(page, 'obfuscated');
    const layers = page.locator('[data-layer]');
    await expect(layers).toHaveCount(4, { timeout: 10_000 });

    await page.getByRole('button', { name: 'Replay' }).click();
    await page.getByRole('button', { name: 'Reveal all' }).click();
    await expect(layers).toHaveCount(4);
    await page.getByRole('button', { name: 'Replay' }).click();
    await expect(layers).toHaveCount(1);
    await page.getByRole('button', { name: 'Reveal next layer' }).click();
    await expect(layers.nth(1)).toBeVisible();
  });

  test('a new text restarts the reveal', async ({ page }) => {
    await page.goto('./?lang=en#/play');
    await waitForEngine(page);
    await pickExample(page, 'obfuscated');
    await expect(page.locator('[data-layer]')).toHaveCount(4, { timeout: 10_000 });
    await pickExample(page, 'clickfix');
    await expect(page.getByText('This text is not obfuscated.')).toBeVisible();
  });
});

test.describe('onion view, reduced motion', () => {
  test.use({ reducedMotion: 'reduce' });

  test('shows every layer at once', async ({ page }) => {
    await page.goto('./?lang=en#/play');
    await waitForEngine(page);
    await pickExample(page, 'obfuscated');
    await expect(page.locator('[data-layer]')).toHaveCount(4);
  });
});
