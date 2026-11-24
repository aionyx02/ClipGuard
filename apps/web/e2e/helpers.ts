import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { expect, type Page } from '@playwright/test';

const axeSource = readFileSync(
  createRequire(import.meta.url).resolve('axe-core/axe.min.js'),
  'utf8',
);

/** Waits until `init()` resolved (the footer shows the engine version). */
export async function waitForEngine(page: Page): Promise<void> {
  await expect(page.getByTestId('engine-info')).not.toBeEmpty({ timeout: 20_000 });
  await expect(page.getByTestId('skeleton')).toHaveCount(0);
}

export async function pickExample(page: Page, id: string): Promise<void> {
  await page.locator(`[data-example="${id}"]`).click();
  await expect(page.getByTestId('results')).toBeVisible();
}

/**
 * axe-core (WCAG 2.0/2.1 A + AA, best practices; includes colour contrast). Evaluated through the
 * DevTools protocol, so the page's CSP (no inline scripts) does not get in the way.
 */
export async function axeViolations(page: Page): Promise<string[]> {
  await page.evaluate(axeSource);
  return page.evaluate(async () => {
    const axe = (
      window as unknown as {
        axe: {
          run: (
            ctx: unknown,
            o: unknown,
          ) => Promise<{
            violations: { id: string; nodes: { target: string[]; failureSummary?: string }[] }[];
          }>;
        };
      }
    ).axe;
    const result = await axe.run(document, {
      runOnly: {
        type: 'tag',
        values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'],
      },
    });
    return result.violations.map(
      (v) =>
        `${v.id}: ${v.nodes
          .slice(0, 3)
          .map((n) => `${n.target.join(' ')} — ${n.failureSummary ?? ''}`)
          .join(' | ')}`,
    );
  });
}
