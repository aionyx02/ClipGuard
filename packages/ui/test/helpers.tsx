import { render } from '@testing-library/react';
import axe from 'axe-core';
import type { ReactElement } from 'react';
import { expect } from 'vitest';
import { type LocaleMode, LocaleProvider } from '../src/i18n/LocaleProvider';
import { ThemeProvider } from '../src/theme/ThemeProvider';

export function renderUi(ui: ReactElement, locale: LocaleMode = 'zh-TW') {
  return render(
    <ThemeProvider storage={null}>
      <LocaleProvider defaultMode={locale} storage={null}>
        {ui}
      </LocaleProvider>
    </ThemeProvider>,
  );
}

/** Runs axe on a rendered tree. Colour contrast needs real layout, so it is checked in the browser. */
export async function expectNoAxeViolations(container: Element) {
  const result = await axe.run(container, {
    rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
  });
  const summary = result.violations.map(
    (v) => `${v.id}: ${v.nodes.map((n) => n.html).join(' | ')}`,
  );
  expect(summary).toEqual([]);
}
