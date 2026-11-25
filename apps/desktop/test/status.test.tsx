import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { parseFtl } from '../src/lib/core-messages';
import { REASONS } from '../src/lib/ipc';
import { scopeRows } from '../src/ui/ScopeTable';
import { StatusCard } from '../src/ui/StatusCard';
import { renderDesktop, status } from './helpers';
import { calls } from './tauri';

const ftl = (locale: string) =>
  parseFtl(readFileSync(resolve(__dirname, `../../../locales/${locale}/ui-desktop.ftl`), 'utf8'));
const en = ftl('en');
const zh = ftl('zh-TW');

describe('ui-desktop.ftl', () => {
  it('zh-TW and en define the same ids', () => {
    expect(Object.keys(zh).sort()).toEqual(Object.keys(en).sort());
  });

  it('has one status message per Reason', () => {
    for (const r of REASONS) {
      expect(en[`ui-desktop-status-${r}`], r).toBeTruthy();
      expect(zh[`ui-desktop-status-${r}`], r).toBeTruthy();
    }
  });
});

describe('status card', () => {
  it('says everything works when it does', () => {
    renderDesktop(<StatusCard status={status()} />);
    expect(screen.getByText('All protection is working.')).toBeInTheDocument();
    expect(screen.getAllByText('Working')).toHaveLength(4);
  });

  it.each(REASONS)('renders the message for %s', (reason) => {
    for (const locale of ['en', 'zh-TW'] as const) {
      const { container, unmount } = renderDesktop(
        <StatusCard
          status={status({ intercept: { state: 'degraded', reason }, tray: 'degraded' })}
        />,
        { locale },
      );
      const row = container.querySelector('[data-area="intercept"]') as HTMLElement;
      const message = row.querySelector(`[data-reason="${reason}"]`);
      const expected = (locale === 'en' ? en : zh)[`ui-desktop-status-${reason}`];
      // Plain messages render verbatim; none of them should fall back to the id.
      expect(message?.textContent).toBe(expected);
      expect(container.textContent).not.toContain(`ui-desktop-status-${reason}`);
      unmount();
    }
  });

  it('shows an unavailable capability and a generic line for an unknown reason', () => {
    const { container } = renderDesktop(
      <StatusCard
        status={status({ watch: { state: 'unavailable', reason: 'brand-new' }, tray: 'failed' })}
      />,
    );
    const row = container.querySelector('[data-area="watch"]') as HTMLElement;
    expect(within(row).getByText('Unavailable')).toBeInTheDocument();
    expect(within(row).getByText('This protection is limited right now.')).toBeInTheDocument();
    expect(screen.getByText('Some protection is not working. Details below.')).toBeInTheDocument();
  });

  it('offers the Accessibility button and GUI steps after an update', async () => {
    renderDesktop(
      <StatusCard
        status={status({
          intercept: { state: 'unavailable', reason: 'no-accessibility-after-update' },
          tray: 'failed',
        })}
      />,
    );
    expect(screen.getByText(/click “−” below it to remove it/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Open Accessibility settings' }));
    expect(calls('open_accessibility_settings')).toHaveLength(1);
  });
});

describe('protection scope', () => {
  it('never claims right-click, menu or drag-and-drop pastes are confirmed', () => {
    for (const platform of ['windows', 'macos', 'linux'] as const) {
      const rows = scopeRows(platform, status());
      for (const m of ['context-menu', 'edit-menu', 'drag-drop', 'remote-desktop']) {
        expect(rows.find((r) => r.method === m)?.confirm).toBe('not-covered');
      }
    }
  });

  it('follows the live intercept status for keyboard pastes', () => {
    const rows = scopeRows(
      'linux',
      status({ intercept: { state: 'unavailable', reason: 'wayland-no-intercept' } }),
    );
    expect(rows.find((r) => r.method === 'keyboard')?.confirm).toBe('unavailable');
  });
});
