import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { Allowlist } from '../src/settings/PasteGuard';
import { renderDesktop, settings } from './helpers';
import { emitNow, handlers } from './tauri';

const withList = (allowlist: string[]) =>
  settings({ pasteGuard: { registered: true, detected: true, allowlist } });

const shown = () =>
  within(screen.getByRole('list'))
    .getAllByRole('listitem')
    .map((li) => li.querySelector('code')?.textContent);

describe('allowlist', () => {
  // The worker stores the normalized name (no `.exe`) and emits
  // settings-changed before the command returns; the list must show what was
  // stored, whichever arrives first.
  it('shows the stored name when settings-changed arrives first', async () => {
    handlers.set('allowlist_add', () => {
      emitNow('settings-changed', withList(['notepad']));
    });
    handlers.set('get_settings', () => withList(['notepad']));
    renderDesktop(<Allowlist />);
    await userEvent.type(screen.getByLabelText('Program name'), 'notepad.exe');
    await userEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(shown()).toEqual(['notepad']);
  });

  it('shows the stored name when the command returns first', async () => {
    handlers.set('get_settings', () => withList(['notepad']));
    renderDesktop(<Allowlist />);
    await userEvent.type(screen.getByLabelText('Program name'), 'notepad.exe');
    await userEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(await screen.findByText('notepad')).toBeInTheDocument();
    expect(shown()).toEqual(['notepad']);
  });
});
