import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { App, kindMessageId } from '../src/confirm/App';
import { renderDesktop } from './helpers';
import { calls, emit } from './tauri';

const REQUEST = {
  kinds: ['ui-desktop-kind-credit-card', 'registered'],
  maskedPreview: 'card: **** **** **** 1111',
  targetName: 'notepad.exe',
};

async function open() {
  renderDesktop(<App />);
  await emit('paste-confirm', REQUEST);
  return screen.getByRole('button', { name: 'Cancel' });
}

describe('paste confirmation', () => {
  it('shows the masked preview, the kinds and the target', async () => {
    await open();
    expect(screen.getByRole('alertdialog')).toBeInTheDocument();
    expect(screen.getByText(REQUEST.maskedPreview)).toBeInTheDocument();
    expect(screen.getByText('Credit card number')).toBeInTheDocument();
    expect(screen.getByText('A secret you registered')).toBeInTheDocument();
    expect(screen.getByText(/notepad\.exe/)).toBeInTheDocument();
  });

  it('focuses Cancel by default', async () => {
    const cancel = await open();
    expect(cancel).toHaveFocus();
  });

  it('Enter cancels', async () => {
    await open();
    await userEvent.keyboard('{Enter}');
    await waitFor(() => expect(calls('paste_choice')).toEqual([{ choice: 'cancel' }]));
  });

  it('Esc cancels', async () => {
    await open();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(calls('paste_choice')).toEqual([{ choice: 'cancel' }]));
  });

  it('Enter cancels even when another button has focus', async () => {
    await open();
    screen.getByRole('button', { name: 'Paste original' }).focus();
    await userEvent.keyboard('{Enter}');
    await waitFor(() => expect(calls('paste_choice')).toEqual([{ choice: 'cancel' }]));
  });

  it('the other choices need a deliberate click', async () => {
    await open();
    await userEvent.click(screen.getByRole('button', { name: 'Paste masked' }));
    await waitFor(() => expect(calls('paste_choice')).toEqual([{ choice: 'masked' }]));
    // The preview is dropped once answered.
    await waitFor(() => expect(screen.queryByText(REQUEST.maskedPreview)).toBeNull());
  });

  it('maps bare core kinds to message ids', () => {
    expect(kindMessageId('credit_card')).toBe('ui-desktop-kind-credit-card');
    expect(kindMessageId('ui-desktop-kind-api-key')).toBe('ui-desktop-kind-api-key');
    expect(kindMessageId('<script>')).toBe('ui-desktop-kind-other');
  });
});
