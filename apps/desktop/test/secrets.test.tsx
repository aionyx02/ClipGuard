import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { SecretsManager } from '../src/settings/Secrets';
import { renderDesktop } from './helpers';
import { calls, handlers } from './tauri';

// Built at run time; never a real credential.
const SECRET = ['pw', 'test', String(Date.now() % 100000), 'xyz'].join('-');

function inputs() {
  return {
    secret: screen.getByLabelText('Secret to register') as HTMLInputElement,
    confirm: screen.getByLabelText('Enter it again') as HTMLInputElement,
    label: screen.getByLabelText('Name (optional)') as HTMLInputElement,
  };
}

/** The secret must not be anywhere in the DOM: not in text, not in an input's value. */
function expectSecretGone() {
  expect(document.body.textContent).not.toContain(SECRET);
  expect(document.body.innerHTML).not.toContain(SECRET);
  for (const el of document.querySelectorAll('input')) expect(el.value).not.toContain(SECRET);
}

describe('register secret form', () => {
  it('uses password inputs for the secret and its confirmation', () => {
    handlers.set('list_secrets', () => []);
    renderDesktop(<SecretsManager />);
    const { secret, confirm, label } = inputs();
    expect(secret).toHaveAttribute('type', 'password');
    expect(confirm).toHaveAttribute('type', 'password');
    expect(label).toHaveAttribute('type', 'text');
  });

  it('sends the secret once and clears it after a successful submit', async () => {
    let list: Array<{ id: string; label: string; length: number; createdAtMs: number }> = [];
    handlers.set('list_secrets', () => list);
    handlers.set('register_secret', () => {
      list = [{ id: 'a1', label: 'VPN', length: SECRET.length, createdAtMs: 0 }];
      return { id: 'a1' };
    });
    renderDesktop(<SecretsManager />);
    const { secret, confirm, label } = inputs();
    await userEvent.type(secret, SECRET);
    await userEvent.type(confirm, SECRET);
    await userEvent.type(label, 'VPN');
    await userEvent.click(screen.getByRole('button', { name: 'Register' }));

    expect(calls('register_secret')).toEqual([{ secret: SECRET, confirm: SECRET, label: 'VPN' }]);
    expect(secret.value).toBe('');
    expect(confirm.value).toBe('');
    await screen.findByText('VPN');
    expect(screen.getByText(new RegExp(`${SECRET.length} characters`))).toBeInTheDocument();
    expect(label.value).toBe('');
    expectSecretGone();
  });

  it('clears the secret on error and shows the field error through Fluent', async () => {
    handlers.set('list_secrets', () => []);
    handlers.set('register_secret', () => {
      throw { field: 'confirm', messageId: 'registered-mismatch' };
    });
    renderDesktop(<SecretsManager />);
    const { secret, confirm } = inputs();
    await userEvent.type(secret, SECRET);
    await userEvent.type(confirm, `${SECRET}!`);
    await userEvent.click(screen.getByRole('button', { name: 'Register' }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent("The two entries don't match. Please try again.");
    expect(confirm).toHaveAttribute('aria-invalid', 'true');
    expect(confirm).toHaveAttribute('aria-describedby', alert.id);
    expect(secret.value).toBe('');
    expect(confirm.value).toBe('');
    expectSecretGone();
  });

  it('never renders a raw error, even one that echoes the input', async () => {
    handlers.set('list_secrets', () => []);
    handlers.set('register_secret', (args) => {
      throw new Error(`bad secret ${String(args?.secret)}`);
    });
    renderDesktop(<SecretsManager />);
    const { secret, confirm } = inputs();
    await userEvent.type(secret, SECRET);
    await userEvent.type(confirm, SECRET);
    await userEvent.click(screen.getByRole('button', { name: 'Register' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Something went wrong. Please try again.',
    );
    expectSecretGone();
  });

  it('lists secrets by label and length only, and removes after a confirmation', async () => {
    let list = [{ id: 'k1', label: '', length: 24, createdAtMs: Date.UTC(2026, 10, 1) }];
    handlers.set('list_secrets', () => list);
    handlers.set('remove_secret', () => {
      list = [];
    });
    renderDesktop(<SecretsManager />);
    expect(await screen.findByText('Untitled')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Remove “Untitled”' }));
    await userEvent.click(screen.getByRole('button', { name: 'Remove it' }));
    expect(calls('remove_secret')).toEqual([{ id: 'k1' }]);
    await waitFor(() => expect(screen.getByText('No secrets registered yet.')).toBeInTheDocument());
  });
});
