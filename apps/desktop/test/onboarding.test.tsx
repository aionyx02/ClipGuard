import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { App } from '../src/onboarding/App';
import { renderDesktop, status } from './helpers';
import { calls, handlers } from './tauri';

const heading = () => screen.getByRole('heading', { level: 1 }).textContent;

describe('onboarding', () => {
  it('the limits page can only be left with “Got it”, and the wizard ends with complete_onboarding', async () => {
    renderDesktop(<App />, { platform: 'windows' });
    expect(heading()).toBe('Welcome to PasteWarden');
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(heading()).toBe("First, what PasteWarden can't protect");
    expect(screen.queryByRole('button', { name: 'Next' })).toBeNull();
    expect(screen.getByRole('table')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Got it' }));
    // No Accessibility page outside macOS.
    expect(heading()).toBe('All set');
    await userEvent.click(screen.getByRole('button', { name: 'Start using PasteWarden' }));
    expect(calls('complete_onboarding')).toHaveLength(1);
  });

  it('macOS adds the Accessibility page with a button to System Settings', async () => {
    handlers.set('get_protection_status', () =>
      status({ intercept: { state: 'unavailable', reason: 'no-accessibility' }, tray: 'failed' }),
    );
    renderDesktop(<App />, { platform: 'macos', locale: 'zh-TW' });
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));
    await userEvent.click(screen.getByRole('button', { name: '我知道了' }));
    expect(heading()).toBe('允許 PasteWarden 攔截貼上');
    await userEvent.click(await screen.findByRole('button', { name: '打開「輔助使用」設定' }));
    expect(calls('open_accessibility_settings')).toHaveLength(1);
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));
    expect(heading()).toBe('設定完成');
  });

  it('after an update on macOS, explains removing and re-adding the old entry', async () => {
    handlers.set('get_protection_status', () =>
      status({
        intercept: { state: 'unavailable', reason: 'no-accessibility-after-update' },
        tray: 'failed',
      }),
    );
    renderDesktop(<App />, { platform: 'macos', versionChanged: true });
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    await userEvent.click(screen.getByRole('button', { name: 'Got it' }));
    expect(
      await screen.findByText(/macOS needs you to allow PasteWarden again/),
    ).toBeInTheDocument();
    expect(screen.getByText(/click “−” below it to remove it/)).toBeInTheDocument();
  });
});
