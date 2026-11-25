import { LocaleSwitcher, ThemeSwitcher, useT } from '@paste-warden/ui';
import { act, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { media, setLanguages } from './env';
import { renderDesktop, settings } from './helpers';
import { calls, emit } from './tauri';

function Probe() {
  const t = useT();
  return (
    <>
      <p data-testid="text">{t('ui-desktop-cancel')}</p>
      <ThemeSwitcher />
      <LocaleSwitcher />
    </>
  );
}

const theme = () => document.documentElement.dataset.theme;
const text = () => screen.getByTestId('text').textContent;

describe('theme', () => {
  it('follows the system live when set to system', () => {
    renderDesktop(<Probe />, { theme: 'system' });
    expect(theme()).toBe('light');
    act(() => media.setDark(true));
    expect(theme()).toBe('dark');
    act(() => media.setDark(false));
    expect(theme()).toBe('light');
  });

  it('a manual choice overrides the system', () => {
    media.dark = true;
    renderDesktop(<Probe />, { theme: 'light' });
    expect(theme()).toBe('light');
    act(() => media.setDark(false));
    expect(theme()).toBe('light');
  });

  it('picking a theme saves it through set_theme', async () => {
    renderDesktop(<Probe />, { theme: 'system' });
    await userEvent.click(screen.getByRole('radio', { name: 'Dark' }));
    expect(theme()).toBe('dark');
    expect(calls('set_theme')).toEqual([{ theme: 'dark' }]);
  });

  it('applies settings-changed from another window without echoing it back', async () => {
    renderDesktop(<Probe />, { theme: 'system' });
    await emit('settings-changed', settings({ theme: 'dark' }));
    expect(theme()).toBe('dark');
    expect(screen.getByRole('radio', { name: 'Dark' })).toBeChecked();
    expect(calls('set_theme')).toEqual([]);
  });
});

describe('language', () => {
  it('follows the system language when set to system', () => {
    setLanguages(['zh-Hant-TW', 'en']);
    renderDesktop(<Probe />, { locale: 'system' });
    expect(text()).toBe('取消');
    expect(document.documentElement.lang).toBe('zh-TW');
  });

  it('reacts to a system language change', () => {
    renderDesktop(<Probe />, { locale: 'system' });
    expect(text()).toBe('Cancel');
    act(() => {
      setLanguages(['zh-TW']);
      window.dispatchEvent(new Event('languagechange'));
    });
    expect(text()).toBe('取消');
  });

  it('a manual choice overrides the system', () => {
    setLanguages(['zh-TW']);
    renderDesktop(<Probe />, { locale: 'en' });
    expect(text()).toBe('Cancel');
  });

  it('picking a language saves it through set_locale', async () => {
    renderDesktop(<Probe />, { locale: 'en' });
    await userEvent.click(screen.getByRole('radio', { name: '繁體中文' }));
    expect(text()).toBe('取消');
    expect(calls('set_locale')).toEqual([{ locale: 'zh-TW' }]);
  });

  it('applies settings-changed without echoing it back', async () => {
    renderDesktop(<Probe />, { locale: 'en' });
    await emit('settings-changed', settings({ locale: 'zh-TW' }));
    expect(text()).toBe('取消');
    expect(calls('set_locale')).toEqual([]);
  });
});
