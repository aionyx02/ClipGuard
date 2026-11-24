import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { LocaleSwitcher, ThemeSwitcher } from '../src/components/Preferences';
import { createBundles, matchLocale, translator } from '../src/i18n/fluent';
import { LOCALE_STORAGE_KEY, LocaleProvider, useLocale } from '../src/i18n/LocaleProvider';
import { THEME_STORAGE_KEY, ThemeProvider, useTheme } from '../src/theme/ThemeProvider';
import { setMedia } from './setup';

const DARK = '(prefers-color-scheme: dark)';

function ThemeProbe() {
  const { mode, resolved } = useTheme();
  return <output data-testid="theme">{`${mode}:${resolved}`}</output>;
}

function LocaleProbe() {
  const { locale, t } = useLocale();
  return <output data-testid="locale">{`${locale}:${t('ui-comp-action-quarantine')}`}</output>;
}

function App() {
  return (
    <ThemeProvider>
      <LocaleProvider>
        <ThemeProbe />
        <LocaleProbe />
        <ThemeSwitcher />
        <LocaleSwitcher />
      </LocaleProvider>
    </ThemeProvider>
  );
}

describe('ThemeProvider', () => {
  it('follows prefers-color-scheme live in system mode', () => {
    render(<App />);
    expect(screen.getByTestId('theme')).toHaveTextContent('system:light');
    expect(document.documentElement.dataset.theme).toBe('light');
    act(() => setMedia(DARK, true));
    expect(screen.getByTestId('theme')).toHaveTextContent('system:dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
  });

  it('persists a manual choice and ignores the OS afterwards', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('radio', { name: 'Dark' }));
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
    act(() => setMedia(DARK, false));
    expect(document.documentElement.dataset.theme).toBe('dark');
  });

  it('restores the stored choice', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'light');
    setMedia(DARK, true);
    render(<App />);
    expect(screen.getByTestId('theme')).toHaveTextContent('light:light');
  });

  it('ignores garbage in storage', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'neon');
    render(<App />);
    expect(screen.getByTestId('theme')).toHaveTextContent('system:light');
  });
});

describe('LocaleProvider', () => {
  it('maps browser languages to a supported locale', () => {
    expect(matchLocale(['zh-Hant-TW', 'en'])).toBe('zh-TW');
    expect(matchLocale(['zh-CN'])).toBe('zh-TW');
    expect(matchLocale(['en-GB'])).toBe('en');
    expect(matchLocale(['fr-FR', 'de'])).toBe('en');
    expect(matchLocale([])).toBe('en');
  });

  it('switches language, persists it and sets <html lang>', async () => {
    const user = userEvent.setup();
    localStorage.setItem(LOCALE_STORAGE_KEY, 'zh-TW');
    render(<App />);
    expect(screen.getByTestId('locale')).toHaveTextContent('zh-TW:已隔離');
    await user.click(screen.getByRole('radio', { name: 'English' }));
    expect(screen.getByTestId('locale')).toHaveTextContent('en:Quarantined');
    expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe('en');
    expect(document.documentElement.lang).toBe('en');
  });

  it('follows languagechange in system mode', () => {
    const spy = vi.spyOn(navigator, 'languages', 'get').mockReturnValue(['en-US']);
    render(<App />);
    expect(screen.getByTestId('locale')).toHaveTextContent('en:');
    spy.mockReturnValue(['zh-TW']);
    act(() => {
      window.dispatchEvent(new Event('languagechange'));
    });
    expect(screen.getByTestId('locale')).toHaveTextContent('zh-TW:');
    spy.mockRestore();
  });
});

describe('Fluent loader', () => {
  it('loads both locales from locales/*/ui*.ftl with identical ids', () => {
    const files = import.meta.glob('../../../locales/*/ui*.ftl', {
      query: '?raw',
      import: 'default',
      eager: true,
    }) as Record<string, string>;
    const idsOf = (lang: string) =>
      Object.entries(files)
        .filter(([path]) => path.includes(`/locales/${lang}/`))
        .flatMap(([, text]) => [...text.matchAll(/^([a-z][a-z0-9-]*) =/gm)].map((m) => m[1]))
        .sort();
    const zh = idsOf('zh-TW');
    expect(zh.length).toBeGreaterThan(30);
    expect(zh).toEqual(idsOf('en'));
    const bundles = createBundles();
    for (const id of zh) {
      expect(bundles.get('zh-TW')?.hasMessage(id as string), id).toBe(true);
      expect(bundles.get('en')?.hasMessage(id as string), id).toBe(true);
    }
  });

  it('formats variables and falls back to the id', () => {
    const t = translator(createBundles(), 'en');
    expect(t('ui-comp-risk-value', { score: 92 })).toBe('92 / 100');
    expect(t('ui-comp-does-not-exist')).toBe('ui-comp-does-not-exist');
  });

  it('lets messages from @paste-warden/core override the build-time copy', () => {
    const t = translator(createBundles({ en: { 'ui-comp-action-allow': 'All good' } }), 'en');
    expect(t('ui-comp-action-allow')).toBe('All good');
  });
});
