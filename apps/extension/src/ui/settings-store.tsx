// Settings for the popup and options page: loaded from storage.local before the first render
// (the theme / locale providers read their store synchronously), kept live via storage.onChanged.
import {
  LOCALE_STORAGE_KEY,
  LocaleProvider,
  type PreferenceStore,
  THEME_STORAGE_KEY,
  ThemeProvider,
} from '@paste-warden/ui';
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { browser } from 'wxt/browser';
import { type ExtSettings, normalizeSettings, SETTINGS_KEY } from '../lib/settings';

export async function loadSettings(): Promise<ExtSettings> {
  const got = await browser.storage.local.get(SETTINGS_KEY);
  return normalizeSettings(got[SETTINGS_KEY]);
}

/** Merges `patch` into the stored settings (read-modify-write, so other pages' edits survive). */
export async function saveSettings(patch: Partial<ExtSettings>): Promise<ExtSettings> {
  const next = normalizeSettings({ ...(await loadSettings()), ...patch });
  await browser.storage.local.set({ [SETTINGS_KEY]: next });
  return next;
}

interface Ctx {
  settings: ExtSettings;
  update: (patch: Partial<ExtSettings>) => void;
}
const SettingsContext = createContext<Ctx | null>(null);

export function useSettings(): Ctx {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error('useSettings outside <SettingsRoot>');
  return ctx;
}

function SettingsRoot({ initial, children }: { initial: ExtSettings; children: ReactNode }) {
  const [settings, setSettings] = useState(initial);
  useEffect(() => {
    const listener = (changes: Record<string, { newValue?: unknown }>, area: string) => {
      if (area === 'local' && changes[SETTINGS_KEY]) {
        setSettings(normalizeSettings(changes[SETTINGS_KEY].newValue));
      }
    };
    browser.storage.onChanged.addListener(listener);
    return () => browser.storage.onChanged.removeListener(listener);
  }, []);

  // The theme / locale providers persist through this store into the same settings object.
  const store = useMemo<PreferenceStore>(
    () => ({
      get: (key) =>
        key === THEME_STORAGE_KEY
          ? initial.theme
          : key === LOCALE_STORAGE_KEY
            ? initial.locale
            : null,
      set: (key, value) => {
        if (key === THEME_STORAGE_KEY) void saveSettings({ theme: value as ExtSettings['theme'] });
        if (key === LOCALE_STORAGE_KEY)
          void saveSettings({ locale: value as ExtSettings['locale'] });
      },
    }),
    [initial],
  );

  const ctx = useMemo<Ctx>(
    () => ({
      settings,
      update: (patch) => {
        setSettings((s) => normalizeSettings({ ...s, ...patch }));
        void saveSettings(patch);
      },
    }),
    [settings],
  );

  return (
    <SettingsContext.Provider value={ctx}>
      <ThemeProvider storage={store}>
        <LocaleProvider storage={store}>{children}</LocaleProvider>
      </ThemeProvider>
    </SettingsContext.Provider>
  );
}

/** Renders `app` into #root once the settings are loaded. */
export async function mount(app: ReactNode): Promise<void> {
  const initial = await loadSettings().catch(() => normalizeSettings({}));
  const el = document.getElementById('root');
  if (!el) return;
  createRoot(el).render(<SettingsRoot initial={initial}>{app}</SettingsRoot>);
}
