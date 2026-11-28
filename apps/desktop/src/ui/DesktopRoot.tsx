// Every window: loads the settings from Rust before the first render (the theme / locale
// providers read their store synchronously), then keeps them live through `settings-changed`,
// so a change in one window (or the tray) reaches the others.
import {
  LOCALE_STORAGE_KEY,
  type LocaleMode,
  LocaleProvider,
  type PreferenceStore,
  THEME_STORAGE_KEY,
  type ThemeMode,
  ThemeProvider,
  useLocale,
  useTheme,
} from '@paste-warden/ui';
import {
  createContext,
  type ReactNode,
  StrictMode,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { createRoot } from 'react-dom/client';
import { coreMessages } from '../lib/core-messages';
import { type DesktopSettings, events, ipc, subscribe } from '../lib/ipc';

interface Ctx {
  settings: DesktopSettings;
  /** Applies a change locally right away; the next `settings-changed` is authoritative. */
  patch: (patch: Partial<DesktopSettings>) => void;
}
const SettingsContext = createContext<Ctx | null>(null);

export function useSettings(): Ctx {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error('useSettings outside <DesktopRoot>');
  return ctx;
}

/** Pushes theme / locale changes that came from Rust into the providers. */
function SyncPreferences({ theme, locale }: { theme: ThemeMode; locale: LocaleMode }) {
  const themeCtx = useTheme();
  const localeCtx = useLocale();
  useEffect(() => {
    if (themeCtx.mode !== theme) themeCtx.setMode(theme);
  }, [theme, themeCtx]);
  useEffect(() => {
    if (localeCtx.mode !== locale) localeCtx.setMode(locale);
  }, [locale, localeCtx]);
  return null;
}

export interface DesktopRootProps {
  initial: DesktopSettings;
  children: ReactNode;
}

export function DesktopRoot({ initial, children }: DesktopRootProps) {
  const [settings, setSettings] = useState(initial);
  // What Rust last told us (or what we last asked for), so echoing a value back from
  // SyncPreferences does not call set_theme / set_locale again.
  const known = useRef({ theme: initial.theme, locale: initial.locale });

  useEffect(
    () =>
      subscribe(() =>
        events.settingsChanged((next) => {
          known.current = { theme: next.theme, locale: next.locale };
          setSettings(next);
        }),
      ),
    [],
  );

  const store = useMemo<PreferenceStore>(
    () => ({
      get: (key) =>
        key === THEME_STORAGE_KEY
          ? initial.theme
          : key === LOCALE_STORAGE_KEY
            ? initial.locale
            : null,
      set: (key, value) => {
        if (key === THEME_STORAGE_KEY && value !== known.current.theme) {
          const theme = value as DesktopSettings['theme'];
          known.current.theme = theme;
          setSettings((s) => ({ ...s, theme }));
          ipc.setTheme(theme).catch(() => {});
        }
        if (key === LOCALE_STORAGE_KEY && value !== known.current.locale) {
          const locale = value as DesktopSettings['locale'];
          known.current.locale = locale;
          setSettings((s) => ({ ...s, locale }));
          ipc.setLocale(locale).catch(() => {});
        }
      },
    }),
    [initial],
  );

  const ctx = useMemo<Ctx>(
    () => ({ settings, patch: (p) => setSettings((s) => ({ ...s, ...p })) }),
    [settings],
  );

  return (
    <SettingsContext.Provider value={ctx}>
      <ThemeProvider storage={store}>
        <LocaleProvider storage={store} messages={coreMessages}>
          <SyncPreferences theme={settings.theme} locale={settings.locale} />
          {children}
        </LocaleProvider>
      </ThemeProvider>
    </SettingsContext.Provider>
  );
}

/** Used until Rust answers (or if it never does): follow the system. */
export const DEFAULT_SETTINGS: DesktopSettings = {
  locale: 'system',
  theme: 'system',
  pasteGuard: { registered: true, detected: true, allowlist: [] },
  onboardingDone: true,
  platform: 'windows',
  versionChanged: false,
};

/** Renders `app` into #root once the settings are loaded. */
export async function mount(app: ReactNode): Promise<void> {
  const initial = await ipc.getSettings().catch(() => DEFAULT_SETTINGS);
  const el = document.getElementById('root');
  if (!el) return;
  createRoot(el).render(
    <StrictMode>
      <DesktopRoot initial={initial}>{app}</DesktopRoot>
    </StrictMode>,
  );
}
