import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { localPreferenceStore, mediaMatches, type PreferenceStore, watchMedia } from '../storage';

export type ThemeMode = 'system' | 'light' | 'dark';
export type ResolvedTheme = 'light' | 'dark';

export const THEME_STORAGE_KEY = 'paste-warden:theme';
const DARK_QUERY = '(prefers-color-scheme: dark)';

interface ThemeContextValue {
  /** What the user picked. */
  mode: ThemeMode;
  /** What is applied right now (`system` resolved through `prefers-color-scheme`). */
  resolved: ResolvedTheme;
  setMode: (mode: ThemeMode) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

function isThemeMode(value: unknown): value is ThemeMode {
  return value === 'system' || value === 'light' || value === 'dark';
}

export interface ThemeProviderProps {
  children: ReactNode;
  /** Used when nothing is stored. Default `system`. */
  defaultMode?: ThemeMode;
  /** Where the choice is persisted; `null` disables persistence. Default `localStorage`. */
  storage?: PreferenceStore | null;
  /** Element that receives `data-theme`. Default `document.documentElement`. */
  target?: HTMLElement | null;
}

/**
 * System / light / dark. `system` follows `prefers-color-scheme` live (no reload). The resolved
 * theme is written to `data-theme` on the target element, which switches the CSS tokens.
 */
export function ThemeProvider({
  children,
  defaultMode = 'system',
  storage = localPreferenceStore,
  target,
}: ThemeProviderProps) {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    const stored = storage?.get(THEME_STORAGE_KEY);
    return isThemeMode(stored) ? stored : defaultMode;
  });
  const [systemDark, setSystemDark] = useState(() => mediaMatches(DARK_QUERY));

  useEffect(() => watchMedia(DARK_QUERY, setSystemDark), []);

  const resolved: ResolvedTheme = mode === 'system' ? (systemDark ? 'dark' : 'light') : mode;

  useEffect(() => {
    const el = target ?? globalThis.document?.documentElement;
    if (!el) return;
    el.dataset.theme = resolved;
    el.style.colorScheme = resolved;
  }, [resolved, target]);

  const setMode = useCallback(
    (next: ThemeMode) => {
      setModeState(next);
      storage?.set(THEME_STORAGE_KEY, next);
    },
    [storage],
  );

  const value = useMemo(() => ({ mode, resolved, setMode }), [mode, resolved, setMode]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used inside <ThemeProvider>');
  return ctx;
}
