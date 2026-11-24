import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import type { Locale } from '../report';
import { localPreferenceStore, type PreferenceStore } from '../storage';
import { createBundles, matchLocale, type Translate, translator } from './fluent';

export type LocaleMode = 'system' | Locale;
export const LOCALE_STORAGE_KEY = 'paste-warden:locale';

interface LocaleContextValue {
  mode: LocaleMode;
  locale: Locale;
  setMode: (mode: LocaleMode) => void;
  t: Translate;
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

function isLocaleMode(value: unknown): value is LocaleMode {
  return value === 'system' || value === 'zh-TW' || value === 'en';
}

function systemLanguages(): readonly string[] {
  const nav = globalThis.navigator;
  if (!nav) return [];
  return nav.languages?.length ? nav.languages : [nav.language];
}

export interface LocaleProviderProps {
  children: ReactNode;
  /** Used when nothing is stored. Default `system`. */
  defaultMode?: LocaleMode;
  /** Where the choice is persisted; `null` disables persistence. Default `localStorage`. */
  storage?: PreferenceStore | null;
  /** Extra / overriding messages, e.g. `messages(locale)` from `@paste-warden/core`. */
  messages?: Partial<Record<Locale, Record<string, string>>>;
  /** Set `lang` on <html>. Default true; pass false when embedding in someone else's page. */
  setDocumentLang?: boolean;
}

/**
 * System / 繁中 / English. `system` follows `navigator.languages` and reacts to the browser's
 * `languagechange` event. Strings come from `locales/<lang>/ui*.ftl` (Fluent).
 */
export function LocaleProvider({
  children,
  defaultMode = 'system',
  storage = localPreferenceStore,
  messages,
  setDocumentLang = true,
}: LocaleProviderProps) {
  const [mode, setModeState] = useState<LocaleMode>(() => {
    const stored = storage?.get(LOCALE_STORAGE_KEY);
    return isLocaleMode(stored) ? stored : defaultMode;
  });
  const [systemLocale, setSystemLocale] = useState<Locale>(() => matchLocale(systemLanguages()));

  useEffect(() => {
    const onChange = () => setSystemLocale(matchLocale(systemLanguages()));
    globalThis.addEventListener?.('languagechange', onChange);
    return () => globalThis.removeEventListener?.('languagechange', onChange);
  }, []);

  const locale: Locale = mode === 'system' ? systemLocale : mode;
  const bundles = useMemo(() => createBundles(messages), [messages]);
  const t = useMemo(() => translator(bundles, locale), [bundles, locale]);

  useEffect(() => {
    if (setDocumentLang && globalThis.document) document.documentElement.lang = locale;
  }, [locale, setDocumentLang]);

  const setMode = useCallback(
    (next: LocaleMode) => {
      setModeState(next);
      storage?.set(LOCALE_STORAGE_KEY, next);
    },
    [storage],
  );

  const value = useMemo(() => ({ mode, locale, setMode, t }), [mode, locale, setMode, t]);
  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

export function useLocale(): LocaleContextValue {
  const ctx = useContext(LocaleContext);
  if (!ctx) throw new Error('useLocale must be used inside <LocaleProvider>');
  return ctx;
}

/** Shorthand for components that only need strings. */
export function useT(): Translate {
  return useLocale().t;
}
