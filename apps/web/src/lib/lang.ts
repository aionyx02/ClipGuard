// `?lang=en` / `?lang=zh-TW` in the URL selects the language and wins over the stored choice,
// so a shared link opens in the sender's language. Changing the language rewrites the parameter
// (history.replaceState: no reload, no new history entry). Phase 3 §3.5.
import type { Locale } from '@paste-warden/core';
import { LOCALE_STORAGE_KEY, type LocaleMode, type PreferenceStore } from '@paste-warden/ui';

/** Normalizes a `lang` parameter: `zh`, `zh-tw`, `zh-Hant` → `zh-TW`; `en`, `en-US` → `en`. */
export function parseLang(value: string | null | undefined): Locale | undefined {
  const v = value?.trim().toLowerCase();
  if (!v) return undefined;
  if (v.startsWith('zh')) return 'zh-TW';
  if (v.startsWith('en')) return 'en';
  return undefined;
}

/** The URL with `lang` set (or removed for `system`), keeping every other part. */
export function withLang(href: string, mode: LocaleMode): string {
  const url = new URL(href);
  if (mode === 'system') url.searchParams.delete('lang');
  else url.searchParams.set('lang', mode);
  return url.toString();
}

/** Wraps a store so the locale key reads `?lang=` first and writes it back into the URL. */
export function urlLocaleStore(inner: PreferenceStore, win: Window = window): PreferenceStore {
  return {
    get(key) {
      if (key === LOCALE_STORAGE_KEY) {
        const fromUrl = parseLang(new URLSearchParams(win.location.search).get('lang'));
        if (fromUrl) return fromUrl;
      }
      return inner.get(key);
    },
    set(key, value) {
      inner.set(key, value);
      if (key !== LOCALE_STORAGE_KEY) return;
      const mode = value === 'system' || parseLang(value) ? (value as LocaleMode) : 'system';
      const next = withLang(win.location.href, mode);
      if (next !== win.location.href) win.history.replaceState(win.history.state, '', next);
    },
  };
}
