// Strings used by the content side: locales/<lang>/ui-extension.ftl (`ui-ext-*`) and
// pastejack.ftl (pastejacking reasons, which use a Fluent selector), inlined at build time.
import { FluentBundle, FluentResource } from '@fluent/bundle';
import type { Locale } from '@paste-warden/core/types';
import { systemLocale } from '@paste-warden/overlay';
import type { PastejackReason } from './pastejack';
import type { LocaleMode } from './settings';

const sources = import.meta.glob('../../../../locales/*/{ui-extension,pastejack}.ftl', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

export type Translate = (id: string, args?: Record<string, string | number>) => string;

const bundles = new Map<Locale, FluentBundle>();

function bundle(locale: Locale): FluentBundle {
  let b = bundles.get(locale);
  if (b) return b;
  b = new FluentBundle(locale, { useIsolating: false });
  for (const [path, text] of Object.entries(sources)) {
    if (path.includes(`/locales/${locale}/`)) b.addResource(new FluentResource(text));
  }
  bundles.set(locale, b);
  return b;
}

export function translator(locale: Locale): Translate {
  const chain = [bundle(locale), bundle('en')];
  return (id, args) => {
    for (const b of chain) {
      const m = b.getMessage(id);
      if (m?.value) return b.formatPattern(m.value, args);
    }
    return id;
  };
}

/** `system` → zh-TW for any Chinese browser language, else English (same rule as the overlay). */
export function resolveLocale(mode: LocaleMode, languages?: readonly string[]): Locale {
  return mode === 'system' ? systemLocale(languages) : mode;
}

export function pastejackReasonText(t: Translate, r: PastejackReason): string {
  return r.signal ? t(r.id, { signal: r.signal }) : t(r.id);
}
