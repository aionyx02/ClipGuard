import { FluentBundle, FluentResource, type FluentVariable } from '@fluent/bundle';
import type { Locale } from '../report';

export const LOCALES: readonly Locale[] = ['zh-TW', 'en'];
export const FALLBACK_LOCALE: Locale = 'en';

/**
 * Every `locales/<lang>/ui*.ftl` file in the repo, inlined at build time by Vite. The same files
 * are embedded by the Rust `paste-warden-i18n` crate, which checks ids match across languages.
 */
const sources = import.meta.glob('../../../../locales/*/ui*.ftl', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

export type MessageArgs = Record<string, FluentVariable>;
export type Translate = (id: string, args?: MessageArgs) => string;

function localeOf(path: string): string | undefined {
  return path.match(/locales\/([^/]+)\//)?.[1];
}

/** Builds one bundle per locale from the build-time sources (plus optional extra messages). */
export function createBundles(
  extra?: Partial<Record<Locale, Record<string, string>>>,
): Map<Locale, FluentBundle> {
  const bundles = new Map<Locale, FluentBundle>();
  for (const locale of LOCALES) {
    // Bidi isolation marks would leak into copied text and tests; UI strings place
    // variables where direction is unambiguous.
    bundles.set(locale, new FluentBundle(locale, { useIsolating: false }));
  }
  for (const [path, text] of Object.entries(sources)) {
    const bundle = bundles.get(localeOf(path) as Locale);
    if (!bundle) continue;
    const errors = bundle.addResource(new FluentResource(text));
    if (errors.length > 0) console.warn(`[paste-warden/ui] ${path}:`, errors[0]?.message);
  }
  // Messages from `@paste-warden/core`'s `messages(locale)` override the build-time copy.
  for (const locale of LOCALES) {
    const messages = extra?.[locale];
    if (!messages) continue;
    const ftl = Object.entries(messages)
      .map(([id, value]) => `${id} = ${value.replace(/\n/g, '\n    ')}`)
      .join('\n');
    bundles.get(locale)?.addResource(new FluentResource(ftl), { allowOverrides: true });
  }
  return bundles;
}

/** Returns a translator for `locale`, falling back to English, then to the id itself. */
export function translator(bundles: Map<Locale, FluentBundle>, locale: Locale): Translate {
  const chain = [bundles.get(locale), bundles.get(FALLBACK_LOCALE)];
  return (id, args) => {
    for (const bundle of chain) {
      const message = bundle?.getMessage(id);
      if (message?.value) return bundle?.formatPattern(message.value, args) ?? id;
    }
    return id;
  };
}

/** Picks zh-TW for any Chinese preference (zh, zh-TW, zh-Hant, zh-HK…), else English. */
export function matchLocale(preferred: readonly string[] | undefined): Locale {
  for (const tag of preferred ?? []) {
    const lower = tag.toLowerCase();
    if (lower.startsWith('zh')) return 'zh-TW';
    if (lower.startsWith('en')) return 'en';
  }
  return FALLBACK_LOCALE;
}
