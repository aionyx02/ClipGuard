import type { Locale } from '@paste-warden/ui/report';

/**
 * `locales/<lang>/ui-overlay.ftl`, inlined at build time. That file only uses single-line
 * messages with plain `{ $var }` placeables, so a few lines of parsing replace @fluent/bundle
 * (which alone would eat most of the overlay's size budget).
 */
const sources = import.meta.glob('../../../locales/*/ui-overlay.ftl', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

export type Strings = Record<string, string>;

export function parseFtl(source: string): Strings {
  const out: Strings = {};
  for (const line of source.split('\n')) {
    const m = /^([a-z][a-z0-9-]*)\s*=\s*(.*)$/.exec(line);
    if (m?.[1] && m[2] !== undefined) out[m[1]] = m[2].trim();
  }
  return out;
}

const table: Partial<Record<Locale, Strings>> = {};
for (const [path, text] of Object.entries(sources)) {
  const lang = /locales\/([^/]+)\//.exec(path)?.[1] as Locale | undefined;
  if (lang) table[lang] = { ...table[lang], ...parseFtl(text) };
}

export function stringsFor(locale: Locale): Strings {
  return { ...table.en, ...table[locale] };
}

/** zh-TW for any Chinese UI language, else English. Follows the browser (= OS) language. */
export function systemLocale(languages?: readonly string[]): Locale {
  const langs = languages ?? globalThis.navigator?.languages ?? [];
  for (const tag of langs) {
    const lower = tag.toLowerCase();
    if (lower.startsWith('zh')) return 'zh-TW';
    if (lower.startsWith('en')) return 'en';
  }
  return 'en';
}

export function format(strings: Strings, id: string, args?: Record<string, string | number>) {
  const pattern = strings[id] ?? id;
  return pattern.replace(/\{\s*\$([a-z0-9_-]+)\s*\}/gi, (_, key: string) =>
    String(args?.[key] ?? ''),
  );
}
