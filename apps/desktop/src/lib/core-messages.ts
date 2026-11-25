// The shared LocaleProvider bundles `locales/*/ui*.ftl`. Errors from `register_secret` carry
// core message ids (`registered-*`, docs/spec/detection-rules.md §5.1) that live in
// `registered.ftl`, so the desktop app adds that file on top.
import type { Locale } from '@paste-warden/ui';

const sources = import.meta.glob('../../../../locales/*/registered.ftl', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

/**
 * Splits a Fluent file into `{ id: source pattern }`. Enough for LocaleProvider's `messages`
 * (which writes each entry back as `id = pattern`): messages start at column 0, continuation
 * lines (select expressions) are kept verbatim, comments and blank lines end a message.
 */
export function parseFtl(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  let current: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    const start = line.match(/^([a-z][a-z0-9-]*)\s*=\s?(.*)$/);
    if (start?.[1] !== undefined) {
      current = start[1];
      out[current] = start[2] ?? '';
    } else if (line.trim() === '' || line.startsWith('#')) {
      current = null;
    } else if (current) {
      out[current] = `${out[current]}\n${line.trimStart()}`;
    }
  }
  return out;
}

function build(): Partial<Record<Locale, Record<string, string>>> {
  const out: Partial<Record<Locale, Record<string, string>>> = {};
  for (const [path, text] of Object.entries(sources)) {
    const locale = path.match(/locales\/([^/]+)\//)?.[1];
    if (locale !== 'zh-TW' && locale !== 'en') continue;
    out[locale] = { ...out[locale], ...parseFtl(text) };
  }
  return out;
}

export const coreMessages = build();
