import type { Locale } from '@paste-warden/core';

export const REPO_URL = 'https://github.com/aionyx02/paste-warden';
export const RELEASES_URL = `${REPO_URL}/releases`;

/**
 * A page of the docs site, which is deployed next to the playground at `./docs/` (zh-TW is the
 * root locale, English lives under `en/`). Relative, so it works under `/` and `/<repo>/`.
 */
export function docsUrl(locale: Locale, path = ''): string {
  const clean = path.replace(/^\/+/, '');
  return locale === 'en' ? `./docs/en/${clean}` : `./docs/${clean}`;
}
