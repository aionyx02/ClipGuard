// Post-build checks for apps/web/dist (run by `pnpm build`):
// - the CSP meta is there and only allows 'self';
// - every asset URL in index.html is relative (the site is served under / or /<repo>/);
// - both engine builds shipped: the .wasm and the wasm2js fallback chunk;
// - the initial JS (what index.html loads) stays small: the engine is lazy-loaded.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const dist = fileURLToPath(new URL('../dist/', import.meta.url));
const INITIAL_JS_BUDGET_GZ = 120 * 1024;
const problems = [];

const html = readFileSync(join(dist, 'index.html'), 'utf8');
const csp = html
  .match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1]
  ?.replaceAll('&#39;', "'");
if (!csp) problems.push('index.html: no Content-Security-Policy meta');
else if (!/connect-src 'self'(;|$)/.test(csp))
  problems.push(`CSP connect-src is not 'self' only: ${csp}`);
for (const [, url] of html.matchAll(/(?:src|href)="([^"]+)"/g)) {
  if (/^(\/|https?:)/.test(url)) problems.push(`index.html: non-relative URL ${url}`);
}

const assets = readdirSync(join(dist, 'assets'));
if (!assets.some((f) => f.endsWith('.wasm'))) problems.push('no .wasm in dist/assets');
const jsFiles = assets.filter((f) => f.endsWith('.js'));
const raw = jsFiles.find((f) =>
  readFileSync(join(dist, 'assets', f), 'utf8').includes('pw_analyze'),
);
if (!raw) problems.push('no wasm2js fallback chunk (pw_analyze) in dist/assets');

const entry = [...html.matchAll(/<script type="module"[^>]*src="\.\/assets\/([^"]+)"/g)].map(
  (m) => m[1],
);
let initial = 0;
for (const f of entry) initial += gzipSync(readFileSync(join(dist, 'assets', f))).length;
if (entry.length === 0) problems.push('index.html: no module entry script');
if (initial > INITIAL_JS_BUDGET_GZ) {
  problems.push(
    `initial JS ${(initial / 1024).toFixed(1)} KiB gz > budget ${INITIAL_JS_BUDGET_GZ / 1024} KiB`,
  );
}

const total = assets.reduce((n, f) => n + statSync(join(dist, 'assets', f)).size, 0);
console.log(
  `web dist: initial JS ${(initial / 1024).toFixed(1)} KiB gz, all assets ${(total / 1024).toFixed(0)} KiB raw`,
);
if (problems.length > 0) {
  for (const p of problems) console.error(`✗ ${p}`);
  process.exit(1);
}
console.log('✓ CSP, relative URLs, wasm + wasm2js present');
