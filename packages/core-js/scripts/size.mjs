// Size budget (docs/plan/phase-2.md §2.6): the gzip'd .wasm must stay under 1.5 MB.
// The wasm2js fallback has no hard budget (it is loaded only on demand) but is reported.
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';

const dist = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const BUDGET_GZIP = 1_500_000;

const files = [
  ['wasm/paste_warden_bg.wasm', BUDGET_GZIP],
  ['wasm2js/paste_warden_raw.js', undefined],
];
let ok = true;
for (const [file, budget] of files) {
  const bytes = readFileSync(join(dist, file));
  const gz = gzipSync(bytes, { level: 9 }).length;
  const br = brotliCompressSync(bytes, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length;
  const over = budget !== undefined && gz >= budget;
  ok &&= !over;
  console.log(
    `${file}: raw ${bytes.length} B, gzip ${gz} B, brotli ${br} B${budget ? ` (budget gzip < ${budget} B)` : ''}${over ? '  OVER BUDGET' : ''}`,
  );
}
if (!ok) process.exit(1);
