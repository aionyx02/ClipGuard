// Fails the build when the overlay bundle grows past its budget (phase-3 §3.1: "as small as possible").
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const BUDGET = 15 * 1024;
const file = new URL('../dist/overlay.js', import.meta.url);
const raw = readFileSync(file);
const gz = gzipSync(raw, { level: 9 }).length;
console.log(`overlay.js: ${raw.length} B raw, ${gz} B gzip (budget ${BUDGET} B)`);
if (gz > BUDGET) {
  console.error('overlay bundle is over budget');
  process.exit(1);
}
