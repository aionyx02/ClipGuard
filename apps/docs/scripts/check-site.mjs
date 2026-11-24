// Post-build smoke check: the pages phase-3 §3.6 promises exist in both languages, links use
// the configured base (DOCS_BASE, default /docs/), and the built install pages contain no `xattr`.
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const dist = fileURLToPath(new URL('../dist/', import.meta.url));
const base = process.env.DOCS_BASE ?? '/docs/';
const pages = [
  '',
  'user/install/chrome-edge/',
  'user/install/firefox/',
  'user/install/userscript/',
  'user/install/desktop/',
  'user/features/',
  'user/privacy/',
  'dev/',
  'dev/agent-hooks/',
  'dev/mcp/',
  'dev/generated/threat-model/',
  'dev/generated/detection-rules/',
];
const problems = [];
for (const locale of ['', 'en/']) {
  for (const page of pages) {
    const file = `${dist}${locale}${page}index.html`;
    if (!existsSync(file)) {
      problems.push(`missing ${locale}${page}`);
      continue;
    }
    const html = readFileSync(file, 'utf8');
    if (!html.includes(`href="${base}`)) problems.push(`${locale}${page}: no ${base} base links`);
    if (page.startsWith('user/') && /xattr/i.test(html)) problems.push(`${locale}${page}: xattr`);
  }
}
if (problems.length > 0) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`site ok: ${pages.length * 2} pages checked`);
