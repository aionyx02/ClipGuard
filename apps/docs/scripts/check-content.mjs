// Content rules for the hand-written pages (roadmap §8, phase-3 §3.6):
// - never mention `xattr`: install docs must not teach users to paste a quarantine-removal
//   command — that is exactly the ClickFix pattern PasteWarden blocks;
// - every zh-TW page has an English counterpart.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../src/content/docs/', import.meta.url));

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === 'generated' ? [] : walk(path);
    return /\.mdx?$/.test(name) ? [path] : [];
  });
}

const problems = [];
// `/`-separated on every OS: on Windows `relative` returns `en\…`, which never
// matched the `en/` checks below.
const pages = walk(root).map((p) => relative(root, p).split(sep).join('/'));
for (const page of pages) {
  const text = readFileSync(join(root, page), 'utf8');
  if (/xattr/i.test(text)) problems.push(`${page}: mentions xattr (roadmap §8)`);
}
for (const page of pages.filter((p) => !p.startsWith('en/'))) {
  if (!pages.includes(`en/${page}`)) problems.push(`${page}: missing English page en/${page}`);
}
if (problems.length > 0) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`content ok: ${pages.length} hand-written pages`);
