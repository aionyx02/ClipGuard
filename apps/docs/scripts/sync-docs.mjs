// Copies the canonical specs from ../../docs into the Starlight content tree at build time, so
// the site never drifts from the repo. Edit the originals; the copies are gitignored.
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, posix, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO = 'https://github.com/aionyx02/paste-warden';
export const BRANCH = 'dev';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const outDir = join(here, '..', 'src', 'content', 'docs', 'dev', 'generated');
// Charts are served from public/ (gitignored): the page shows the light or the dark SVG
// depending on Starlight's data-theme, which a plain Markdown image cannot do.
const chartDir = join(here, '..', 'public', 'dev', 'redteam-report');
const base = process.env.DOCS_BASE ?? '/docs/';

/** phase-5.md §5.13: `redteam report --out redteam/reports` output, when it exists. */
export const REPORT = [
  'redteam/reports/report.md',
  'redteam-report',
  30,
  '紅藍隊報表 Red-team report',
];

/** [source path in the repo, output slug, sidebar order, sidebar label] */
export const SOURCES = [
  ['docs/THREAT_MODEL.md', 'threat-model', 10, '威脅模型 Threat model'],
  ['docs/spec/detection-rules.md', 'detection-rules', 20, '偵測規格 Detection spec'],
];

/** Splits off the first `# Title` line. */
export function extractTitle(markdown) {
  const match = markdown.match(/^#\s+(.+?)\s*$/m);
  if (!match) return { title: 'Untitled', body: markdown };
  const body = markdown.slice(0, match.index) + markdown.slice(match.index + match[0].length);
  return { title: match[1], body: body.replace(/^\s*\n/, '') };
}

/** Relative links would break once the file moves; point them at the file on GitHub. */
export function rewriteLinks(markdown, sourcePath) {
  const sourceDir = posix.dirname(sourcePath);
  return markdown.replace(/(!?\[[^\]]*\]\()([^)\s]+)(\))/g, (whole, open, target, close) => {
    if (/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(target)) return whole;
    const [path, hash = ''] = target.split('#');
    const resolved = posix.normalize(posix.join(sourceDir, path));
    if (resolved.startsWith('..')) return whole;
    const kind = path.endsWith('/') ? 'tree' : 'blob';
    return `${open}${REPO}/${kind}/${BRANCH}/${resolved}${hash ? `#${hash}` : ''}${close}`;
  });
}

/**
 * `![alt](name.svg)` -> a light and a dark <img>; theme.css hides the one that does not match
 * Starlight's resolved theme. `chartBase` is the URL the SVGs are copied to.
 */
export function themedCharts(markdown, chartBase) {
  return markdown.replace(/!\[([^\]]*)\]\(([a-z0-9-]+)\.svg\)/g, (_, alt, name) => {
    const a = alt.replace(/"/g, '&quot;');
    return [
      `<img class="pw-chart-light" src="${chartBase}${name}.svg" alt="${a}" />`,
      `<img class="pw-chart-dark" src="${chartBase}${name}-dark.svg" alt="${a}" />`,
    ].join('\n');
  });
}

function yamlString(value) {
  return JSON.stringify(value);
}

export function toStarlightPage(markdown, sourcePath, order, label) {
  const { title, body } = extractTitle(markdown);
  const editUrl = `${REPO}/edit/${BRANCH}/${sourcePath}`;
  const front = [
    '---',
    `title: ${yamlString(title)}`,
    `editUrl: ${yamlString(editUrl)}`,
    'sidebar:',
    `  order: ${order}`,
    ...(label ? [`  label: ${yamlString(label)}`] : []),
    '---',
    '',
    ':::note[自動產生 · Generated]',
    `本頁在建置時由 [\`${sourcePath}\`](${REPO}/blob/${BRANCH}/${sourcePath}) 複製而來，請修改原始檔。`,
    `This page is copied from \`${sourcePath}\` at build time and is maintained in Traditional Chinese.`,
    ':::',
    '',
  ].join('\n');
  return front + rewriteLinks(body, sourcePath);
}

export function sync() {
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  for (const [source, slug, order, label] of SOURCES) {
    const markdown = readFileSync(join(repoRoot, source), 'utf8');
    writeFileSync(join(outDir, `${slug}.md`), toStarlightPage(markdown, source, order, label));
    console.log(`synced ${source} -> ${relative(repoRoot, join(outDir, `${slug}.md`))}`);
  }
  syncReport();
}

function syncReport() {
  rmSync(chartDir, { recursive: true, force: true });
  const [source, slug, order, label] = REPORT;
  const src = join(repoRoot, source);
  if (!existsSync(src)) {
    console.log(`no ${source}: red-team report page skipped`);
    return;
  }
  mkdirSync(chartDir, { recursive: true });
  const srcDir = dirname(src);
  for (const name of readdirSync(srcDir).filter((n) => n.endsWith('.svg'))) {
    copyFileSync(join(srcDir, name), join(chartDir, name));
  }
  const markdown = themedCharts(readFileSync(src, 'utf8'), `${base}dev/redteam-report/`);
  writeFileSync(join(outDir, `${slug}.md`), toStarlightPage(markdown, source, order, label));
  console.log(`synced ${source} (+ charts) -> ${relative(repoRoot, join(outDir, `${slug}.md`))}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) sync();
