import assert from 'node:assert/strict';
import { test } from 'node:test';
import { extractTitle, REPO, rewriteLinks, toStarlightPage } from './sync-docs.mjs';

test('extracts the first heading as the title', () => {
  const { title, body } = extractTitle('# 威脅模型\n\n> intro\n\n## 1. 保護什麼\n');
  assert.equal(title, '威脅模型');
  assert.equal(body, '> intro\n\n## 1. 保護什麼\n');
});

test('rewrites relative links to GitHub and leaves others alone', () => {
  const md = [
    '[roadmap](plan/roadmap.md#8)',
    '[rules](../rules/)',
    '[abs](https://example.invalid/x)',
    '[anchor](#top)',
    '[outside](../../etc/passwd)',
  ].join('\n');
  const out = rewriteLinks(md, 'docs/THREAT_MODEL.md');
  assert.match(out, new RegExp(`\\(${REPO}/blob/dev/docs/plan/roadmap.md#8\\)`));
  assert.match(out, new RegExp(`\\(${REPO}/tree/dev/rules/\\)`));
  assert.match(out, /\(https:\/\/example\.invalid\/x\)/);
  assert.match(out, /\(#top\)/);
  assert.match(out, /\(\.\.\/\.\.\/etc\/passwd\)/);
});

test('produces Starlight frontmatter with an edit link to the source', () => {
  const page = toStarlightPage('# Title "x"\n\nbody', 'docs/spec/detection-rules.md', 20);
  assert.match(page, /^---\ntitle: "Title \\"x\\""\n/);
  assert.match(page, /editUrl: ".*\/edit\/dev\/docs\/spec\/detection-rules.md"/);
  assert.match(page, /order: 20/);
  assert.ok(page.endsWith('body'));
});
