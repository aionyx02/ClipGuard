// node --test tests/blue/policy.test.mjs  (also run from test_blue_policy.py)
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { decide, pathArgs } from '../../src/redteam/blue/pw-blue-policy.mjs'

const ROOT = '/work/blue'
const st = (max = 150) => ({ calls: 0, maxCalls: max })
const ok = (tool, input) => decide(tool, input, st(), ROOT)

test('writes only under rules/ and corpus/ data dirs', () => {
  assert.equal(ok('write', { filePath: 'rules/command/programs.json' }).allow, true)
  assert.equal(ok('edit', { filePath: `${ROOT}/corpus/cases/redteam-1.jsonl` }).allow, true)
  assert.equal(ok('write', { filePath: '.pw-blue/blue-output.json' }).allow, true)
  for (const p of [
    'crates/core/src/lib.rs',
    'xtask/src/main.rs',
    '.github/workflows/ci.yml',
    '.opencode/plugins/pw-blue-guard.ts',
    'corpus/README.md',
    'rulesx/a.json',
    '../outside/rules/a.json',
    '/etc/passwd',
    'rules/../crates/core/src/lib.rs',
    '.pw-blue/store/x.jsonl',
  ]) {
    assert.equal(ok('write', { filePath: p }).allow, false, p)
  }
  assert.equal(ok('write', { content: 'x' }).reason, 'write-without-path')
})

test('patch bodies are checked by their file headers', () => {
  const good = '*** Begin Patch\n*** Update File: rules/command/programs.json\n@@\n-a\n+b\n*** End Patch'
  const bad = '*** Begin Patch\n*** Update File: rules/a.json\n*** Add File: crates/core/src/x.rs\n*** End Patch'
  assert.equal(ok('patch', { patchText: good }).allow, true)
  assert.equal(ok('patch', { patchText: bad }).allow, false)
  assert.deepEqual(pathArgs({ diff: '--- a/rules/x.json\n+++ b/rules/x.json' }), ['rules/x.json', 'rules/x.json'])
})

test('reads cannot reach redteam/, .git or outside the worktree', () => {
  assert.equal(ok('read', { filePath: 'rules/context.json' }).allow, true)
  assert.equal(ok('grep', { pattern: 'x', path: 'corpus' }).allow, true)
  assert.equal(ok('read', { filePath: '.pw-blue/blue-input.jsonl' }).allow, true)
  assert.equal(ok('read', { filePath: 'redteam/eval/heldout.jsonl' }).allow, false)
  assert.equal(ok('glob', { pattern: '*', path: '.git' }).allow, false)
  assert.equal(ok('read', { filePath: '/Users/someone/.ssh/id_ed25519' }).allow, false)
})

test('reads cannot reach engine code or docs (keeps the context small)', () => {
  assert.equal(ok('read', { filePath: 'rules/command/signals.json' }).allow, true)
  assert.equal(ok('glob', { pattern: 'corpus/cases/*.jsonl' }).allow, true)
  assert.equal(ok('read', { filePath: 'crates/core/src/command/verdict.rs' }).reason, 'read-engine-or-docs')
  assert.equal(ok('read', { filePath: 'docs/spec/detection-rules.md' }).allow, false)
  assert.equal(ok('read', { filePath: 'xtask/src/main.rs' }).allow, false)
  assert.equal(ok('grep', { pattern: 'x', path: 'crates' }).allow, false)
  assert.equal(ok('glob', { pattern: 'crates/core/src/**/*.rs' }).allow, false)
  assert.equal(ok('glob', { pattern: './docs/**' }).allow, false)
})

test('shell: exact allowlisted prefixes, no chaining', () => {
  assert.equal(ok('shell', { command: 'cargo run -p xtask -- corpus run' }).allow, true)
  assert.equal(ok('bash', { command: 'cargo test -p paste-warden-rules' }).allow, true)
  for (const c of [
    'cargo run -p xtask -- corpus run; rm -rf ~',
    'cargo run -p xtask -- corpus run && git push',
    'cargo run -p xtask -- corpus run | sh',
    'cargo run -p xtask -- corpus run > rules/x.json',
    'cargo run -p xtask -- corpus $(id)',
    'cargo run -p xtask -- corpus `id`',
    'cargo run -p xtask -- corpus run\ngit push',
    'git push origin dev',
    'gh pr merge 1',
    'cargo build',
    '',
  ]) {
    assert.equal(ok('shell', { command: c }).allow, false, JSON.stringify(c))
  }
})

test('add-from-run only reads the bypass-only store', () => {
  const add = 'cargo run -p xtask -- corpus add-from-run '
  assert.equal(ok('shell', { command: `${add}.pw-blue/store v1 --expect malicious` }).allow, true)
  assert.equal(ok('shell', { command: `${add}../redteam/runs/r1 v1 --expect malicious` }).allow, false)
  assert.equal(ok('shell', { command: `${add}redteam/eval v1 --expect malicious` }).allow, false)
})

test('unknown and network tools are denied', () => {
  for (const t of ['webfetch', 'websearch', 'task', 'mcp__x__y', 'paste-warden_analyze', 'newtool']) {
    assert.equal(ok(t, {}).allow, false, t)
  }
})

test('tool-call limit blocks everything after the cap', () => {
  const s = st(2)
  assert.equal(decide('read', { filePath: 'rules/a.json' }, s, ROOT).allow, true)
  assert.equal(decide('read', { filePath: 'rules/a.json' }, s, ROOT).allow, true)
  assert.equal(decide('read', { filePath: 'rules/a.json' }, s, ROOT).reason, 'tool-call-limit')
})
