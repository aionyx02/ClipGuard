// PasteWarden blue-team tool policy (docs/plan/phase-5.md §5.5.1).
// Pure decision logic for pw-blue-guard.ts; tested by tests/blue/policy.test.mjs.
// Default deny: a tool or argument shape this file does not know is blocked.
import path from 'node:path'

// Writable trees (repo-relative, POSIX separators).
export const WRITE_PREFIXES = [
  'rules/',
  'corpus/cases/',
  'corpus/benign/',
  'corpus/divergences/',
]

// The orchestrator's hand-off directory inside the worktree (git-excluded):
// blue-input.jsonl and the bypass-only run store are read here, and the only
// file the agent may write here is its equivalence verdicts.
export const HANDOFF_DIR = '.pw-blue'
export const HANDOFF_OUTPUT = '.pw-blue/blue-output.json'
export const HANDOFF_STORE = '.pw-blue/store'
const ADD_FROM_RUN = 'cargo run -p xtask -- corpus add-from-run '

// Never readable even if present (the orchestrator also leaves redteam/ out
// of the sparse checkout, so these normally do not exist at all).
export const READ_DENY_PREFIXES = ['redteam/', '.git/', '.opencode/']

// Engine code and docs: the agent cannot change them, and reading them is
// what grew round 1's context to ~184k tokens (3 minutes per step). The task
// prompt carries the spec summary it needs instead.
export const CONTEXT_DENY_PREFIXES = ['crates/', 'docs/', 'xtask/', 'target/']

// The only shell commands allowed, as exact prefixes.
export const SHELL_PREFIXES = [
  'cargo run -p xtask -- corpus ',
  'cargo test -p paste-warden-rules',
  'cargo test -p paste-warden-core',
]

// Shell metacharacters that could chain or redirect a second command.
const SHELL_META = /[;&|`<>\n\r]|\$\(|\$\{/

const READ_TOOLS = new Set(['read', 'glob', 'grep', 'list'])
const WRITE_TOOLS = new Set(['write', 'edit', 'patch', 'multiedit'])
const OTHER_ALLOWED = new Set(['shell', 'bash', 'todowrite', 'todoread'])

export const DEFAULT_MAX_TOOL_CALLS = 150

function deny(reason) {
  return { allow: false, reason }
}

// Repo-relative POSIX path for `p`, or null when it escapes `root`.
export function relInside(root, p, cwd = root) {
  if (typeof p !== 'string' || p === '' || p.includes('\0')) return null
  const abs = path.resolve(cwd, p)
  const rel = path.relative(root, abs)
  if (rel.startsWith('..') || path.isAbsolute(rel)) return null
  return rel.split(path.sep).join('/')
}

function startsWithAny(rel, prefixes) {
  const r = rel === '' ? '' : rel
  return prefixes.some((pre) => r === pre.replace(/\/$/, '') || r.startsWith(pre))
}

// Every argument value that names a path: keys like path, filePath, file,
// paths, cwd, directory. Patch bodies are parsed for their file headers.
export function pathArgs(input) {
  const out = []
  if (!input || typeof input !== 'object') return out
  for (const [key, value] of Object.entries(input)) {
    const k = key.toLowerCase()
    const pathy =
      k.includes('path') || k.includes('file') || k === 'cwd' || k.includes('dir')
    if (pathy) {
      if (typeof value === 'string') out.push(value)
      else if (Array.isArray(value)) {
        for (const v of value) if (typeof v === 'string') out.push(v)
      } else if (value != null) out.push(String(value))
    }
    if (typeof value === 'string' && (k.includes('patch') || k === 'diff')) {
      const re = /^\*\*\* (?:Add|Update|Delete) File: (.+)$|^(?:\+\+\+|---) (?:[ab]\/)?(.+)$/gm
      for (const m of value.matchAll(re)) {
        const p = (m[1] ?? m[2] ?? '').trim()
        if (p && p !== '/dev/null') out.push(p)
      }
    }
  }
  return out
}

// state: { calls: number, maxCalls: number }
export function decide(tool, input, state, root) {
  state.calls += 1
  if (state.calls > state.maxCalls) return deny('tool-call-limit')
  const t = String(tool ?? '').toLowerCase()

  if (READ_TOOLS.has(t)) {
    const paths = pathArgs(input)
    for (const p of paths) {
      const rel = relInside(root, p)
      if (rel === null) return deny('read-outside-worktree')
      if (startsWithAny(rel, READ_DENY_PREFIXES)) return deny('read-denied-path')
      if (startsWithAny(rel, CONTEXT_DENY_PREFIXES)) return deny('read-engine-or-docs')
    }
    // A glob pattern can name a tree on its own (`crates/**/*.rs`).
    if (t === 'glob' && input && typeof input.pattern === 'string') {
      const rel = relInside(root, input.pattern.replace(/^\.\//, ''))
      if (rel !== null && startsWithAny(rel, [...READ_DENY_PREFIXES, ...CONTEXT_DENY_PREFIXES])) {
        return deny('read-engine-or-docs')
      }
    }
    return { allow: true }
  }

  if (WRITE_TOOLS.has(t)) {
    const paths = pathArgs(input)
    if (paths.length === 0) return deny('write-without-path')
    for (const p of paths) {
      const rel = relInside(root, p)
      if (rel === null) return deny('write-outside-worktree')
      if (rel === HANDOFF_OUTPUT) continue
      if (!startsWithAny(rel, WRITE_PREFIXES)) return deny('write-denied-path')
    }
    return { allow: true }
  }

  if (t === 'shell' || t === 'bash') {
    const cmd = input && typeof input.command === 'string' ? input.command.trim() : ''
    if (!cmd) return deny('shell-without-command')
    if (SHELL_META.test(cmd)) return deny('shell-metacharacter')
    if (!SHELL_PREFIXES.some((pre) => cmd === pre.trim() || cmd.startsWith(pre))) {
      return deny('shell-not-allowlisted')
    }
    // Corpus additions may only copy from the bypass-only store.
    if (cmd.startsWith(ADD_FROM_RUN)) {
      const store = cmd.slice(ADD_FROM_RUN.length).trim().split(/\s+/)[0]
      if (relInside(root, store) !== HANDOFF_STORE) {
        return deny('add-from-run-store')
      }
    }
    // A workdir argument must stay inside the worktree.
    for (const p of pathArgs(input)) {
      if (relInside(root, p) === null) return deny('shell-outside-worktree')
    }
    return { allow: true }
  }

  if (OTHER_ALLOWED.has(t)) return { allow: true }
  // webfetch, websearch, task (sub-agents), MCP tools, anything new.
  return deny('tool-not-allowed')
}
