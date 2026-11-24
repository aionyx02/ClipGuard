// Runs corpus cases (corpus/cases/*.jsonl) through the JS API, with the same
// expectation semantics as crates/conformance (check.rs, ops/{command,secret,hidden}.rs).
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

/** crates/core/src/limits.rs `MAX_ANALYZED_CHARS`. */
const MAX_ANALYZED_CHARS = 1 << 20;

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const CHARSETS = {
  hex: '0123456789abcdef',
  HEX: '0123456789ABCDEF',
  alnum: UPPER + LOWER + DIGITS,
  lower: LOWER + DIGITS,
  upper: UPPER + DIGITS,
  digits: DIGITS,
  base64: `${UPPER}${LOWER}${DIGITS}+/`,
  base64url: `${UPPER}${LOWER}${DIGITS}-_`,
};

/** corpus/README.md §2 Text. */
export function text(v) {
  if (typeof v === 'string') return v;
  if (v && typeof v === 'object') {
    if (Array.isArray(v.parts)) return v.parts.map(text).join('');
    if (v.rand) {
      const { seed, charset, len, skip = 0 } = v.rand;
      const cs = [...(CHARSETS[charset] ?? charset)];
      let state = seed >>> 0;
      const next = () => {
        state = (Math.imul(state, 1103515245) + 12345) & 0x7fffffff;
        return cs[(state >>> 8) % cs.length];
      };
      for (let i = 0; i < skip; i++) next();
      let out = '';
      for (let i = 0; i < len; i++) out += next();
      return out;
    }
    if (v.repeat) return text(v.repeat.text).repeat(v.repeat.count);
  }
  throw new Error(`not a Text: ${JSON.stringify(v)}`);
}

const isText = (v) =>
  v &&
  typeof v === 'object' &&
  !Array.isArray(v) &&
  Object.keys(v).length === 1 &&
  ('parts' in v || 'rand' in v || 'repeat' in v);

/** Resolves Text objects anywhere inside an expectation. */
function resolveAll(v) {
  if (isText(v)) return text(v);
  if (Array.isArray(v)) return v.map(resolveAll);
  if (v && typeof v === 'object')
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, resolveAll(x)]));
  return v;
}

const strings = (v) =>
  Array.isArray(v)
    ? v.map((x) => (typeof x === 'string' ? x : text(x)))
    : [typeof v === 'string' ? v : text(v)];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** check.rs `partial_match`: undefined when it matches, else a reason. */
function partialMatch(e, a) {
  if (
    e &&
    typeof e === 'object' &&
    !Array.isArray(e) &&
    a &&
    typeof a === 'object' &&
    !Array.isArray(a)
  ) {
    for (const [k, ev] of Object.entries(e)) {
      if (k in a) {
        const why = partialMatch(ev, a[k]);
        if (why) return `${k}: ${why}`;
        continue;
      }
      if (k.endsWith('_not_contain')) {
        const hay = a[k.slice(0, -'_not_contain'.length)] ?? '';
        for (const s of strings(ev)) if (hay.includes(s)) return `${k}: ${hay} contains ${s}`;
        continue;
      }
      if (k.endsWith('_contain')) {
        const hay = a[k.slice(0, -'_contain'.length)] ?? '';
        for (const s of strings(ev)) if (!hay.includes(s)) return `${k}: ${hay} lacks ${s}`;
        continue;
      }
      if (ev === null) continue;
      return `${k}: missing`;
    }
    return undefined;
  }
  return same(e, a) ? undefined : `expected ${JSON.stringify(e)}, got ${JSON.stringify(a)}`;
}

/** Expectation checker: every key must be consumed, like conformance's `Expect`. */
class Expect {
  constructor(exp) {
    this.rest = { ...resolveAll(exp) };
    this.failures = [];
  }
  take(k) {
    const v = this.rest[k];
    delete this.rest[k];
    return v;
  }
  fail(m) {
    this.failures.push(m);
  }
  eq(k, actual) {
    const e = this.take(k);
    if (e !== undefined && !same(e, actual))
      this.fail(`${k}: expected ${JSON.stringify(e)}, got ${JSON.stringify(actual)}`);
  }
  ne(k, actual) {
    const e = this.take(k);
    if (e !== undefined && same(e, actual)) this.fail(`${k}: got ${JSON.stringify(actual)}`);
  }
  includeAll(k, actual) {
    const e = this.take(k);
    if (e !== undefined)
      for (const s of strings(e))
        if (!actual.includes(s)) this.fail(`${k}: ${s} not in ${JSON.stringify(actual)}`);
  }
  excludeAll(k, actual) {
    const e = this.take(k);
    if (e !== undefined)
      for (const s of strings(e))
        if (actual.includes(s)) this.fail(`${k}: ${s} in ${JSON.stringify(actual)}`);
  }
  containInAny(k, actual) {
    const e = this.take(k);
    if (e !== undefined)
      for (const s of strings(e))
        if (!actual.some((a) => a.includes(s)))
          this.fail(`${k}: no item contains ${s}; got ${JSON.stringify(actual)}`);
  }
  containInNone(k, actual) {
    const e = this.take(k);
    if (e !== undefined)
      for (const s of strings(e))
        if (actual.some((a) => a.includes(s))) this.fail(`${k}: some item contains ${s}`);
  }
  listExact(k, actual) {
    const e = this.take(k);
    if (e === undefined) return;
    if (e.length !== actual.length)
      return this.fail(`${k}: expected ${e.length} item(s), got ${JSON.stringify(actual)}`);
    e.forEach((x, i) => {
      const why = partialMatch(x, actual[i]);
      if (why) this.fail(`${k}[${i}]: ${why}`);
    });
  }
  listInclude(k, actual) {
    const e = this.take(k);
    if (e !== undefined)
      for (const x of e)
        if (!actual.some((a) => !partialMatch(x, a)))
          this.fail(`${k}: nothing matches ${JSON.stringify(x)}`);
  }
  listExclude(k, actual) {
    const e = this.take(k);
    if (e !== undefined)
      for (const x of e)
        if (actual.some((a) => !partialMatch(x, a)))
          this.fail(`${k}: something matches ${JSON.stringify(x)}`);
  }
}

const kinds = (trace) => [...new Set(trace.map((s) => s.kind))];

function commandChecks(exp, cmd) {
  const reasons = cmd.reasons.map((r) => r.text);
  exp.eq('level', cmd.level);
  exp.ne('level_not', cmd.level);
  exp.includeAll('reasons_include', reasons);
  exp.containInAny('reasons_contain', reasons);
  exp.containInNone('reasons_not_contain', reasons);
  exp.eq('reasons_empty', reasons.length === 0);
}

/** The ops this file knows, mapped to (api, case) → Expect. */
const OPS = {
  'command.analyze'(api, c, input) {
    const exp = new Expect(c.expect);
    commandChecks(exp, api.analyze(input).command);
    return exp;
  },
  'command.analyze_in'(api, c, input) {
    const ctx = c.args?.context;
    const context = ctx && {
      sourceKind: ctx.source,
      platform: ctx.platform,
      app: ctx.app,
      url: ctx.url,
    };
    const cmd = api.analyze(input, { context }).command;
    const exp = new Expect(c.expect);
    commandChecks(exp, cmd);
    exp.eq('risk_score', cmd.risk_score);
    const min = exp.take('risk_score_min');
    if (min !== undefined && cmd.risk_score < min)
      exp.fail(`risk_score ${cmd.risk_score} < ${min}`);
    const max = exp.take('risk_score_max');
    if (max !== undefined && cmd.risk_score > max)
      exp.fail(`risk_score ${cmd.risk_score} > ${max}`);
    exp.eq('trace_kinds', kinds(cmd.trace));
    exp.includeAll('trace_kinds_include', kinds(cmd.trace));
    exp.excludeAll('trace_kinds_exclude', kinds(cmd.trace));
    exp.eq('trace_empty', cmd.trace.length === 0);
    exp.eq('hosts', cmd.hosts);
    exp.includeAll('hosts_include', cmd.hosts);
    return exp;
  },
  'hidden.analyze'(api, c, input) {
    const h = api.analyze(input).hidden;
    const reasons = h.reasons.map((r) => r.text);
    const exp = new Expect(c.expect);
    exp.eq('level', h.level);
    exp.containInAny('reasons_contain', reasons);
    exp.containInNone('reasons_not_contain', reasons);
    exp.eq('reasons_empty', reasons.length === 0);
    return exp;
  },
  'secret.find'(api, c, input) {
    const opts = c.args?.packs ? { settings: { packs: c.args.packs } } : {};
    const found = api
      .analyze(input, opts)
      .secrets.map((s) => ({ ...s, index_utf16: s.span_utf16[0] }));
    const exp = new Expect(c.expect);
    exp.listExact('matches', found);
    exp.listInclude('matches_include', found);
    exp.listExclude('matches_exclude', found);
    exp.eq('count', found.length);
    const ks = found.map((s) => s.kind);
    exp.includeAll('kinds_include', ks);
    exp.excludeAll('kinds_exclude', ks);
    exp.containInNone(
      'masked_not_contain',
      found.map((s) => s.masked),
    );
    return exp;
  },
  'secret.mask_text'(api, c, input) {
    const opts = c.args?.packs ? { settings: { packs: c.args.packs } } : {};
    const exp = new Expect(c.expect);
    exp.eq('output', api.mask(input, api.analyze(input, opts), 'zh-TW'));
    return exp;
  },
};

/** Corpus cases whose op is in OPS. */
export function cases() {
  const dir = join(repoRoot, 'corpus', 'cases');
  const out = [];
  for (const f of readdirSync(dir)
    .filter((f) => f.endsWith('.jsonl'))
    .sort()) {
    for (const line of readFileSync(join(dir, f), 'utf8').split('\n')) {
      if (!line.trim()) continue;
      const c = JSON.parse(line);
      if (c.op in OPS) out.push(c);
    }
  }
  return out;
}

/**
 * Runs one case. Returns `{ status: 'pass' | 'fail' | 'skip', failures }`;
 * `skip` = an expect key this runner does not implement (reported, never silent).
 */
export function runCase(api, c) {
  const input = c.input === undefined ? '' : text(c.input);
  // `Engine::analyze` reads only the first MAX_ANALYZED_CHARS chars (limits.rs);
  // cases beyond it test the detector's own head/tail scan, not the engine.
  if ([...input].length > MAX_ANALYZED_CHARS) {
    return { status: 'skip', failures: ['input longer than MAX_ANALYZED_CHARS'] };
  }
  const exp = OPS[c.op](api, c, input);
  const leftover = Object.keys(exp.rest);
  if (exp.failures.length) return { status: 'fail', failures: exp.failures };
  if (leftover.length)
    return { status: 'skip', failures: [`unhandled expect keys: ${leftover.join(', ')}`] };
  return { status: 'pass', failures: [] };
}
