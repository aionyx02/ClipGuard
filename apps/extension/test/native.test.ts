import { describe, expect, it } from 'vitest';
import {
  classifyHello,
  EXT_PROBE_RETRY_MAX_MS,
  EXT_PROBE_RETRY_MS,
  INITIAL_RECORD,
  type NativeDeps,
  NativeLink,
  type NativeRecord,
  nextRecord,
  normalizeRecord,
  retryDelay,
  ruleIdOr,
  verdictMessage,
} from '../src/lib/native';

const MIN = 60_000;

describe('retryDelay', () => {
  it('starts at 10 minutes and doubles up to 60', () => {
    expect(EXT_PROBE_RETRY_MS).toBe(10 * MIN);
    expect(EXT_PROBE_RETRY_MAX_MS).toBe(60 * MIN);
    expect([1, 2, 3, 4, 5, 50, 1e9].map(retryDelay)).toEqual([
      10 * MIN,
      20 * MIN,
      40 * MIN,
      60 * MIN,
      60 * MIN,
      60 * MIN,
      60 * MIN,
    ]);
    expect(retryDelay(0)).toBe(10 * MIN);
    expect(retryDelay(Number.NaN)).toBe(10 * MIN);
  });
});

describe('classifyHello', () => {
  it('reads the desktop state', () => {
    expect(classifyHello({ v: 1, ok: true, desktop: 'running' })).toBe('running');
    expect(classifyHello({ v: 1, ok: true, desktop: 'not_running' })).toBe('not_running');
    expect(classifyHello({ v: 1, ok: false, err: 'version' })).toBe('incompatible');
    expect(classifyHello({ v: 2, ok: true, desktop: 'running' })).toBe('absent');
    for (const junk of [null, undefined, 'x', 1, {}, { ok: true }]) {
      expect(classifyHello(junk)).toBe('absent');
    }
  });
});

describe('nextRecord / normalizeRecord', () => {
  it('backs off on failure and resets on success', () => {
    let r: NativeRecord = INITIAL_RECORD;
    r = nextRecord(r, 'absent', 0);
    expect(r).toEqual({ state: 'absent', failures: 1, nextProbeAt: 10 * MIN });
    r = nextRecord(r, 'not_running', 1000);
    expect(r).toEqual({ state: 'not_running', failures: 2, nextProbeAt: 1000 + 20 * MIN });
    r = nextRecord(r, 'running', 5);
    expect(r).toEqual({ state: 'running', failures: 0, nextProbeAt: 5 + 60 * MIN });
    expect(nextRecord(r, 'off', 9)).toEqual(INITIAL_RECORD);
  });

  it('never trusts stored data', () => {
    expect(normalizeRecord(undefined)).toEqual(INITIAL_RECORD);
    expect(normalizeRecord({ state: 'hacked', failures: -3, nextProbeAt: 'x' })).toEqual(
      INITIAL_RECORD,
    );
    expect(normalizeRecord({ state: 'running', failures: 2.7, nextProbeAt: 5 })).toEqual({
      state: 'running',
      failures: 2,
      nextProbeAt: 5,
    });
  });
});

describe('verdictMessage', () => {
  const v = { kind: 'gitleaks.aws-access-token', severity: 'high', action: 'confirm' } as const;
  it('sends only rule, severity, host and action', () => {
    expect(verdictMessage(v, 'Example.invalid.', 3)).toEqual({
      v: 1,
      id: 3,
      op: 'verdict',
      kind: 'gitleaks.aws-access-token',
      severity: 'high',
      origin_host: 'example.invalid',
      action: 'confirm',
    });
    expect(verdictMessage(v, '', 1)?.origin_host).toBe('');
  });
  it('drops anything that is not a hostname or a rule id', () => {
    expect(verdictMessage(v, 'https://example.invalid/a?b', 1)).toBeNull();
    expect(verdictMessage(v, 'user@example.invalid', 1)).toBeNull();
    expect(verdictMessage({ ...v, kind: 'rm -rf ~' }, 'example.invalid', 1)).toBeNull();
    expect(ruleIdOr('rm -rf ~', 'command')).toBe('command');
    expect(ruleIdOr(undefined, 'secret')).toBe('secret');
    expect(ruleIdOr('tw-national-id', 'secret')).toBe('tw-national-id');
  });
});

interface Harness {
  link: NativeLink;
  sent: Record<string, unknown>[];
  stored: { value: unknown };
  clock: { now: number };
  perm: { granted: boolean };
  host: { reply: (msg: Record<string, unknown>) => Promise<unknown> };
}

function harness(): Harness {
  const h = {
    sent: [] as Record<string, unknown>[],
    stored: { value: undefined as unknown },
    clock: { now: 1_000_000 },
    perm: { granted: true },
    host: {
      reply: (_msg: Record<string, unknown>): Promise<unknown> =>
        Promise.reject(new Error('Specified native messaging host not found.')),
    },
  };
  const deps: NativeDeps = {
    hasPermission: async () => h.perm.granted,
    send: (msg) => {
      h.sent.push(msg);
      return h.host.reply(msg);
    },
    load: async () => h.stored.value,
    save: async (r) => {
      h.stored.value = r;
    },
    now: () => h.clock.now,
    version: '0.1.0',
  };
  return { ...h, link: new NativeLink(deps) };
}

describe('NativeLink', () => {
  it('does nothing without the permission', async () => {
    const h = harness();
    h.perm.granted = false;
    expect((await h.link.probe()).state).toBe('off');
    expect(await h.link.sendVerdict({ kind: 'x', severity: 'high', action: 'blocked' }, 'a')).toBe(
      false,
    );
    expect(h.sent).toHaveLength(0);
  });

  it('downgrades quietly when the host is absent and retries with backoff', async () => {
    const h = harness();
    const r1 = await h.link.probe();
    expect(r1).toEqual({ state: 'absent', failures: 1, nextProbeAt: 1_000_000 + 10 * MIN });
    expect(h.sent).toEqual([
      { v: 1, id: 1, op: 'hello', ext: { ver: '0.1.0', caps: ['verdict'] } },
    ]);

    // Not due yet: no new probe.
    h.clock.now += 9 * MIN;
    expect(await h.link.probe()).toEqual(r1);
    expect(h.sent).toHaveLength(1);

    // Due: probe again, interval doubles.
    h.clock.now += MIN;
    const r2 = await h.link.probe();
    expect(r2.failures).toBe(2);
    expect(r2.nextProbeAt - h.clock.now).toBe(20 * MIN);
    h.clock.now = r2.nextProbeAt;
    const r3 = await h.link.probe();
    h.clock.now = r3.nextProbeAt;
    const r4 = await h.link.probe();
    expect(r4.nextProbeAt - h.clock.now).toBe(60 * MIN);
    expect(h.sent).toHaveLength(4);

    // Verdicts are not sent while absent.
    expect(await h.link.sendVerdict({ kind: 'x', severity: 'high', action: 'blocked' }, 'a')).toBe(
      false,
    );
    expect(h.sent).toHaveLength(4);
  });

  it('a forced probe ignores the schedule and restarts the backoff', async () => {
    const h = harness();
    await h.link.probe();
    await h.link.probe(true);
    expect(h.sent).toHaveLength(2);
    expect(((await h.link.status()) as NativeRecord).failures).toBe(1);
  });

  it('connects, sends verdicts, and notices the desktop going away', async () => {
    const h = harness();
    h.host.reply = async (msg) =>
      msg.op === 'hello'
        ? { v: 1, id: msg.id, ok: true, desktop: 'running', host: { ver: '0.1.0' } }
        : { v: 1, id: msg.id, ok: true, desktop: 'running' };
    expect((await h.link.probe()).state).toBe('running');
    const verdict = { kind: 'command', severity: 'high', action: 'blocked' } as const;
    expect(await h.link.sendVerdict(verdict, 'example.invalid')).toBe(true);
    expect(h.sent[1]).toMatchObject({ op: 'verdict', origin_host: 'example.invalid' });

    // Desktop quit: the host answers not_running.
    h.host.reply = async (msg) => ({
      v: 1,
      id: msg.id,
      ok: false,
      err: 'not_running',
      desktop: 'not_running',
    });
    expect(await h.link.sendVerdict(verdict, 'example.invalid')).toBe(false);
    expect(((await h.link.status()) as NativeRecord).state).toBe('not_running');

    // Host uninstalled: rejects.
    h.host.reply = () => Promise.reject(new Error('gone'));
    expect((await h.link.probe(true)).state).toBe('absent');
  });

  it('one probe at a time', async () => {
    const h = harness();
    const [a, b] = await Promise.all([h.link.probe(), h.link.probe()]);
    expect(a).toEqual(b);
    expect(h.sent).toHaveLength(1);
  });

  it('survives a broken storage', async () => {
    const h = harness();
    const link = new NativeLink({
      hasPermission: () => Promise.reject(new Error('x')),
      send: () => Promise.reject(new Error('x')),
      load: () => Promise.reject(new Error('x')),
      save: () => Promise.reject(new Error('x')),
      now: () => 0,
      version: '0',
    });
    expect((await link.probe()).state).toBe('off');
    expect(h.sent).toHaveLength(0);
  });
});
