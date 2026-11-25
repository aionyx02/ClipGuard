import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { frameAt, nextScenario, SCENARIOS, scenario, stillTime } from '../src/lib/demo';

const ftl = (lang: string) =>
  // Vitest runs from apps/web.
  readFileSync(resolve(process.cwd(), `../../locales/${lang}/ui-web.ftl`), 'utf8');

describe('demo timelines', () => {
  it('every scenario starts at a chapter and caption, in order, inside its length', () => {
    for (const s of SCENARIOS) {
      for (const marks of [s.chapters, s.captions]) {
        expect(marks[0]?.start).toBe(0);
        for (let i = 1; i < marks.length; i++) {
          expect(marks[i]?.start).toBeGreaterThan(marks[i - 1]?.start ?? 0);
        }
        expect(marks.at(-1)?.start).toBeLessThan(s.length);
      }
      for (const [start, end = s.length] of Object.values(s.spans)) {
        expect(start).toBeGreaterThanOrEqual(0);
        expect(end).toBeGreaterThan(start);
        expect(end).toBeLessThanOrEqual(s.length);
      }
    }
  });

  it('clickfix: blocked at write time, then the paste carries only the notice', () => {
    const s = scenario('clickfix');
    const before = frameAt(s, 1_600);
    expect(before.on('xray')).toBe(true);
    expect(before.on('warning')).toBe(false);
    const caught = frameAt(s, 3_100);
    expect(caught).toMatchObject({ chapter: 'catch', caption: 'catch' });
    expect(caught.on('xray')).toBe(false);
    expect(caught.on('warning')).toBe(true);
    expect(frameAt(s, stillTime(s)).on('pasted')).toBe(true);
  });

  it('secrets: the dialog comes before the masked paste, never together', () => {
    const s = scenario('secrets');
    for (let t = 0; t < s.length; t += 100) {
      const f = frameAt(s, t);
      expect(f.on('dialog') && f.on('masked')).toBe(false);
    }
    expect(frameAt(s, 3_000).on('dialog')).toBe(true);
    expect(frameAt(s, stillTime(s)).on('sent')).toBe(true);
  });

  it('loops, cycles through scenarios, and never throws on odd input', () => {
    const s = scenario('pastejack');
    expect(frameAt(s, s.length + 10).t).toBe(10);
    expect(frameAt(s, -10).t).toBe(s.length - 10);
    for (const t of [Number.NaN, Number.POSITIVE_INFINITY]) expect(frameAt(s, t).t).toBe(0);
    expect(frameAt(s, 0).on('no-such-span')).toBe(false);
    const order = SCENARIOS.map((x) => x.id);
    expect(order.map(nextScenario)).toEqual([...order.slice(1), order[0]]);
  });

  it('every tab, chapter and caption has text in both languages', () => {
    for (const lang of ['en', 'zh-TW']) {
      const text = ftl(lang);
      const has = (id: string) =>
        expect(text, `${lang}: ${id}`).toMatch(new RegExp(`^${id} =`, 'm'));
      for (const s of SCENARIOS) {
        has(`ui-web-demo-tab-${s.id}`);
        for (const c of s.chapters) has(`ui-web-demo-${s.id}-ch-${c.id}`);
        for (const c of s.captions) has(`ui-web-demo-${s.id}-cap-${c.id}`);
      }
    }
  });
});
