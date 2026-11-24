// MAIN ↔ isolated channel and the writeText hook, in one happy-dom window (both "worlds" share it
// here; in the browser they are separate JS worlds over the same DOM).
import { Window as HappyWindow } from 'happy-dom';
import { describe, expect, it, vi } from 'vitest';
import { connectContent, connectMain } from '../src/lib/channel';
import { installHook } from '../src/lib/hook';
import { HELLO_EVENT, type Reply, type WriteRequest } from '../src/lib/protocol';

type Win = Window & typeof globalThis;

/** A separate window per test, so listeners from earlier tests can't answer. */
function freshWin(): Win {
  return new HappyWindow({ url: 'https://example.invalid/' }) as unknown as Win;
}

describe('channel', () => {
  it('pairs in either order and answers synchronously', () => {
    const win = freshWin();
    const seen: WriteRequest[] = [];
    // isolated side first, MAIN second
    connectContent(
      win,
      (req) => {
        seen.push(req);
        return req.text === 'bad' ? { v: 'block', notice: 'N' } : { v: 'allow' };
      },
      () => 'fallback',
    );
    const main = connectMain(win);
    expect(main.ask({ via: 'writeText', text: 'bad' })).toEqual({ v: 'block', notice: 'N' });
    expect(main.ask({ via: 'setData', text: 'ok', html: true })).toEqual({ v: 'allow' });
    expect(seen).toEqual([
      { via: 'writeText', text: 'bad', html: false },
      { via: 'setData', text: 'ok', html: true },
    ]);
  });

  it('uses a fresh random event name for every page', () => {
    const names = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const w = freshWin();
      w.addEventListener(HELLO_EVENT, (e) => names.add((e as CustomEvent).detail as string));
      connectMain(w);
    }
    expect(names.size).toBe(5);
    for (const n of names) expect(n).toMatch(/^pw[0-9a-f]{32}$/);
  });

  it('fails closed when paired but nothing answers', () => {
    const w = freshWin();
    let name = '';
    w.addEventListener(HELLO_EVENT, (e) => {
      name = (e as CustomEvent).detail as string;
    });
    const main = connectMain(w);
    expect(name).toMatch(/^pw[0-9a-f]{32}$/);
    // Not paired yet: sync writes go through, async ones wait.
    expect(main.ask({ via: 'setData', text: 'x' }).v).toBe('wait');
    // Something acks the pairing but never answers requests (a broken or hijacked channel).
    w.dispatchEvent(
      new w.CustomEvent(`${name}:ack`, { detail: JSON.stringify({ notice: 'FALLBACK' }) }),
    );
    expect(main.ask({ via: 'writeText', text: 'x' })).toEqual({ v: 'block', notice: 'FALLBACK' });
  });

  it('a page cannot pair with an unknown name format', () => {
    const win = freshWin();
    const handler = vi.fn((): Reply => ({ v: 'allow' }));
    connectContent(win, handler, () => 'n');
    win.dispatchEvent(new win.CustomEvent(HELLO_EVENT, { detail: 'not-a-name' }));
    win.dispatchEvent(
      new win.CustomEvent('not-a-name:q', {
        detail: JSON.stringify({ s: 1, via: 'writeText', text: 'x' }),
      }),
    );
    expect(handler).not.toHaveBeenCalled();
  });
});

describe('hook', () => {
  it('replaces a blocked writeText and keeps allowed ones', async () => {
    const win = freshWin();
    const clip = win.navigator.clipboard;
    expect(typeof win.Clipboard).toBe('function');
    const replies: Record<string, Reply> = { bad: { v: 'block', notice: 'NOTICE' } };
    installHook(win, {
      ask: (req) => replies[req.text] ?? { v: 'allow' },
      wait: async () => ({ v: 'allow' }),
    });
    await clip.writeText('bad');
    expect(await clip.readText()).toBe('NOTICE');
    await clip.writeText('fine');
    expect(await clip.readText()).toBe('fine');
    expect(win.Clipboard.prototype.writeText.name).toBe('writeText');
  });

  it('waits for a late verdict on async writes', async () => {
    const child = freshWin();
    expect(typeof child.Clipboard).toBe('function');
    installHook(child, {
      ask: () => ({ v: 'wait', id: 7 }),
      wait: async (id) => (id === 7 ? { v: 'block', notice: 'LATE' } : { v: 'allow' }),
    });
    await child.navigator.clipboard.writeText('x');
    expect(await child.navigator.clipboard.readText()).toBe('LATE');
  });
});
