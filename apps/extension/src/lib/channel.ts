// MAIN world ↔ isolated world channel (S2: synchronous CustomEvent; THREAT_MODEL T17).
//
// Handshake, once per frame, at document_start (before any page script can listen):
//   MAIN generates a random name N, listens for READY and dispatches HELLO(N).
//   isolated listens for HELLO and dispatches READY.
// Whichever side loads second completes it. The isolated side then answers on `N:ack` with the
// rendered fallback notice, and from then on:
//   MAIN → `N:q` detail = JSON {s, via, text, html}   (dispatched synchronously)
//   isolated → `N:r` detail = JSON {s, v, notice?, id?} (dispatched inside the q handler)
//   isolated → `N:r` detail = JSON {id, v, notice?}     (later, for `wait` replies)
// The page never learns N (the handshake happens before page scripts run), and even if it did,
// it could only ask for verdicts about its own text. MAIN keeps its own copies of the natives.
import {
  type Ask,
  type AwaitReply,
  HELLO_EVENT,
  MAX_REQUEST_CHARS,
  READY_EVENT,
  type Reply,
  type WriteRequest,
} from './protocol';

type AnyFn = (...args: unknown[]) => unknown;

function randomName(win: Window & typeof globalThis): string {
  const bytes = new Uint8Array(16);
  win.crypto.getRandomValues(bytes);
  let s = 'pw';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** How long async writes wait for a late isolated side / engine before giving up (allow). */
const WAIT_TIMEOUT_MS = 4000;

/** MAIN world side. Returns the `ask` / `wait` pair for `installHook`. */
export function connectMain(win: Window & typeof globalThis): { ask: Ask; wait: AwaitReply } {
  const apply = Reflect.apply;
  const ET = win.EventTarget.prototype;
  const add = ET.addEventListener as AnyFn;
  const remove = ET.removeEventListener as AnyFn;
  const dispatch = ET.dispatchEvent as AnyFn;
  const NativeCustomEvent = win.CustomEvent;
  const detailGetter = Object.getOwnPropertyDescriptor(win.CustomEvent.prototype, 'detail')
    ?.get as AnyFn;
  const parse = JSON.parse;
  const stringify = JSON.stringify;
  const setTimer = win.setTimeout.bind(win);

  const name = randomName(win);
  let paired = false;
  let fallbackNotice = '';
  let seq = 0;
  let current: { s: number; reply: Reply | null } | null = null;
  const waiting = new Map<number, (r: Reply) => void>();
  const pairWaiters: Array<() => void> = [];

  const detailOf = (e: Event): unknown => {
    try {
      const d = apply(detailGetter, e, []);
      return typeof d === 'string' ? parse(d) : null;
    } catch {
      return null;
    }
  };

  apply(add, win, [
    `${name}:ack`,
    (e: Event) => {
      const d = detailOf(e) as { notice?: unknown } | null;
      if (paired || !d || typeof d.notice !== 'string') return;
      paired = true;
      fallbackNotice = d.notice;
      apply(remove, win, [READY_EVENT, onReady, true]);
      for (const w of pairWaiters.splice(0)) w();
    },
    true,
  ]);
  apply(add, win, [
    `${name}:r`,
    (e: Event) => {
      const d = detailOf(e) as { s?: unknown; id?: unknown; v?: unknown; notice?: unknown } | null;
      if (!d) return;
      const reply = toReply(d);
      if (!reply) return;
      if (typeof d.s === 'number' && current && current.s === d.s) current.reply = reply;
      else if (typeof d.id === 'number') {
        const done = waiting.get(d.id);
        waiting.delete(d.id);
        done?.(reply);
      }
    },
    true,
  ]);

  const hello = () => apply(dispatch, win, [new NativeCustomEvent(HELLO_EVENT, { detail: name })]);
  const onReady = () => {
    if (!paired) hello();
  };
  apply(add, win, [READY_EVENT, onReady, true]);
  hello();

  const block = (): Reply => ({ v: 'block', notice: fallbackNotice });

  const ask: Ask = (req: WriteRequest) => {
    if (!paired) {
      // Isolated side not here (yet): async callers wait for it, sync callers go through.
      return { v: 'wait', id: -1 };
    }
    const text =
      req.text.length > MAX_REQUEST_CHARS ? req.text.slice(0, MAX_REQUEST_CHARS) : req.text;
    const s = ++seq;
    const frame = { s, reply: null as Reply | null };
    const outer = current;
    current = frame;
    try {
      apply(dispatch, win, [
        new NativeCustomEvent(`${name}:q`, {
          detail: stringify({ s, via: req.via, text, html: req.html === true }),
        }),
      ]);
    } catch {
      // Fall through to the missing-reply case.
    } finally {
      current = outer;
    }
    // Paired but no answer: something on the page interfered with the channel. Fail closed.
    return frame.reply ?? block();
  };

  const wait: AwaitReply = (id: number) =>
    new Promise<Reply>((resolve) => {
      const timer = setTimer(() => {
        waiting.delete(id);
        resolve({ v: 'allow' });
      }, WAIT_TIMEOUT_MS);
      const done = (r: Reply) => {
        win.clearTimeout(timer);
        resolve(r);
      };
      if (id === -1) {
        // Not paired yet: wait for the pairing, then ask again.
        pairWaiters.push(() => {
          win.clearTimeout(timer);
          resolve({ v: 'wait', id: -2 });
        });
        return;
      }
      waiting.set(id, done);
    });

  return { ask, wait };
}

function toReply(d: { v?: unknown; notice?: unknown; id?: unknown }): Reply | null {
  if (d.v === 'allow') return { v: 'allow' };
  if (d.v === 'block' && typeof d.notice === 'string') return { v: 'block', notice: d.notice };
  if (d.v === 'wait' && typeof d.id === 'number') return { v: 'wait', id: d.id };
  return null;
}

export interface ContentChannel {
  /** Answers a `wait` reply later. */
  resolve(id: number, reply: Reply): void;
  /** A MAIN-world hook has paired with this side. */
  paired(): boolean;
}

/**
 * Isolated-world side. `handle` runs synchronously inside the page's write call and must not
 * throw (errors become `allow`, logged without the text).
 */
export function connectContent(
  win: Window,
  handle: (req: WriteRequest) => Reply,
  fallbackNotice: () => string,
): ContentChannel {
  const names = new Set<string>();

  const send = (name: string, detail: object) => {
    win.dispatchEvent(new CustomEvent(`${name}:r`, { detail: JSON.stringify(detail) }));
  };

  const listen = (name: string) => {
    if (names.has(name)) return;
    names.add(name);
    win.addEventListener(
      `${name}:q`,
      (e: Event) => {
        let s: unknown;
        let reply: Reply = { v: 'allow' };
        try {
          const raw = (e as CustomEvent).detail;
          if (typeof raw !== 'string' || raw.length > MAX_REQUEST_CHARS * 6 + 256) return;
          const d = JSON.parse(raw) as {
            s?: unknown;
            via?: unknown;
            text?: unknown;
            html?: unknown;
          };
          s = d.s;
          if (typeof d.text !== 'string' || typeof d.via !== 'string') return;
          reply = handle({
            via: d.via as WriteRequest['via'],
            text: d.text,
            html: d.html === true,
          });
        } catch (err) {
          console.warn('[PasteWarden] write check failed:', (err as Error)?.name ?? 'Error');
        }
        if (typeof s === 'number') send(name, { s, ...reply });
      },
      true,
    );
    win.dispatchEvent(
      new CustomEvent(`${name}:ack`, { detail: JSON.stringify({ notice: fallbackNotice() }) }),
    );
  };

  // Several names are accepted on purpose: a page that somehow sent HELLO first must not be
  // able to stop the real MAIN-world hook from pairing (that would turn the hook off).
  win.addEventListener(
    HELLO_EVENT,
    (e: Event) => {
      const name = (e as CustomEvent).detail;
      if (typeof name === 'string' && /^pw[0-9a-f]{32}$/.test(name) && names.size < 8) listen(name);
    },
    true,
  );
  win.dispatchEvent(new CustomEvent(READY_EVENT));

  return {
    resolve(id, reply) {
      for (const name of names) send(name, { id, ...reply });
    },
    paired: () => names.size > 0,
  };
}
