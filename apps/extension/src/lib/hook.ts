// MAIN-world clipboard hooks (docs/plan/phase-3.md §3.2, docs/spikes/s2-wasm-csp.md).
//
// Runs in the page's own JS world at document_start, before any page script, so it can capture
// the native functions and wrap them:
//
//   Clipboard.prototype.writeText / write     async: wait for the verdict, then write
//   DataTransfer.prototype.setData            sync, only on clipboard events (copy / cut)
//   DataTransferItemList.prototype.add        sync, same
//   Document.prototype.execCommand('copy')    sync: the default action copies the selection
//
// Every write asks `ask()` synchronously (CustomEvent to the isolated world, ~0.02 ms). The hook
// itself never sees settings or reports; it only learns "allow" or "write this notice instead".
//
// Same-origin child frames (about:blank, srcdoc) are hooked as soon as the page reaches their
// window through contentWindow / contentDocument or inserts them, so a fresh iframe can't hand
// out an unwrapped `writeText` (THREAT_MODEL T18). Cross-origin frames get their own content
// scripts (all_frames + match_origin_as_fallback).
import type { Ask, AwaitReply, Reply, Via, WriteRequest } from './protocol';

export interface HookOptions {
  ask: Ask;
  wait: AwaitReply;
}

type AnyFn = (...args: unknown[]) => unknown;

const TEXT_FORMATS = new Set(['text', 'text/plain', 'text/html', 'text/uri-list', 'url']);

/** Windows already hooked, across every realm this hook has touched. */
const hooked = new WeakSet<object>();

/**
 * Installs the hooks into `win` (and, lazily, into its same-origin child frames). Idempotent per
 * window. Never throws: a missing API just isn't wrapped.
 */
export function installHook(win: Window & typeof globalThis, opts: HookOptions): void {
  if (hooked.has(win)) return;
  hooked.add(win);

  const apply = Reflect.apply;
  const getDesc = Object.getOwnPropertyDescriptor;
  const defineProp = Object.defineProperty;
  const W = win as unknown as Record<string, { prototype: Record<string, unknown> } | undefined>;
  const proto = (name: string) => W[name]?.prototype;

  const ask = (req: WriteRequest): Reply => {
    try {
      return opts.ask(req);
    } catch {
      return { v: 'allow' };
    }
  };
  /** Resolves `wait` replies (engine still loading, or the isolated side not paired yet). */
  const settle = async (req: WriteRequest, first: Reply): Promise<Reply> => {
    let reply = first;
    for (let i = 0; i < 3 && reply.v === 'wait'; i++) {
      const next: Reply = await opts.wait(reply.id).catch((): Reply => ({ v: 'allow' }));
      // `wait` again = the channel just paired: ask for real now.
      reply = next.v === 'wait' ? ask(req) : next;
    }
    return reply.v === 'wait' ? { v: 'allow' } : reply;
  };

  /** Replaces `obj[key]` with `make(original)`, keeping the property's attributes. */
  const wrapMethod = (
    obj: Record<string, unknown> | undefined,
    key: string,
    make: (orig: AnyFn) => AnyFn,
  ) => {
    if (!obj) return;
    const desc = getDesc(obj, key);
    const orig = desc?.value;
    if (typeof orig !== 'function') return;
    const wrapped = make(orig as AnyFn);
    try {
      defineProp(wrapped, 'name', { value: key });
      defineProp(wrapped, 'length', { value: (orig as AnyFn).length });
    } catch {
      // Cosmetic only.
    }
    defineProp(obj, key, { ...desc, value: wrapped });
  };

  // --- Natives used later (captured now so the page can't swap them out) ---
  const DocProto = proto('Document');
  const getSelectionNative = DocProto?.getSelection as
    | ((this: Document) => Selection | null)
    | undefined;
  const selToString = proto('Selection')?.toString as ((this: Selection) => string) | undefined;
  const activeGetter = DocProto ? getDesc(DocProto, 'activeElement')?.get : undefined;
  const taValue = getDesc(proto('HTMLTextAreaElement') ?? {}, 'value')?.get;
  const inValue = getDesc(proto('HTMLInputElement') ?? {}, 'value')?.get;
  const taStart = getDesc(proto('HTMLTextAreaElement') ?? {}, 'selectionStart')?.get;
  const taEnd = getDesc(proto('HTMLTextAreaElement') ?? {}, 'selectionEnd')?.get;
  const inStart = getDesc(proto('HTMLInputElement') ?? {}, 'selectionStart')?.get;
  const inEnd = getDesc(proto('HTMLInputElement') ?? {}, 'selectionEnd')?.get;
  const TextAreaCtor = win.HTMLTextAreaElement;
  const InputCtor = win.HTMLInputElement;
  const NativeBlob = win.Blob;
  const NativeClipboardItem = (win as unknown as { ClipboardItem?: typeof ClipboardItem })
    .ClipboardItem;
  const blobText = proto('Blob')?.text as ((this: Blob) => Promise<string>) | undefined;
  const addListener = proto('EventTarget')?.addEventListener as AnyFn | undefined;
  const preventDefault = proto('Event')?.preventDefault as AnyFn | undefined;
  const clipboardDataGetter = getDesc(proto('ClipboardEvent') ?? {}, 'clipboardData')?.get;
  const itemsGetter = getDesc(proto('DataTransfer') ?? {}, 'items')?.get;
  const isTrustedOf = (e: Event): boolean => {
    try {
      return e.isTrusted === true;
    } catch {
      return false;
    }
  };

  /** Text the default `copy` action would put on the clipboard. */
  const selectionText = (): string => {
    try {
      const doc = win.document;
      let active = activeGetter ? (apply(activeGetter, doc, []) as Element | null) : null;
      while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
      if (active instanceof TextAreaCtor && taValue && taStart && taEnd) {
        const v = apply(taValue, active, []) as string;
        return v.slice(apply(taStart, active, []) as number, apply(taEnd, active, []) as number);
      }
      if (active instanceof InputCtor && inValue && inStart && inEnd) {
        const start = apply(inStart, active, []) as number | null;
        const end = apply(inEnd, active, []) as number | null;
        if (start !== null && end !== null) {
          return (apply(inValue, active, []) as string).slice(start, end);
        }
      }
      const sel = getSelectionNative ? apply(getSelectionNative, doc, []) : null;
      return sel && selToString ? (apply(selToString, sel, []) as string) : '';
    } catch {
      return '';
    }
  };

  // --- Which DataTransfer objects belong to real clipboard events ---
  const clipboardData = new WeakSet<object>();
  const clipboardItems = new WeakSet<object>();
  let execDepth = 0;
  const nativeSetData = proto('DataTransfer')?.setData as AnyFn | undefined;

  const onClipboardEvent = (event: Event) => {
    if (!isTrustedOf(event)) return;
    const dt = clipboardDataGetter
      ? (apply(clipboardDataGetter, event, []) as DataTransfer | null)
      : null;
    if (!dt) return;
    clipboardData.add(dt);
    try {
      if (itemsGetter) clipboardItems.add(apply(itemsGetter, dt, []) as object);
    } catch {
      // No items list: setData is still covered.
    }
    // execCommand('copy'/'cut') from page script: without a handler, the browser copies the
    // selection (the classic hidden-textarea ClickFix). Check it here, before any page handler.
    if (execDepth > 0 && nativeSetData && preventDefault) {
      const text = selectionText();
      if (!text) return;
      const reply = ask({ via: 'execCommand', text });
      if (reply.v === 'block') {
        apply(nativeSetData, dt, ['text/plain', reply.notice]);
        apply(preventDefault, event, []);
      }
    }
  };
  if (addListener) {
    apply(addListener, win, ['copy', onClipboardEvent, true]);
    apply(addListener, win, ['cut', onClipboardEvent, true]);
  }

  const checkFormat = (via: Via, format: unknown, data: unknown): string | null => {
    const f = String(format).toLowerCase();
    if (!TEXT_FORMATS.has(f)) return null;
    const reply = ask({ via, text: String(data), html: f === 'text/html' });
    return reply.v === 'block' ? reply.notice : null;
  };

  // --- DataTransfer.setData / DataTransferItemList.add (copy & cut events) ---
  wrapMethod(
    proto('DataTransfer'),
    'setData',
    (orig) =>
      function setData(this: DataTransfer, ...args: unknown[]) {
        if (clipboardData.has(this) && args.length >= 2) {
          const notice = checkFormat('setData', args[0], args[1]);
          if (notice !== null) return apply(orig, this, [args[0], notice]);
        }
        return apply(orig, this, args);
      },
  );
  wrapMethod(
    proto('DataTransferItemList'),
    'add',
    (orig) =>
      function add(this: DataTransferItemList, ...args: unknown[]) {
        if (clipboardItems.has(this) && typeof args[0] === 'string' && args.length >= 2) {
          const notice = checkFormat('itemsAdd', args[1], args[0]);
          if (notice !== null) return apply(orig, this, [notice, args[1]]);
        }
        return apply(orig, this, args);
      },
  );

  // --- execCommand('copy' | 'cut') ---
  wrapMethod(
    DocProto,
    'execCommand',
    (orig) =>
      function execCommand(this: Document, ...args: unknown[]) {
        const c = String(args[0]).toLowerCase();
        if (c !== 'copy' && c !== 'cut') return apply(orig, this, args);
        execDepth++;
        try {
          return apply(orig, this, args);
        } finally {
          execDepth--;
        }
      },
  );

  // --- Async Clipboard API ---
  const ClipboardProto = proto('Clipboard');
  wrapMethod(
    ClipboardProto,
    'writeText',
    (orig) =>
      function writeText(this: Clipboard, ...args: unknown[]) {
        if (args.length === 0) return apply(orig, this, []);
        let text: string;
        try {
          text = String(args[0]);
        } catch (err) {
          return Promise.reject(err);
        }
        const req: WriteRequest = { via: 'writeText', text };
        const reply = ask(req);
        // Verdict known now: write in the same task, keeping the user activation intact.
        if (reply.v === 'allow') return apply(orig, this, [text]);
        if (reply.v === 'block') return apply(orig, this, [reply.notice]);
        return settle(req, reply).then((r) =>
          apply(orig, this, [r.v === 'block' ? r.notice : text]),
        );
      },
  );

  wrapMethod(
    ClipboardProto,
    'write',
    (orig) =>
      function write(this: Clipboard, ...args: unknown[]) {
        const items = args[0];
        if (!NativeClipboardItem || !NativeBlob || !blobText) return apply(orig, this, args);
        let list: ClipboardItem[];
        try {
          list = Array.from(items as Iterable<ClipboardItem>);
        } catch {
          return apply(orig, this, args);
        }
        const check = async (): Promise<string | null> => {
          for (const item of list) {
            let types: readonly string[] = [];
            try {
              types = item.types;
            } catch {
              continue;
            }
            for (const type of types) {
              const f = type.toLowerCase();
              if (f !== 'text/plain' && f !== 'text/html') continue;
              const blob = await item.getType(type);
              const text = (await apply(blobText, blob, [])) as string;
              const req: WriteRequest = { via: 'write', text, html: f === 'text/html' };
              const reply = await settle(req, ask(req));
              if (reply.v === 'block') return reply.notice;
            }
          }
          return null;
        };
        return check().then(
          (notice) =>
            notice === null
              ? apply(orig, this, args)
              : apply(orig, this, [
                  [
                    new NativeClipboardItem({
                      'text/plain': new NativeBlob([notice], { type: 'text/plain' }),
                    }),
                  ],
                ]),
          // Unreadable item: let the native call produce the same error.
          () => apply(orig, this, args),
        );
      },
  );

  // --- Same-origin child frames (T18) ---
  const hookChild = (child: unknown) => {
    try {
      const w = child as (Window & typeof globalThis) | null;
      // Cross-origin: touching `Clipboard` throws; those frames have their own content scripts.
      if (w && typeof w.Clipboard === 'function' && !hooked.has(w)) installHook(w, opts);
    } catch {
      // Cross-origin or detached.
    }
  };
  const hookFramesIn = (node: unknown) => {
    try {
      const n = node as Element & { contentWindow?: unknown };
      if (n && (n.localName === 'iframe' || n.localName === 'frame') && 'contentWindow' in n) {
        hookChild(contentWindowNative ? apply(contentWindowNative, n, []) : null);
      }
      const all = (n as Element)?.querySelectorAll?.('iframe,frame');
      if (all)
        for (const f of Array.from(all))
          hookChild(contentWindowNative ? apply(contentWindowNative, f, []) : null);
    } catch {
      // Ignore.
    }
  };

  let contentWindowNative: AnyFn | undefined;
  for (const name of ['HTMLIFrameElement', 'HTMLFrameElement']) {
    const p = proto(name);
    if (!p) continue;
    const cw = getDesc(p, 'contentWindow');
    const cd = getDesc(p, 'contentDocument');
    if (cw?.get) {
      const getter = cw.get as AnyFn;
      if (name === 'HTMLIFrameElement') contentWindowNative = getter;
      defineProp(p, 'contentWindow', {
        ...cw,
        get: function contentWindow(this: Element) {
          const w = apply(getter, this, []);
          hookChild(w);
          return w;
        },
      });
    }
    if (cd?.get) {
      const getter = cd.get as AnyFn;
      const winOf = cw?.get as AnyFn | undefined;
      defineProp(p, 'contentDocument', {
        ...cd,
        get: function contentDocument(this: Element) {
          if (winOf) hookChild(apply(winOf, this, []));
          return apply(getter, this, []);
        },
      });
    }
  }

  // Inserting an iframe creates its window synchronously: hook it before the caller can use it.
  const NodeProto = proto('Node');
  const ElementProto = proto('Element');
  for (const key of ['appendChild', 'insertBefore', 'replaceChild']) {
    wrapMethod(
      NodeProto,
      key,
      (orig) =>
        function insert(this: Node, ...args: unknown[]) {
          const result = apply(orig, this, args);
          hookFramesIn(args[0]);
          return result;
        },
    );
  }
  for (const key of ['append', 'prepend', 'after', 'before', 'replaceWith']) {
    wrapMethod(
      ElementProto,
      key,
      (orig) =>
        function insert(this: Element, ...args: unknown[]) {
          const result = apply(orig, this, args);
          for (const a of args) hookFramesIn(a);
          return result;
        },
    );
  }
}
