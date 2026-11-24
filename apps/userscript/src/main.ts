// PasteWarden userscript (docs/plan/phase-3.md §3.4): the extension's content-side features
// without the extension.
//
// Runs with `@inject-into content` (Violentmonkey's isolated world, S2), so the WASM engine is
// not bound by the page CSP. The clipboard hooks must live in the page's world: they are injected
// as an inline <script> that pairs with this side over the same random CustomEvent channel as the
// extension. When the page CSP blocks that script:
//   - if this script itself runs in the page world (`@inject-into page`, or a manager without an
//     isolated world), the hooks are installed directly and the engine falls back to wasm2js;
//   - otherwise the injection is retried with the nonce of the page's first nonce'd script, and
//     until then copy events are still checked from here (the async Clipboard API is not).

import pageHookSource from 'virtual:pw-page-hook';
import wasmGzipBase64 from 'virtual:pw-wasm';
import { analyze, backend, init, mask } from '@paste-warden/core';
import type { Report } from '@paste-warden/core/types';
import { showClipboardBlocked, showPasteConfirm } from '@paste-warden/overlay';
import { GM_getValue, GM_registerMenuCommand, GM_setClipboard, GM_setValue } from '$';
import { connectContent } from '../../extension/src/lib/channel';
import { type EngineApi, Guard } from '../../extension/src/lib/guard';
import { installHook } from '../../extension/src/lib/hook';
import {
  type BlockRecord,
  type ExtSettings,
  isAllowlisted,
  isBlockRecord,
  normalizeSettings,
  RECENT_KEY,
  RECENT_MAX,
  SETTINGS_KEY,
} from '../../extension/src/lib/settings';
import { translator } from '../../extension/src/lib/strings';
import { showNotice } from '../../extension/src/lib/toast';

type Win = Window & typeof globalThis;
const win = window as Win;
const doc = win.document;

// Natives for our own writes, captured before any hook exists in this world.
const nativeWriteText = win.navigator.clipboard?.writeText?.bind(win.navigator.clipboard);

// GM_* may be missing (managers without the legacy API): never let that stop the guard.
function gmGet<T>(key: string, fallback: T): T {
  try {
    return typeof GM_getValue === 'function' ? (GM_getValue(key, fallback) as T) : fallback;
  } catch {
    return fallback;
  }
}
function gmSet(key: string, value: unknown): void {
  try {
    if (typeof GM_setValue === 'function') GM_setValue(key, value);
  } catch {
    // Not persisted; the change still applies to this page.
  }
}
function gmClipboard(text: string): boolean {
  try {
    if (typeof GM_setClipboard !== 'function') return false;
    GM_setClipboard(text, 'text');
    return true;
  } catch {
    return false;
  }
}

let settings: ExtSettings = normalizeSettings(gmGet<unknown>(SETTINGS_KEY, null));
let engine: EngineApi | null = null;

const saveSettings = (patch: Partial<ExtSettings>) => {
  settings = normalizeSettings({ ...settings, ...patch });
  gmSet(SETTINGS_KEY, settings);
};

/** The top frame's document when it is reachable (same origin), else this frame's. */
function dialogDocument(): Document {
  try {
    if (win.top && win.top !== win && win.top.document) return win.top.document;
  } catch {
    // Cross-origin top: show it here.
  }
  return doc;
}

async function writeClipboard(text: string): Promise<boolean> {
  try {
    if (nativeWriteText) {
      await nativeWriteText(text);
      return true;
    }
  } catch {
    // Fall through to the manager.
  }
  return gmClipboard(text);
}

function record(r: BlockRecord) {
  try {
    const list = gmGet<unknown[]>(RECENT_KEY, []).filter(isBlockRecord);
    gmSet(RECENT_KEY, [r, ...list].slice(0, RECENT_MAX));
  } catch {
    // Not essential.
  }
}

const guard = new Guard({
  win,
  settings: () => settings,
  engine: () => engine,
  presentBlocked: (e) => {
    void showClipboardBlocked(e.report, {
      url: e.url,
      locale: e.locale,
      document: dialogDocument(),
    }).then((choice) => {
      if (choice === 'allow-once') void writeClipboard(e.original);
    });
  },
  presentWarning: (e) => {
    const t = translator(e.locale);
    const pj = e.kind === 'pastejack';
    showNotice(dialogDocument(), {
      brand: t('ui-ext-toast-brand'),
      title: t(pj ? 'ui-ext-toast-pastejack-title' : 'ui-ext-toast-warn-title'),
      body: t(pj ? 'ui-ext-toast-pastejack-body' : 'ui-ext-toast-warn-body'),
      reasons: e.reasons,
      dismiss: t('ui-ext-toast-dismiss'),
    });
  },
  confirmPaste: (report: Report, locale) => showPasteConfirm(report, { locale }),
  overwriteClipboard: async (text) => gmClipboard(text),
  record,
  resolveWait: (id, reply) => channel.resolve(id, reply),
});

const channel = connectContent(
  win,
  (req) => guard.onWrite(req),
  () => guard.notice(),
);
guard.attach();

// --- Page-world hooks ---
function inject(nonce?: string): boolean {
  try {
    const script = doc.createElement('script');
    if (nonce) script.nonce = nonce;
    script.textContent = pageHookSource;
    // At document-start there may be no <html> yet; a script inserted as the root still runs.
    (doc.head ?? doc.documentElement ?? doc).appendChild(script);
    script.remove();
  } catch {
    // Trusted Types or CSP: not injected.
  }
  // The hook pairs synchronously while the inline script runs.
  return channel.paired();
}

if (!inject()) {
  // Either we already are in the page world (hook ourselves), or CSP blocked the inline script
  // (then this only hooks our own world, which is harmless).
  installHook(win, {
    ask: (req) => guard.onWrite(req),
    wait: () => new Promise((resolve) => setTimeout(() => resolve({ v: 'allow' }), 4000)),
  });
  // Retry with the nonce of the page's first nonce'd script (strict-dynamic pages).
  const tried = new Set<string>();
  const observer = new MutationObserver(() => {
    const nonce = doc.querySelector<HTMLScriptElement>('script[nonce]')?.nonce;
    if (!nonce || tried.has(nonce)) return;
    tried.add(nonce);
    if (inject(nonce) || tried.size > 3) observer.disconnect();
  });
  observer.observe(doc, { childList: true, subtree: true });
  win.addEventListener('load', () => observer.disconnect(), { once: true });

  // Meanwhile, check what copy handlers put on the clipboard (bubble phase on window runs after
  // handlers on the document and the target).
  const onCopy = (event: Event) => {
    const e = event as ClipboardEvent;
    if (channel.paired() || !e.isTrusted || !e.clipboardData) return;
    // Only what a page handler set; a plain user copy of their own selection is left alone.
    const written = e.clipboardData.getData('text/plain');
    if (!written) return;
    const reply = guard.onWrite({ via: 'setData', text: written });
    if (reply.v === 'block') {
      e.clipboardData.setData('text/plain', reply.notice);
      e.clipboardData.setData('text/html', '');
      e.preventDefault();
    }
  };
  win.addEventListener('copy', onCopy);
  win.addEventListener('cut', onCopy);
}

// --- Engine: inlined WASM (gzip + base64), wasm2js when WebAssembly is unavailable or blocked ---
async function wasmBytes(): Promise<Uint8Array | null> {
  if (typeof DecompressionStream !== 'function' || typeof WebAssembly !== 'object') return null;
  const bin = Uint8Array.from(atob(wasmGzipBase64), (c) => c.charCodeAt(0));
  const stream = new Blob([bin]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

wasmBytes()
  .catch(() => null)
  .then((bytes) => init(bytes ? { backend: 'auto', wasm: bytes } : { backend: 'wasm2js' }))
  .then(
    () => {
      engine = { backend: backend() ?? 'wasm2js', analyze, mask };
      console.debug('[PasteWarden] engine:', engine.backend);
      guard.engineReady();
    },
    (err: unknown) => {
      console.warn('[PasteWarden] engine failed to load:', (err as Error)?.name ?? 'Error');
      guard.engineReady();
    },
  );

// --- Manager menu (top frame only) ---
if (win === win.top && typeof GM_registerMenuCommand === 'function') {
  const t = () => guard.t();
  const host = win.location.hostname;
  GM_registerMenuCommand(
    `${t()('ui-ext-popup-toggle-enabled')}: ${settings.enabled ? 'ON' : 'OFF'}`,
    () => {
      saveSettings({ enabled: !settings.enabled });
      win.location.reload();
    },
  );
  if (host) {
    const paused = isAllowlisted(host, settings.allowlist);
    GM_registerMenuCommand(
      `${t()('ui-ext-popup-toggle-site')} (${host}): ${paused ? 'ON' : 'OFF'}`,
      () => {
        saveSettings({
          allowlist: paused
            ? settings.allowlist.filter((h) => !isAllowlisted(host, [h]))
            : [...settings.allowlist, host],
        });
        win.location.reload();
      },
    );
  }
}
