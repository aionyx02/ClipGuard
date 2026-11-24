// Background (Chrome service worker / Firefox event page): settings defaults, the recent-blocks
// log, relaying dialogs from sub-frames to the top frame, and the extension-side clipboard write
// (Chrome: offscreen document + execCommand('copy'); Firefox: navigator.clipboard here). S2.
//
// No engine runs here; nothing here keeps state in memory (the service worker can be killed).
import { browser } from 'wxt/browser';
import { defineBackground } from 'wxt/utils/define-background';
import type { ToBackground, ToContent, ToOffscreen } from '../lib/messages';
import {
  type BlockRecord,
  isBlockRecord,
  normalizeSettings,
  RECENT_KEY,
  RECENT_MAX,
  SETTINGS_KEY,
} from '../lib/settings';

/** Serializes read-modify-write of storage. */
let queue: Promise<unknown> = Promise.resolve();
const serial = <T>(fn: () => Promise<T>): Promise<T> => {
  const next = queue.then(fn, fn);
  queue = next.catch(() => {});
  return next;
};

async function appendRecord(record: BlockRecord): Promise<void> {
  await serial(async () => {
    const got = await browser.storage.local.get(RECENT_KEY);
    const list = Array.isArray(got[RECENT_KEY])
      ? (got[RECENT_KEY] as unknown[]).filter(isBlockRecord)
      : [];
    const clean: BlockRecord = {
      domain: record.domain.slice(0, 253),
      time: record.time,
      kind: record.kind,
      masked: record.masked.slice(0, 200),
    };
    await browser.storage.local.set({ [RECENT_KEY]: [clean, ...list].slice(0, RECENT_MAX) });
  });
}

const OFFSCREEN_URL = '/offscreen.html';

async function writeClipboard(text: string): Promise<boolean> {
  const offscreen = (globalThis as { chrome?: { offscreen?: ChromeOffscreen } }).chrome?.offscreen;
  if (import.meta.env.BROWSER !== 'firefox' && offscreen) {
    try {
      const has = await offscreen.hasDocument?.();
      if (!has) {
        await offscreen.createDocument({
          url: OFFSCREEN_URL,
          reasons: ['CLIPBOARD'],
          justification: 'Write the clipboard when the user allows a blocked copy once',
        });
      }
      const msg: ToOffscreen = { target: 'offscreen', type: 'offscreen-write', text };
      return (await browser.runtime.sendMessage(msg)) === true;
    } catch {
      return false;
    }
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

interface ChromeOffscreen {
  hasDocument?: () => Promise<boolean>;
  createDocument(o: { url: string; reasons: string[]; justification: string }): Promise<void>;
}

export default defineBackground(() => {
  browser.runtime.onInstalled.addListener(async () => {
    const got = await browser.storage.local.get(SETTINGS_KEY);
    // Writes the filled-in defaults (packs stay `null` = follow the browser languages).
    await browser.storage.local.set({ [SETTINGS_KEY]: normalizeSettings(got[SETTINGS_KEY]) });
  });

  browser.runtime.onMessage.addListener((raw: unknown, sender) => {
    if (sender.id !== browser.runtime.id) return undefined;
    const msg = raw as ToBackground & { target?: string };
    if (msg.target === 'offscreen') return undefined;
    switch (msg.type) {
      case 'record':
        if (isBlockRecord(msg.record)) return appendRecord(msg.record).then(() => true);
        return undefined;
      case 'present-blocked':
      case 'present-warning': {
        const tabId = sender.tab?.id;
        if (tabId === undefined) return Promise.resolve(false);
        const out: ToContent =
          msg.type === 'present-blocked'
            ? {
                type: 'show-blocked',
                report: msg.report,
                url: msg.url,
                locale: msg.locale,
                original: msg.original,
              }
            : { type: 'show-warning', locale: msg.locale, kind: msg.kind, reasons: msg.reasons };
        return browser.tabs.sendMessage(tabId, out, { frameId: 0 }).then(
          (ok) => ok === true,
          () => false,
        );
      }
      case 'clipboard-write':
        if (typeof msg.text !== 'string') return undefined;
        return writeClipboard(msg.text);
      default:
        return undefined;
    }
  });
});
