// Isolated world: runs the WASM engine (not bound by the page CSP, S2), answers the MAIN-world
// hook synchronously, guards pastes and shows the in-page overlay.
import { showClipboardBlocked, showPasteConfirm } from '@paste-warden/overlay';
import { browser } from 'wxt/browser';
import { defineContentScript } from 'wxt/utils/define-content-script';
import { connectContent } from '../lib/channel';
import { loadEngine } from '../lib/engine';
import { type BlockedEvent, type EngineApi, Guard, type WarnEvent } from '../lib/guard';
import type { TabStatus, ToBackground, ToContent } from '../lib/messages';
import {
  DEFAULT_SETTINGS,
  type ExtSettings,
  normalizeSettings,
  SETTINGS_KEY,
} from '../lib/settings';
import { translator } from '../lib/strings';
import { showNotice } from '../lib/toast';

export default defineContentScript({
  matches: ['<all_urls>'],
  runAt: 'document_start',
  allFrames: true,
  matchAboutBlank: true,
  matchOriginAsFallback: { chrome: true, firefox: false, edge: true },
  noScriptStartedPostMessage: true,
  main() {
    const win = window;
    const isTop = win === win.top;
    let settings: ExtSettings = DEFAULT_SETTINGS;
    let engine: EngineApi | null = null;

    const send = (msg: ToBackground) => browser.runtime.sendMessage(msg);

    /** Writes from this (isolated) world: not affected by the page's hooks. */
    const writeClipboard = async (text: string): Promise<boolean> => {
      try {
        await win.navigator.clipboard.writeText(text);
        return true;
      } catch {
        return send({ type: 'clipboard-write', text }).then(
          (ok) => ok === true,
          () => false,
        );
      }
    };

    const showBlocked = (e: BlockedEvent) => {
      void showClipboardBlocked(e.report, { url: e.url, locale: e.locale }).then((choice) => {
        if (choice === 'allow-once') void writeClipboard(e.original);
      });
    };
    const showWarning = (e: WarnEvent) => {
      const t = translator(e.locale);
      const pj = e.kind === 'pastejack';
      showNotice(win.document, {
        brand: t('ui-ext-toast-brand'),
        title: t(pj ? 'ui-ext-toast-pastejack-title' : 'ui-ext-toast-warn-title'),
        body: t(pj ? 'ui-ext-toast-pastejack-body' : 'ui-ext-toast-warn-body'),
        reasons: e.reasons,
        dismiss: t('ui-ext-toast-dismiss'),
      });
    };

    const guard = new Guard({
      win,
      settings: () => settings,
      engine: () => engine,
      // A hidden or tiny frame can't show a dialog the user would see: show it in the top frame.
      presentBlocked: (e) => {
        if (isTop) return showBlocked(e);
        send({ type: 'present-blocked', ...e }).then(
          (ok) => ok !== true && showBlocked(e),
          () => showBlocked(e),
        );
      },
      presentWarning: (e) => {
        if (isTop) return showWarning(e);
        send({ type: 'present-warning', ...e }).then(
          (ok) => ok !== true && showWarning(e),
          () => showWarning(e),
        );
      },
      confirmPaste: (report, locale) => showPasteConfirm(report, { locale }),
      overwriteClipboard: (text) =>
        send({ type: 'clipboard-write', text }).then(
          (ok) => ok === true,
          () => false,
        ),
      record: (record, verdict) => {
        send({ type: 'record', record, verdict }).catch(() => {});
      },
      resolveWait: (id, reply) => channel.resolve(id, reply),
    });

    // Order matters: the channel and listeners must exist before any page script runs.
    const channel = connectContent(
      win,
      (req) => guard.onWrite(req),
      () => guard.notice(),
    );
    guard.attach();

    browser.storage.local.get(SETTINGS_KEY).then(
      (got) => {
        settings = normalizeSettings(got[SETTINGS_KEY]);
      },
      () => {},
    );
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes[SETTINGS_KEY]) {
        settings = normalizeSettings(changes[SETTINGS_KEY].newValue);
      }
    });

    // public/ assets added by the build hook aren't in WXT's typed path list.
    const assetUrl = browser.runtime.getURL as (path: string) => string;
    loadEngine(assetUrl('/engine/paste_warden_bg.wasm'), assetUrl('/engine/w2j/index.js')).then(
      (e) => {
        engine = e;
        guard.engineReady();
      },
      (err: unknown) => {
        console.warn('[PasteWarden] engine failed to load:', (err as Error)?.message ?? err);
        guard.engineReady();
      },
    );

    browser.runtime.onMessage.addListener((raw: unknown) => {
      const msg = raw as ToContent;
      if (!isTop) return undefined;
      if (msg.type === 'status') {
        const status: TabStatus = {
          host: win.location.hostname,
          enabled: settings.enabled,
          paused: settings.enabled && !guard.active(),
          blocked: guard.stats.blocked,
          warned: guard.stats.warned,
          backend: engine?.backend ?? null,
        };
        return Promise.resolve(status);
      }
      if (msg.type === 'show-blocked') {
        guard.stats.blocked++;
        showBlocked(msg);
        return Promise.resolve(true);
      }
      if (msg.type === 'show-warning') {
        guard.stats.warned++;
        showWarning(msg);
        return Promise.resolve(true);
      }
      return undefined;
    });
  },
});
