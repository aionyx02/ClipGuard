// MAIN world: wraps the page's clipboard-writing APIs and asks the isolated content script
// (guard.content.ts) for a verdict over a per-page random CustomEvent channel (S2, T17).
import { defineContentScript } from 'wxt/utils/define-content-script';
import { connectMain } from '../lib/channel';
import { installHook } from '../lib/hook';

export default defineContentScript({
  matches: ['<all_urls>'],
  world: 'MAIN',
  runAt: 'document_start',
  allFrames: true,
  matchAboutBlank: true,
  // T18: also inject into about:blank / data: / blob: frames by their creator's origin.
  matchOriginAsFallback: { chrome: true, firefox: false, edge: true },
  noScriptStartedPostMessage: true,
  main() {
    installHook(window, connectMain(window));
  },
});
