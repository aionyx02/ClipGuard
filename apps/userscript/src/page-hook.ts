// Page-world part of the userscript, injected as an inline <script> (built to a string by
// vite.config.ts). Same hook and channel as the extension's MAIN-world content script.
import { connectMain } from '../../extension/src/lib/channel';
import { installHook } from '../../extension/src/lib/hook';

installHook(window, connectMain(window));
