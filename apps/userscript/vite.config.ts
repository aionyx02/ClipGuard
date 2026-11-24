import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import monkey from 'vite-plugin-monkey';
import { noDefaultWasmUrl, noNodeFsImport } from '../extension/scripts/core-plugins.mjs';
import { pasteWardenVirtuals, staticCoreImports } from './build-plugins';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const pkg = JSON.parse(readFileSync(here('package.json'), 'utf8')) as { version: string };
const RELEASES = 'https://github.com/aionyx02/paste-warden/releases/latest/download';

export default defineConfig({
  // The Fluent loader and the pastejack port read ../../locales and ../../rules at build time.
  server: { fs: { allow: [here('../..')] } },
  build: {
    target: 'es2022',
    minify: true,
    reportCompressedSize: false,
    chunkSizeWarningLimit: 8192,
  },
  plugins: [
    noDefaultWasmUrl(),
    noNodeFsImport(),
    staticCoreImports(),
    pasteWardenVirtuals(),
    monkey({
      entry: 'src/main.ts',
      build: {
        fileName: 'paste-warden.user.js',
        metaFileName: true,
        // No @require from a CDN: everything is in the one file.
        systemjs: 'inline',
      },
      userscript: {
        name: { '': 'PasteWarden', 'zh-TW': '剪貼簿守門員 PasteWarden' },
        description: {
          '': 'Clipboard guard: blocks commands websites put on your clipboard (ClickFix), confirms before pasting secrets, detects pastejacking. Runs entirely in your browser.',
          'zh-TW':
            '剪貼簿守門員：攔下網站放進剪貼簿的指令（ClickFix）、貼上機密前先確認、偵測複製內容被竄改。全部在瀏覽器裡完成。',
        },
        namespace: 'https://github.com/aionyx02/paste-warden',
        version: pkg.version,
        license: 'MIT',
        homepageURL: 'https://github.com/aionyx02/paste-warden',
        match: ['*://*/*'],
        'run-at': 'document-start',
        'inject-into': 'content',
        noframes: false,
        updateURL: `${RELEASES}/paste-warden.meta.js`,
        downloadURL: `${RELEASES}/paste-warden.user.js`,
        grant: ['GM_getValue', 'GM_setValue', 'GM_setClipboard', 'GM_registerMenuCommand'],
      },
    }),
  ],
});
