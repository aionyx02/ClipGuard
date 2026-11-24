// `pnpm --filter @paste-warden/extension build`: every browser artifact into dist/.
//
//   dist/paste-warden-chrome.zip      Chrome / Edge (MV3), load unpacked after extracting
//   dist/paste-warden-firefox.xpi     Firefox (MV3), unsigned until Phase 6
//   dist/paste-warden-firefox-sources.zip   sources for AMO review
//   dist/paste-warden.user.js         userscript (apps/userscript)
//
// Unpacked builds stay in .output/chrome-mv3 and .output/firefox-mv3 (the e2e tests load those).
// Needs @paste-warden/core built first (pnpm --filter @paste-warden/core build).
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const pkg = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(pkg, 'dist');
const out = join(pkg, '.output');
const win = process.platform === 'win32';

const run = (cmd, args, cwd = pkg) => {
  console.log(`$ ${cmd} ${args.join(' ')}`);
  execFileSync(cmd, args, { cwd, stdio: 'inherit', shell: win });
};

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

run('node', ['scripts/build-engine.mjs']);
const wxt = join(pkg, 'node_modules', '.bin', win ? 'wxt.cmd' : 'wxt');
run(wxt, ['zip']);
run(wxt, ['zip', '-b', 'firefox', '--mv3']);

copyFileSync(join(out, 'paste-warden-chrome.zip'), join(dist, 'paste-warden-chrome.zip'));
copyFileSync(join(out, 'paste-warden-firefox.zip'), join(dist, 'paste-warden-firefox.xpi'));
if (existsSync(join(out, 'paste-warden-firefox-sources.zip'))) {
  copyFileSync(
    join(out, 'paste-warden-firefox-sources.zip'),
    join(dist, 'paste-warden-firefox-sources.zip'),
  );
}

if (process.env.PW_SKIP_USERSCRIPT !== '1') {
  run('pnpm', ['--filter', '@paste-warden/userscript', 'build']);
  copyFileSync(
    join(pkg, '../userscript/dist/paste-warden.user.js'),
    join(dist, 'paste-warden.user.js'),
  );
}

const kb = (n) => `${(n / 1024).toFixed(0)} KiB`;
for (const name of [
  'paste-warden-chrome.zip',
  'paste-warden-firefox.xpi',
  'paste-warden.user.js',
]) {
  const file = join(dist, name);
  if (!existsSync(file)) continue;
  const size = statSync(file).size;
  const gz = name.endsWith('.js') ? `, ${kb(gzipSync(readFileSync(file)).length)} gzip` : '';
  console.log(`${name}: ${kb(size)}${gz}`);
}
