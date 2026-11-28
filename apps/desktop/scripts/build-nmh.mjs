// Builds `paste-warden-nmh` (crates/platform/src/bin) and copies it to
// src-tauri/binaries/paste-warden-nmh-<target triple>[.exe], the name Tauri's
// `bundle.externalBin` expects (tauri.release.conf.json). The bundler then
// ships it next to the app executable: Contents/MacOS (dmg), the install
// directory (msi / nsis), /usr/bin (deb) and usr/bin inside the AppImage.
//
// Runs as part of `beforeBuildCommand` when building with
// `cargo tauri build --config src-tauri/tauri.release.conf.json`. Tauri sets
// TAURI_ENV_TARGET_TRIPLE and TAURI_ENV_DEBUG for it; without them the host
// triple and a release build are used.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..', '..');
const out = resolve(here, '..', 'src-tauri', 'binaries');
const targetDir = process.env.CARGO_TARGET_DIR ?? join(root, 'target');
const debug = process.env.TAURI_ENV_DEBUG === 'true';
const profile = debug ? 'debug' : 'release';

const hostTriple = execFileSync('rustc', ['-vV'], { encoding: 'utf8' })
  .split('\n')
  .find((l) => l.startsWith('host: '))
  ?.slice('host: '.length)
  .trim();
const triple = process.env.TAURI_ENV_TARGET_TRIPLE || hostTriple;
if (!triple) throw new Error('build-nmh: cannot determine the target triple');

/** Builds for `t` and returns the path of the binary. */
function build(t) {
  const args = ['build', '--locked', '-p', 'paste-warden-platform', '--bin', 'paste-warden-nmh'];
  if (!debug) args.push('--release');
  // Only pass --target when cross-building: it moves the output directory.
  if (t !== hostTriple) args.push('--target', t);
  execFileSync('cargo', args, { cwd: root, stdio: 'inherit' });
  const exe = t.includes('windows') ? '.exe' : '';
  const dir = t === hostTriple ? join(targetDir, profile) : join(targetDir, t, profile);
  return join(dir, `paste-warden-nmh${exe}`);
}

mkdirSync(out, { recursive: true });
const ext = triple.includes('windows') ? '.exe' : '';
const dest = join(out, `paste-warden-nmh-${triple}${ext}`);
if (triple === 'universal-apple-darwin') {
  const parts = ['aarch64-apple-darwin', 'x86_64-apple-darwin'].map(build);
  execFileSync('lipo', ['-create', '-output', dest, ...parts], { stdio: 'inherit' });
} else {
  copyFileSync(build(triple), dest);
}
console.log(`build-nmh: ${dest}`);
