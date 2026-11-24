// macOS only: headless Chromium may use the system pasteboard. Keep a copy of its plain-text
// content in memory (never printed or written to disk) and put it back after the run if the
// tests changed it. Linux CI (headless, no display server clipboard) and Firefox headless use an
// in-memory clipboard, so there is nothing to do there.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const digest = (b: Buffer) => createHash('sha256').update(b).digest('hex');

export default function globalSetup(): (() => void) | undefined {
  if (process.platform !== 'darwin') return undefined;
  let backup: Buffer;
  try {
    backup = execFileSync('pbpaste', ['-Prefer', 'txt'], { maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return undefined;
  }
  const before = digest(backup);
  return () => {
    try {
      const now = execFileSync('pbpaste', ['-Prefer', 'txt'], { maxBuffer: 64 * 1024 * 1024 });
      if (digest(now) !== before) {
        execFileSync('pbcopy', [], { input: backup });
        console.log('[e2e] restored the system clipboard');
      }
    } finally {
      backup.fill(0);
    }
  };
}
