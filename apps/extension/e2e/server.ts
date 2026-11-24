// Local test site for the e2e tests: the same page under three CSPs (phase-3 §3.7, S2):
//   /a/  no CSP
//   /b/  script-src 'self'
//   /c/  strict nonce CSP (S2's "large site" policy plus frame-src for the iframe tests)
// Pages are served from 127.0.0.1; the "cross-origin" iframe comes from localhost.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export type CspVariant = 'a' | 'b' | 'c';
export const VARIANTS: CspVariant[] = ['a', 'b', 'c'];

const site = (name: string) => readFileSync(new URL(`./site/${name}`, import.meta.url), 'utf8');

function csp(variant: CspVariant, nonce: string, port: number): string | null {
  if (variant === 'a') return null;
  if (variant === 'b') return "script-src 'self'";
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' 'strict-dynamic' https: 'unsafe-inline'`,
    "connect-src 'self'",
    `frame-src 'self' http://localhost:${port}`,
    "require-trusted-types-for 'script'",
  ].join('; ');
}

export interface TestSite {
  origin: string;
  url(variant: CspVariant, page?: string): string;
  close(): Promise<void>;
}

export async function startSite(): Promise<TestSite> {
  let port = 0;
  const handler = (req: IncomingMessage, res: ServerResponse) => {
    const m = /^\/([abc])\/([a-z-]+\.(?:html|js))$/.exec(req.url?.split('?')[0] ?? '');
    if (!m) {
      res.writeHead(404).end();
      return;
    }
    const variant = m[1] as CspVariant;
    const file = m[2] as string;
    let body: string;
    try {
      body = site(file);
    } catch {
      res.writeHead(404).end();
      return;
    }
    const nonce = randomBytes(12).toString('base64');
    const headers: Record<string, string> = {
      'content-type': file.endsWith('.js')
        ? 'text/javascript; charset=utf-8'
        : 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    };
    if (file.endsWith('.html')) {
      body = body
        .replaceAll('{{CSP}}', variant)
        .replaceAll('{{NONCE}}', nonce)
        .replaceAll('{{XORIGIN}}', `http://localhost:${port}`);
      const policy = csp(variant, nonce, port);
      if (policy) headers['content-security-policy'] = policy;
    }
    res.writeHead(200, headers).end(body);
  };
  // Loopback only. `localhost` (the cross-origin frame) may resolve to ::1 or 127.0.0.1.
  const v4: Server = createServer(handler);
  await new Promise<void>((resolve) => v4.listen(0, '127.0.0.1', resolve));
  port = (v4.address() as AddressInfo).port;
  const v6: Server = createServer(handler);
  await new Promise<void>((resolve) => {
    v6.once('error', () => resolve()); // no IPv6 loopback: localhost resolves to 127.0.0.1
    v6.listen(port, '::1', resolve);
  });
  const servers = [v4, v6].filter((s) => s.listening);
  const origin = `http://127.0.0.1:${port}`;
  return {
    origin,
    url: (variant, page = 'index.html') => `${origin}/${variant}/${page}`,
    close: async () => {
      await Promise.all(
        servers.map(
          (s) =>
            new Promise<void>((resolve) => {
              // Browsers keep connections alive; without this, close() waits for
              // them and the worker fixture times out during teardown on CI.
              s.closeAllConnections();
              s.close(() => resolve());
            }),
        ),
      );
    },
  };
}
