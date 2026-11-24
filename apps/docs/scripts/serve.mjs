// Minimal static server for screenshots / browser checks: maps URL prefixes to directories.
import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.woff2': 'font/woff2',
  '.wasm': 'application/wasm',
};

/** @param {Record<string, string>} mounts URL prefix (e.g. "/docs/") → directory */
export function serve(mounts, extraRoutes = {}) {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const route = extraRoutes[url.pathname];
    if (route) {
      res.writeHead(200, { 'content-type': route.type });
      res.end(route.body);
      return;
    }
    for (const [prefix, dir] of Object.entries(mounts)) {
      if (!url.pathname.startsWith(prefix)) continue;
      let file = normalize(join(dir, decodeURIComponent(url.pathname.slice(prefix.length))));
      if (!file.startsWith(normalize(dir))) break;
      if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html');
      if (!existsSync(file)) break;
      res.writeHead(200, { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' });
      createReadStream(file).pipe(res);
      return;
    }
    res.writeHead(404).end('not found');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = /** @type {import('node:net').AddressInfo} */ (server.address());
      resolve({ origin: `http://127.0.0.1:${port}`, close: () => server.close() });
    });
  });
}
