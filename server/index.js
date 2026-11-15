// AnyDrop server (Bun + Elysia). A switchboard and a mailbox of sealed boxes:
// it never sees message text or file bytes. Protocol: PROTOCOL.md.
//
// Environment: PORT (8080), WEB_DIR (../web), DATA_DIR (data), PUBLIC_URL,
//              STUN_URL, TURN_URL, TURN_USER, TURN_PASS.

import { Elysia } from 'elysia';
import { statSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { join, resolve, sep } from 'node:path';
import QRCode from 'qrcode';
import { Hub } from './hub.js';
import { loadMail, saveMail } from './mailbox.js';

const env = (k) => process.env[k] || undefined;
const log = (msg) => console.log(`${new Date().toISOString()} ${msg}`);

const port = Number(env('PORT') ?? 8080);
const webDir = resolve(env('WEB_DIR') ?? join(import.meta.dir, '..', 'web'));
const dataDir = resolve(env('DATA_DIR') ?? 'data');

const iceServers = [{ urls: env('STUN_URL') ?? 'stun:stun.l.google.com:19302' }];
if (env('TURN_URL')) iceServers.push({ urls: env('TURN_URL'), username: env('TURN_USER') ?? null, credential: env('TURN_PASS') ?? null });

function lanIp() {
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.')) return a.address;
  }
}
const lanUrl = env('PUBLIC_URL') ?? (lanIp() ? `http://${lanIp()}:${port}` : null);
const config = { iceServers, lanUrl };

const hub = new Hub(loadMail(dataDir, log), log);
setInterval(() => saveMail(hub, dataDir, log), 2000);
setInterval(() => hub.prune(), 3600_000);
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    saveMail(hub, dataDir, log);
    process.exit(0);
  });
}

/** Serves a file from WEB_DIR, or index.html for a folder. Never leaves WEB_DIR. */
function serveStatic(pathname) {
  let rel;
  try {
    rel = decodeURIComponent(pathname);
  } catch {
    return new Response('bad path', { status: 400 });
  }
  let file = resolve(webDir, `.${rel}`);
  if (file !== webDir && !file.startsWith(webDir + sep)) return new Response('not found', { status: 404 });
  try {
    if (statSync(file).isDirectory()) file = join(file, 'index.html');
    if (statSync(file).isFile()) return new Response(Bun.file(file));
  } catch {}
  return new Response('not found', { status: 404 });
}

const conns = new WeakMap(); // Bun socket -> connection state

new Elysia({ websocket: { maxPayloadLength: 64 * 1024, idleTimeout: 120 } })
  .get('/api/health', () => 'ok')
  .get('/api/config', () => config)
  .get('/api/qr', async ({ query }) => {
    const data = typeof query.d === 'string' ? query.d : '';
    if (!data || data.length > 1024) return new Response('bad data', { status: 400 });
    const svg = await QRCode.toString(data, { type: 'svg', margin: 4, width: 240 });
    return new Response(svg, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'no-store' } });
  })
  .ws('/ws', {
    open(ws) {
      conns.set(ws.raw, hub.open(ws.raw));
    },
    message(ws, msg) {
      const conn = conns.get(ws.raw);
      if (!conn) return;
      if (typeof msg === 'string') {
        try { msg = JSON.parse(msg); } catch { return; }
      }
      try {
        hub.message(conn, msg);
      } catch (e) {
        log(`error handling ${msg?.type}: ${e.stack ?? e}`);
      }
    },
    close(ws) {
      const conn = conns.get(ws.raw);
      if (conn) hub.close(conn);
      conns.delete(ws.raw);
    },
  })
  .get('/*', ({ path }) => serveStatic(path))
  .listen({ port, hostname: '0.0.0.0' });

console.log(`\n  AnyDrop server running on port ${port}`);
console.log(`  This computer: http://localhost:${port}`);
if (lanUrl) {
  console.log(`  Phone:         ${lanUrl}   (same Wi-Fi - scan this)\n`);
  console.log(await QRCode.toString(lanUrl, { type: 'terminal', small: true }));
}
