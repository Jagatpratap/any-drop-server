// The switchboard: login, presence, pairing, WebRTC signaling and the sealed mailbox.
// See PROTOCOL.md for the wire format. The server never sees message text or file bytes.

import { createHash, createPublicKey, verify, randomBytes, randomInt } from 'node:crypto';

const PAIR_TTL_MS = 600_000;
const MAX_PAIR_ATTEMPTS = 10;
export const MAIL_TTL_MS = 30 * 24 * 3600 * 1000;
const MAX_MAILBOX = 5000;
const MAX_BOX = 48 * 1024;
const MAX_KEY = 200;
const BATCH = 100;
const MAX_WATCH = 1000;

const B64URL = /^[A-Za-z0-9_-]*$/;
const ID = /^[0-9a-f]{32}$/;
const MID = /^[A-Za-z0-9_-]{1,64}$/;
const CONTROL = /\p{Cc}/gu;

const str = (v) => (typeof v === 'string' ? v : '');
const frame = (v) => JSON.stringify(v);
const randomB64 = (n) => randomBytes(n).toString('base64url');

/** Device id = first 16 bytes of sha256(raw public key), hex. */
const deviceId = (raw) => createHash('sha256').update(raw).digest().subarray(0, 16).toString('hex');

/** Checks the signed challenge. Returns { id, pub } or null. */
function verifyAuth(v, nonce) {
  const pub = str(v.pub), sig = str(v.sig);
  if (!B64URL.test(pub) || !B64URL.test(sig)) return null;
  const raw = Buffer.from(pub, 'base64url'), sigRaw = Buffer.from(sig, 'base64url');
  if (raw.length !== 65 || raw[0] !== 4 || sigRaw.length !== 64) return null;
  try {
    const key = createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: raw.subarray(1, 33).toString('base64url'), y: raw.subarray(33).toString('base64url') },
      format: 'jwk',
    });
    const ok = verify('sha256', Buffer.from(`anydrop-auth:${nonce}`), { key, dsaEncoding: 'ieee-p1363' }, sigRaw);
    return ok ? { id: deviceId(raw), pub } : null;
  } catch {
    return null; // not a point on the curve
  }
}

/** A trimmed display string without control characters, at most `max` characters. */
function clean(v, max, fallback) {
  const s = Array.from(str(v).trim().replace(CONTROL, '')).slice(0, max).join('');
  return s || fallback;
}

/** A base64url public key or signature, or "" if absent/invalid. */
const cleanKey = (v) => (str(v).length <= MAX_KEY && B64URL.test(str(v)) ? str(v) : '');

function parseWatch(v) {
  const ids = Array.isArray(v) ? v.filter((s) => typeof s === 'string' && ID.test(s)).slice(0, MAX_WATCH) : [];
  return new Set(ids);
}

const mailJson = (m) => ({ mid: m.mid, from: m.from, box: m.box, ts: m.ts });

export class Hub {
  /** @param {Map<string, object[]>} mail recipient id -> sealed messages waiting for an ack */
  constructor(mail = new Map(), log = console.log) {
    this.clients = new Map();  // id -> { conn, pub, box, boxSig, watch:Set, sock, lastOnline:string }
    this.pairings = new Map(); // token -> { owner, code, card, created }
    this.codes = new Map();    // 6-digit code -> token
    this.mail = mail;
    this.mailDirty = false;
    this.log = log;
    this.nextConn = 1;
  }

  /** A new socket connected. `sock.send(string)` must deliver a text frame. */
  open(sock) {
    const conn = { n: this.nextConn++, sock, nonce: randomB64(32), me: null, pairAttempts: 0 };
    sock.send(frame({ type: 'challenge', nonce: conn.nonce }));
    return conn;
  }

  close(conn) {
    const id = conn.me;
    const c = id && this.clients.get(id);
    if (!c || c.conn !== conn.n) return;
    this.clients.delete(id);
    this.log(`offline: ${id}`);
    this.presence(c.watch);
  }

  mutual(a, b) {
    return a !== b && !!this.clients.get(a)?.watch.has(b) && !!this.clients.get(b)?.watch.has(a);
  }

  /** Sends each affected online client its list of online mutual contacts, if it changed. */
  presence(affected) {
    for (const id of new Set(affected)) {
      const c = this.clients.get(id);
      if (!c) continue;
      const online = [...c.watch].filter((w) => this.mutual(id, w)).sort();
      const key = online.join(',');
      if (c.lastOnline !== key) {
        c.lastOnline = key;
        c.sock.send(frame({ type: 'online', ids: online }));
      }
    }
  }

  card(id, v) {
    const c = this.clients.get(id);
    return { id, pub: c.pub, box: c.box, boxSig: c.boxSig, name: clean(v.name, 40, 'Device'), device: clean(v.device, 16, 'other') };
  }

  sendTo(id, v) {
    this.clients.get(id)?.sock.send(frame(v));
  }

  /** Handles one parsed JSON frame from `conn`. */
  message(conn, v) {
    if (!v || typeof v !== 'object' || Array.isArray(v)) return;
    const reply = (m) => conn.sock.send(frame(m));
    const kind = str(v.type);

    if (kind === 'auth') {
      if (conn.me) return;
      const who = verifyAuth(v, conn.nonce);
      if (!who) return reply({ type: 'error', message: 'auth failed' });
      const { id, pub } = who;
      // One live connection per identity: the newest wins, the old tab is told why.
      const old = this.clients.get(id);
      if (old) {
        this.clients.delete(id);
        old.sock.send(frame({ type: 'replaced' }));
      }
      const watch = parseWatch(v.watch);
      this.clients.set(id, { conn: conn.n, pub, box: cleanKey(v.box), boxSig: cleanKey(v.boxSig), watch, sock: conn.sock, lastOnline: '' });
      conn.me = id;
      this.log(`online: ${id}`);
      reply({ type: 'welcome', id, time: Date.now() });
      const waiting = this.mail.get(id) ?? [];
      for (let i = 0; i < waiting.length; i += BATCH) reply({ type: 'msgs', items: waiting.slice(i, i + BATCH).map(mailJson) });
      this.presence([...watch, id]);
      return;
    }

    const id = conn.me;
    if (!id || this.clients.get(id)?.conn !== conn.n) return; // not logged in, or superseded by a newer connection
    const me = this.clients.get(id);

    switch (kind) {
      case 'ping':
        return reply({ type: 'pong' });

      case 'watch': {
        const watch = parseWatch(v.ids);
        const affected = [...me.watch, ...watch, id];
        me.watch = watch;
        return this.presence(affected);
      }

      case 'signal': {
        const to = str(v.to);
        if (this.mutual(id, to)) this.sendTo(to, { type: 'signal', from: id, data: v.data === undefined ? null : v.data });
        return;
      }

      // A sealed message. `live` ones (typing) are only passed to an online contact.
      // Others are kept until the recipient acks them, and forwarded now if it is online.
      case 'send': {
        const to = str(v.to), mid = str(v.mid), box = str(v.box);
        if (!ID.test(to) || to === id || !MID.test(mid) || !box || box.length > MAX_BOX) {
          return reply({ type: 'send-error', mid, message: 'invalid message' });
        }
        if (v.live === true) {
          if (this.mutual(id, to)) this.sendTo(to, { type: 'live', msg: { mid, from: id, box, ts: Date.now() } });
          return;
        }
        const list = this.mail.get(to) ?? [];
        const dup = list.find((m) => m.mid === mid && m.from === id);
        if (dup) return reply({ type: 'sent', mid, to, ts: dup.ts }); // retransmit: just confirm again
        if (list.length >= MAX_MAILBOX) return reply({ type: 'send-error', mid, message: 'recipient mailbox is full' });
        const m = { mid, from: id, box, ts: Date.now() };
        list.push(m);
        this.mail.set(to, list);
        this.mailDirty = true;
        this.sendTo(to, { type: 'msgs', items: [mailJson(m)] });
        return reply({ type: 'sent', mid, to, ts: m.ts });
      }

      case 'ack': {
        const mids = new Set(Array.isArray(v.mids) ? v.mids.filter((s) => typeof s === 'string').slice(0, 1000) : []);
        const list = this.mail.get(id);
        if (!list) return;
        const left = list.filter((m) => !mids.has(m.mid));
        if (left.length === list.length) return;
        if (left.length) this.mail.set(id, left);
        else this.mail.delete(id);
        this.mailDirty = true;
        return;
      }

      case 'pair-open': {
        const now = Date.now();
        for (const [token, p] of this.pairings) {
          if (now - p.created >= PAIR_TTL_MS || p.owner === id) this.pairings.delete(token);
        }
        for (const [code, token] of this.codes) if (!this.pairings.has(token)) this.codes.delete(code);
        let code;
        do code = String(randomInt(1_000_000)).padStart(6, '0');
        while (this.codes.has(code));
        const token = randomB64(18);
        this.codes.set(code, token);
        this.pairings.set(token, { owner: id, code, card: this.card(id, v), created: now });
        return reply({ type: 'pair-open', token, code, ttl: PAIR_TTL_MS / 1000 });
      }

      case 'pair-join': {
        conn.pairAttempts += 1;
        const token = typeof v.code === 'string' ? this.codes.get(v.code.trim()) : typeof v.token === 'string' ? v.token : undefined;
        const p = token !== undefined ? this.pairings.get(token) : undefined;
        const ok = p && Date.now() - p.created < PAIR_TTL_MS && p.owner !== id && this.clients.has(p.owner);
        if (conn.pairAttempts > MAX_PAIR_ATTEMPTS || !ok) {
          const message = conn.pairAttempts > MAX_PAIR_ATTEMPTS
            ? 'Too many attempts. Reload and try again.'
            : 'That code is invalid or expired, or the other device went offline.';
          return reply({ type: 'pair-error', message });
        }
        this.pairings.delete(token);
        this.codes.delete(p.code);
        this.sendTo(p.owner, { type: 'paired', peer: this.card(id, v) });
        return reply({ type: 'paired', peer: p.card });
      }

      case 'pair-close': {
        const token = str(v.token);
        const p = this.pairings.get(token);
        if (p && p.owner === id) {
          this.pairings.delete(token);
          this.codes.delete(p.code);
        }
        return;
      }
    }
  }

  /** Drops mail older than 30 days. */
  prune() {
    const cutoff = Date.now() - MAIL_TTL_MS;
    for (const [to, list] of this.mail) {
      const left = list.filter((m) => m.ts >= cutoff);
      if (left.length !== list.length) this.mailDirty = true;
      if (left.length) this.mail.set(to, left);
      else this.mail.delete(to);
    }
  }
}
