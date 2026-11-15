// AnyDrop client.
//
// Text goes through the server, sealed end to end (seal.js): the server holds the
// sealed box until the other device acks it, so the sender can go offline. Receipts,
// typing and name changes travel the same way. The server can't read any of it.
// Files go device-to-device over WebRTC ("file:<id>" data channels), using the
// server only to pass the signed offers/answers/ICE.
// Ticks: clock = not on the server yet, ✓ = server has it, ✓✓ = delivered, blue = read.

import { db } from './db.js';
import { loadIdentity, verify, idFromPub, fingerprint } from './identity.js';
import { loadBoxKey, seal, open as unseal } from './seal.js';

const CHUNK = 64 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const LINK_TIMEOUT = 15000;
const MAX_TEXT = 20000;

const $ = (s) => document.querySelector(s);
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const uid = () => hex(crypto.getRandomValues(new Uint8Array(16)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};

// ---------- icons ----------
const svg = (body, vb = '0 0 24 24') => `<svg viewBox="${vb}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
const I = {
  phone: svg('<rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>'),
  tablet: svg('<rect x="4" y="2.5" width="16" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>'),
  laptop: svg('<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>'),
  desktop: svg('<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M9 20h6M12 16v4"/>'),
  add: svg('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3M21 14v7h-7M17.5 17.5h.01"/>'),
  back: svg('<path d="M15 5l-7 7 7 7"/>'),
  send: svg('<path d="M4 12l16-8-6 16-2.5-6.5z"/><path d="M11.5 13.5L20 4"/>'),
  clip: svg('<path d="M20.5 11.5l-8.3 8.3a5 5 0 01-7.1-7.1l8.3-8.3a3.5 3.5 0 015 5l-8.3 8.3a2 2 0 01-2.8-2.8l7.6-7.6"/>'),
  file: svg('<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5"/>'),
  clock: svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
  fail: svg('<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5h.01"/>'),
  tick: '<svg viewBox="0 0 16 11" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6l3 3 6-7"/></svg>',
  ticks: '<svg viewBox="0 0 16 11" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 6l3 3 6-7M7.5 8.5l.5.5 6-7"/></svg>',
};

// ---------- device types ----------
const DEVICES = {
  android: ['Android phone', 'phone'],
  'android-tablet': ['Android tablet', 'tablet'],
  iphone: ['iPhone', 'phone'],
  ipad: ['iPad', 'tablet'],
  macbook: ['MacBook', 'laptop'],
  mac: ['Mac', 'desktop'],
  'windows-laptop': ['Windows laptop', 'laptop'],
  windows: ['Windows PC', 'desktop'],
  linux: ['Linux', 'desktop'],
  chromebook: ['Chromebook', 'laptop'],
  other: ['Other device', 'desktop'],
};
const deviceKey = (d) => (Object.hasOwn(DEVICES, d) ? d : 'other');
const deviceLabel = (d) => DEVICES[deviceKey(d)][0];

function detectDevice() {
  const ua = navigator.userAgent;
  if (/Android/i.test(ua)) return /Mobile/i.test(ua) ? 'android' : 'android-tablet';
  if (/iPhone|iPod/i.test(ua)) return 'iphone';
  if (/iPad/i.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'ipad';
  if (/Macintosh/.test(ua)) return 'macbook';
  if (/CrOS/.test(ua)) return 'chromebook';
  if (/Windows/.test(ua)) return 'windows';
  if (/Linux/.test(ua)) return 'linux';
  return 'other';
}
function defaultName(device) {
  const a = ['Blue', 'Swift', 'Quiet', 'Bright', 'Lucky', 'Calm', 'Bold', 'Sunny'];
  const b = ['Otter', 'Falcon', 'Panda', 'Fox', 'Koala', 'Lynx', 'Heron', 'Tiger'];
  const r = crypto.getRandomValues(new Uint8Array(2));
  return `${deviceLabel(device)} · ${a[r[0] % a.length]} ${b[r[1] % b.length]}`;
}
const cleanName = (s, fallback = 'Device') => String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 40) || fallback;

// ---------- state ----------
let me;                          // { id, pub, sign }
let box;                         // { pub, sig, ... } this device's sealing key
let profile;                     // { name, device }
const contacts = new Map();      // id -> contact
let online = new Set();          // contacts the server says are online
const links = new Map();         // peer id -> WebRTC link
const retry = new Map();         // peer id -> { delay, timer }
const sigChains = new Map();     // peer id -> promise chain (signals handled in order)
const typingUntil = new Map();   // peer id -> timestamp
const incoming = new Map();      // msg key -> { meta, got } (files arriving)
const progress = new Map();      // msg key -> bytes sent
const urls = new Map();          // msg key -> object URL
let active = null;               // open chat id
let shown = [];                  // messages of the open chat
let ws = null, wsUp = false, replaced = false, wsDelay = 1000;
let iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
let lanUrl = null;
let pendingPair = null;          // { token, id } from a scanned link
let pairing = null;              // { token, code, expires } that we are showing

// ---------- storage helpers ----------
const keyOf = (chat, id) => `${chat}:${id}`;
const saveContact = (c) => db.put('contacts', c).catch(console.warn);
async function saveMsg(m) {
  await db.put('messages', m);
  const c = contacts.get(m.chat);
  if (c && (!c.last || c.last.key === m.key || m.ts >= c.last.ts)) {
    c.last = { key: m.key, ts: m.ts, dir: m.dir, status: m.status, text: m.kind === 'file' ? `📎 ${m.file.name}` : m.text.slice(0, 120) };
    await saveContact(c);
  }
  if (m.chat === active) upsertShown(m);
  renderChats();
}

// ---------- server connection ----------
function connect() {
  if (replaced) return;
  ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onmessage = (e) => { try { onServer(JSON.parse(e.data)); } catch (err) { console.warn(err); } };
  ws.onclose = () => {
    wsUp = false;
    online = new Set();
    renderConn(); renderChats(); renderHead(); renderNotice();
    if (!replaced) setTimeout(connect, wsDelay), (wsDelay = Math.min(wsDelay * 2, 15000));
  };
}
const send = (m) => ws?.readyState === 1 && (ws.send(JSON.stringify(m)), true);
const signal = (to, data) => send({ type: 'signal', to, data });
const sendWatch = () => send({ type: 'watch', ids: [...contacts.keys()] });
setInterval(() => send({ type: 'ping' }), 25000);

async function onServer(m) {
  switch (m.type) {
    case 'challenge':
      send({ type: 'auth', pub: me.pub, sig: await me.sign(`anydrop-auth:${m.nonce}`), box: box.pub, boxSig: box.sig, watch: [...contacts.keys()] });
      break;
    case 'welcome':
      wsUp = true; wsDelay = 1000;
      renderConn(); renderNotice();
      flushOutbox();
      if (pendingPair) send({ type: 'pair-join', token: pendingPair.token, ...profile });
      if ($('#addDlg').open && currentTab === 'show') openPairing();
      break;
    case 'online': onOnline(new Set(m.ids)); break;
    case 'msgs': mailChain = mailChain.then(() => onMail(m.items)).catch(console.warn); break;
    case 'live': onLive(m.msg); break;
    case 'sent': if (contacts.has(m.to)) setStatus(m.to, m.mid, 'sent'); break;
    case 'send-error': console.warn('server refused message', m.mid, m.message); break;
    case 'signal': queueSignal(m.from, m.data); break;
    case 'pair-open': showPairing(m); break;
    case 'pair-error':
      $('#pairErr').textContent = m.message;
      if (pendingPair) { toast(m.message); pendingPair = null; }
      break;
    case 'paired': onPaired(m.peer); break;
    case 'replaced':
      replaced = true;
      $('#replaced').hidden = false;
      for (const l of [...links.values()]) dropLink(l, false);
      break;
  }
}

// ---------- sealed messages through the server ----------
let mailChain = Promise.resolve();
const canSeal = (c) => typeof c?.box === 'string' && c.box.length > 0;

async function post(peer, obj, { mid = uid(), live = false } = {}) {
  const c = contacts.get(peer);
  if (!canSeal(c) || !wsUp) return false;
  const sealed = await seal(box, c.box, me.id, peer, mid, obj);
  return send({ type: 'send', to: peer, mid, box: sealed, ...(live ? { live: true } : {}) });
}

// Everything the server hasn't confirmed yet, plus read receipts it never got.
async function flushOutbox() {
  for (const c of contacts.values()) {
    if (!canSeal(c)) continue;
    const msgs = await db.chat(c.id);
    for (const m of msgs) if (m.dir === 'out' && m.kind === 'text' && m.status === 'pending') await post(c.id, { k: 'text', text: m.text, ts: m.ts }, { mid: m.id });
    const reads = msgs.filter((m) => m.dir === 'in' && m.status === 'read' && !m.rs);
    if (reads.length && (await post(c.id, { k: 'rcpt', st: 'read', mids: reads.map((m) => m.id) }))) for (const m of reads) { m.rs = true; db.put('messages', m); }
  }
}

async function onMail(items) {
  const acks = [];
  const delivered = new Map(); // peer -> mids
  for (const it of Array.isArray(items) ? items : []) {
    if (typeof it?.mid !== 'string') continue;
    acks.push(it.mid);
    const c = contacts.get(it.from);
    if (!canSeal(c)) continue; // not someone we paired with: drop it
    const d = await unseal(box, c.box, it.from, me.id, it.mid, String(it.box || ''));
    if (!d) { console.warn('dropped a box that failed to open, from', it.from); continue; }
    if (d.k === 'text' && typeof d.text === 'string') {
      const key = keyOf(c.id, it.mid);
      if (!(await db.get('messages', key))) {
        typingUntil.delete(c.id);
        await gotMessage({ key, id: it.mid, chat: c.id, dir: 'in', kind: 'text', text: d.text.slice(0, MAX_TEXT), ts: tsOf(d.ts), status: 'delivered' });
      }
      if (!delivered.has(c.id)) delivered.set(c.id, []);
      delivered.get(c.id).push(it.mid);
    } else if (d.k === 'rcpt' && Array.isArray(d.mids) && ['delivered', 'read'].includes(d.st)) {
      for (const id of d.mids.slice(0, 1000)) if (typeof id === 'string') await setStatus(c.id, id, d.st);
    } else if (d.k === 'profile') {
      applyProfile(c, d);
    }
  }
  for (const [peer, mids] of delivered) await post(peer, { k: 'rcpt', st: 'delivered', mids });
  if (acks.length) send({ type: 'ack', mids: acks });
}

async function onLive(it) {
  const c = contacts.get(it?.from);
  if (!canSeal(c)) return;
  const d = await unseal(box, c.box, it.from, me.id, String(it.mid), String(it.box || ''));
  if (d?.k === 'typing') {
    typingUntil.set(c.id, Date.now() + 4000);
    renderChats(); renderHead();
    setTimeout(() => { renderChats(); renderHead(); }, 4100);
  }
}

function applyProfile(c, d) {
  const name = cleanName(d.name, c.name), device = deviceKey(d.device);
  if (name === c.name && device === c.device) return;
  c.name = name; c.device = device;
  saveContact(c); renderChats(); renderHead();
}

function onOnline(ids) {
  const prev = online;
  online = ids;
  for (const id of prev) {
    if (!ids.has(id) && contacts.has(id)) {
      contacts.get(id).lastSeen = Date.now();
      saveContact(contacts.get(id));
      probe(links.get(id)); // its page is probably gone: check the P2P link quickly
    }
  }
  for (const id of ids) if (!prev.has(id)) ensureLink(id);
  renderChats(); renderHead(); renderNotice();
}

// ---------- WebRTC links (one per contact) ----------
// The lower id dials; the higher id says "hey" so the lower one dials it.
const sdpText = (sid, from, to, d) => `anydrop-sdp:${sid}:${from}>${to}:${d.type}:${d.sdp}`;
const linkOpen = (id) => links.get(id)?.open === true;

// Heartbeat: a closed tab or a dropped network can leave a channel looking "open"
// for a long time. Any frame from the peer counts as a sign of life.
const PING_AFTER = 8000, DEAD_AFTER = 20000;
function probe(link, wait = 3000) {
  if (!link?.open) return;
  const asked = Date.now();
  chatSend(link, { t: 'ping' });
  setTimeout(() => link.heard < asked && dropLink(link), wait);
}
setInterval(() => {
  for (const l of links.values()) {
    if (!l.open) continue;
    const quiet = Date.now() - l.heard;
    if (quiet > DEAD_AFTER) dropLink(l);
    else if (quiet > PING_AFTER) chatSend(l, { t: 'ping' });
  }
}, 4000);

function ensureLink(id) {
  if (!contacts.has(id) || !online.has(id) || replaced) return;
  const l = links.get(id);
  if (l && (l.open || Date.now() - l.born < LINK_TIMEOUT)) return;
  if (me.id < id) dial(id);
  else signal(id, { hey: 1 });
}

function scheduleRetry(id) {
  const r = retry.get(id) || { delay: 1000 };
  clearTimeout(r.timer);
  r.timer = setTimeout(() => ensureLink(id), r.delay);
  r.delay = Math.min(r.delay * 2, 30000);
  retry.set(id, r);
}

function newLink(peer, sid) {
  const pc = new RTCPeerConnection({ iceServers });
  const link = { peer, sid, pc, dc: null, open: false, dead: false, born: Date.now(), fileChain: Promise.resolve() };
  pc.onicecandidate = (e) => e.candidate && signal(peer, { sid, ice: e.candidate.toJSON() });
  pc.ondatachannel = (e) => attachChannel(link, e.channel);
  pc.onconnectionstatechange = () => ['failed', 'closed'].includes(pc.connectionState) && dropLink(link);
  link.timer = setTimeout(() => !link.open && dropLink(link), LINK_TIMEOUT);
  links.set(peer, link);
  return link;
}

function dropLink(link, again = true) {
  if (link.dead) return;
  link.dead = true;
  clearTimeout(link.timer);
  try { link.pc.close(); } catch {}
  if (links.get(link.peer) === link) links.delete(link.peer);
  for (const [k, v] of incoming) if (v.link === link) incoming.delete(k);
  renderHead();
  if (link.peer === active) renderShown();
  if (again && online.has(link.peer)) scheduleRetry(link.peer);
}

async function dial(peer) {
  const old = links.get(peer);
  if (old) dropLink(old, false);
  const link = newLink(peer, uid());
  attachChannel(link, link.pc.createDataChannel('chat', { ordered: true }));
  try {
    await link.pc.setLocalDescription(await link.pc.createOffer());
    await sendSdp(link);
  } catch (e) {
    console.warn('offer failed', e);
    dropLink(link);
  }
}

async function sendSdp(link) {
  const d = link.pc.localDescription;
  const sdp = { type: d.type, sdp: d.sdp };
  signal(link.peer, { sid: link.sid, sdp, sig: await me.sign(sdpText(link.sid, me.id, link.peer, sdp)) });
}

function queueSignal(from, data) {
  const chain = (sigChains.get(from) || Promise.resolve()).then(() => onSignal(from, data)).catch((e) => console.warn('signal', e));
  sigChains.set(from, chain);
}

async function onSignal(from, d) {
  const c = contacts.get(from);
  if (!c || !d || typeof d !== 'object') return;
  if (d.hey) {
    // The other side has no working link to us: start a fresh one (we are the dialer).
    if (me.id < from) {
      const l = links.get(from);
      if (!l || l.open || Date.now() - l.born > 2000) dial(from);
    }
    return;
  }
  if (typeof d.sid !== 'string') return;
  if (d.sdp && typeof d.sdp.sdp === 'string') {
    if (!(await verify(c.pub, sdpText(d.sid, from, me.id, d.sdp), String(d.sig || '')))) {
      console.warn('dropped unsigned or forged offer/answer from', from);
      return;
    }
    if (d.sdp.type === 'offer') {
      const old = links.get(from);
      if (old) dropLink(old, false);
      const link = newLink(from, d.sid);
      await link.pc.setRemoteDescription(d.sdp);
      await link.pc.setLocalDescription(await link.pc.createAnswer());
      await sendSdp(link);
    } else if (d.sdp.type === 'answer') {
      const link = links.get(from);
      if (link?.sid === d.sid && link.pc.signalingState === 'have-local-offer') await link.pc.setRemoteDescription(d.sdp);
    }
  } else if (d.ice) {
    const link = links.get(from);
    if (link?.sid === d.sid && !link.dead) await link.pc.addIceCandidate(d.ice).catch(() => {});
  }
}

function attachChannel(link, dc) {
  dc.binaryType = 'arraybuffer';
  if (dc.label === 'chat') {
    link.dc = dc;
    dc.onopen = () => onLinkOpen(link);
    dc.onclose = () => dropLink(link);
    let chain = Promise.resolve(); // handle chat frames in arrival order
    dc.onmessage = (e) => { if (typeof e.data === 'string') chain = chain.then(() => onChat(link, e.data)).catch(console.warn); };
    if (dc.readyState === 'open') onLinkOpen(link);
  } else if (dc.label.startsWith('file:')) {
    receiveFile(link, dc);
  } else {
    dc.close();
  }
}

const chatSend = (link, obj) => {
  if (!link?.open || link.dc?.readyState !== 'open') return false;
  link.dc.send(JSON.stringify(obj));
  return true;
};

async function onLinkOpen(link) {
  if (link.open || link.dead) return;
  link.open = true;
  link.heard = Date.now();
  clearTimeout(link.timer);
  const r = retry.get(link.peer);
  if (r) { clearTimeout(r.timer); retry.delete(link.peer); }
  chatSend(link, { t: 'hello', name: profile.name, device: profile.device });
  renderHead(); renderChats(); renderNotice();
  // Files waiting for this device go now (text goes through the server instead).
  for (const m of await db.chat(link.peer)) if (m.dir === 'out' && m.kind === 'file' && (m.status === 'pending' || m.status === 'sent')) transmit(link, m);
}

function transmit(link, m) {
  link.fileChain = link.fileChain.then(() => sendFile(link, m)).catch((e) => console.warn('file send', e));
}

// Status changes run one at a time: a "read" and an "ack" often arrive back to back
// and must not overwrite each other. Status only ever moves forward.
const RANK = { pending: 0, sent: 1, delivered: 2, read: 3 };
let statusChain = Promise.resolve();
function setStatus(chat, id, status) {
  statusChain = statusChain.then(async () => {
    const m = await db.get('messages', keyOf(chat, id));
    if (m && m.dir === 'out' && RANK[status] > (RANK[m.status] ?? -1)) { m.status = status; await saveMsg(m); }
  }).catch(console.warn);
  return statusChain;
}
const markSent = (m) => setStatus(m.chat, m.id, 'sent');

async function onChat(link, raw) {
  let d;
  try { d = JSON.parse(raw); } catch { return; }
  const peer = link.peer;
  const c = contacts.get(peer);
  if (!c) return;
  link.heard = Date.now();
  switch (d.t) {
    case 'ping': chatSend(link, { t: 'pong' }); break;
    case 'pong': break;
    case 'hello': applyProfile(c, d); break;
    case 'msg': {
      if (typeof d.id !== 'string' || d.id.length > 64 || typeof d.text !== 'string') return;
      const key = keyOf(peer, d.id);
      if (!(await db.get('messages', key))) {
        const m = { key, id: d.id, chat: peer, dir: 'in', kind: 'text', text: d.text.slice(0, MAX_TEXT), ts: tsOf(d.ts), status: 'delivered' };
        typingUntil.delete(peer);
        await gotMessage(m);
      }
      chatSend(link, { t: 'ack', id: d.id });
      break;
    }
    case 'ack': if (typeof d.id === 'string') setStatus(peer, d.id, 'delivered'); break;
    case 'read': for (const id of (Array.isArray(d.ids) ? d.ids : []).slice(0, 1000)) if (typeof id === 'string') await setStatus(peer, id, 'read'); break;
    case 'typing':
      typingUntil.set(peer, Date.now() + 4000);
      renderChats(); renderHead();
      setTimeout(() => { renderChats(); renderHead(); }, 4100);
      break;
  }
}

// Sender clocks can be off; never place a message in the future.
const tsOf = (ts) => Math.min(Number(ts) || Date.now(), Date.now());

async function gotMessage(m) {
  const c = contacts.get(m.chat);
  const seeing = m.chat === active && document.visibilityState === 'visible';
  if (!seeing) c.unread = (c.unread || 0) + 1;
  await saveMsg(m);
  if (seeing) markRead(m.chat);
  else notify(c, m);
}

// ---------- files over their own data channel ----------
async function sendFile(link, m) {
  if (link.dead) return;
  const fresh = await db.get('messages', m.key);
  if (!fresh || fresh.status === 'delivered' || fresh.status === 'read') return;
  const dc = link.pc.createDataChannel(`file:${m.id}`, { ordered: true });
  dc.binaryType = 'arraybuffer';
  dc.bufferedAmountLowThreshold = 1024 * 1024;
  await new Promise((resolve, reject) => {
    dc.onopen = resolve;
    dc.onclose = () => reject(new Error('closed'));
    setTimeout(() => reject(new Error('timeout')), 10000);
  });
  const acked = new Promise((resolve) => { dc.onmessage = (e) => e.data === 'ok' && resolve(true); dc.onclose = () => resolve(false); });
  dc.send(JSON.stringify({ id: m.id, ts: m.ts, name: m.file.name, size: m.file.size, mime: m.file.type }));
  const blob = fresh.blob;
  for (let off = 0; off < m.file.size; off += CHUNK) {
    if (link.dead || dc.readyState !== 'open') throw new Error('link closed');
    const buf = await blob.slice(off, off + CHUNK).arrayBuffer();
    while (dc.bufferedAmount > HIGH_WATER) await new Promise((r) => { dc.onbufferedamountlow = r; setTimeout(r, 250); });
    dc.send(buf);
    progress.set(m.key, off + buf.byteLength);
    paintProgress(m.key, (off + buf.byteLength) / m.file.size);
  }
  dc.send('end');
  await markSent(fresh);
  // The receiver answers "ok" once it has stored the whole file; then it closes the channel.
  const ok = await Promise.race([acked, sleep(120000).then(() => false)]);
  progress.delete(m.key);
  if (ok) await setStatus(m.chat, m.id, 'delivered');
  else if (m.chat === active) renderShown();
  try { dc.close(); } catch {}
}

function receiveFile(link, dc) {
  const peer = link.peer;
  let meta = null, key = null, parts = [], got = 0, finished = false;
  dc.onmessage = async (e) => {
    if (typeof e.data !== 'string') {
      if (!meta || finished) return;
      got += e.data.byteLength;
      if (got > meta.size) { dc.close(); return; }
      parts.push(e.data);
      incoming.get(key).got = got;
      paintProgress(key, got / (meta.size || 1));
      return;
    }
    if (!meta) {
      let h;
      try { h = JSON.parse(e.data); } catch { return dc.close(); }
      if (typeof h.id !== 'string' || h.id.length > 64 || !(Number(h.size) >= 0)) return dc.close();
      meta = { name: String(h.name || 'file').slice(0, 255), size: Number(h.size), type: String(h.mime || '').slice(0, 100) };
      key = keyOf(peer, h.id);
      meta.id = h.id; meta.ts = tsOf(h.ts);
      if (await db.get('messages', key)) { finished = true; dc.send('ok'); return; } // already have it
      incoming.set(key, { meta, got: 0, link });
      if (peer === active) renderShown();
      return;
    }
    if (e.data === 'end' && !finished && got === meta.size) {
      finished = true;
      incoming.delete(key);
      const blob = new Blob(parts, { type: meta.type || 'application/octet-stream' });
      parts = [];
      await gotMessage({ key, id: meta.id, chat: peer, dir: 'in', kind: 'file', file: { name: meta.name, size: meta.size, type: meta.type }, blob, ts: meta.ts, status: 'delivered' });
      try { dc.send('ok'); } catch {}
      setTimeout(() => { try { dc.close(); } catch {} }, 500);
    }
  };
  dc.onclose = () => {
    if (!finished && key && incoming.delete(key) && peer === active) renderShown();
  };
}

// ---------- sending ----------
async function sendText(peer, text) {
  text = text.trim().slice(0, MAX_TEXT);
  if (!text) return;
  const id = uid();
  const m = { key: keyOf(peer, id), id, chat: peer, dir: 'out', kind: 'text', text, ts: Date.now(), status: 'pending' };
  await saveMsg(m);
  if (!canSeal(contacts.get(peer))) toast('Pair with this device again to send messages (its encryption key is missing).');
  else post(peer, { k: 'text', text, ts: m.ts }, { mid: id });
  renderNotice();
}

async function sendFiles(peer, files) {
  for (const f of files) {
    const id = uid();
    const m = { key: keyOf(peer, id), id, chat: peer, dir: 'out', kind: 'file', file: { name: f.name, size: f.size, type: f.type }, blob: f, ts: Date.now(), status: 'pending' };
    await saveMsg(m);
    deliverOrQueue(peer, m);
  }
}

function deliverOrQueue(peer, m) {
  const link = links.get(peer);
  if (link?.open) transmit(link, m);
  else ensureLink(peer);
  renderNotice();
}

function markRead(chat) {
  const c = contacts.get(chat);
  const unread = shown.filter((m) => m.chat === chat && m.dir === 'in' && m.status !== 'read');
  if (c?.unread) { c.unread = 0; saveContact(c); renderChats(); }
  if (!unread.length) return;
  for (const m of unread) { m.status = 'read'; m.rs = false; db.put('messages', m); }
  post(chat, { k: 'rcpt', st: 'read', mids: unread.map((m) => m.id) }).then((ok) => {
    if (ok) for (const m of unread) { m.rs = true; db.put('messages', m); }
  });
}

// ---------- pairing ----------
function pairUrl(token) {
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  const base = local && lanUrl ? lanUrl : location.origin;
  return `${base}/${location.search}#pair=${token}.${me.id}`;
}

function openPairing() {
  if (pairing && pairing.expires > Date.now() + 30000) return renderPairing();
  $('#qrImg').removeAttribute('src');
  $('#code').textContent = '––– –––';
  send({ type: 'pair-open', ...profile });
}
function showPairing(m) {
  pairing = { token: m.token, code: m.code, expires: Date.now() + m.ttl * 1000 };
  renderPairing();
}
function renderPairing() {
  $('#qrImg').src = `/api/qr?d=${encodeURIComponent(pairUrl(pairing.token))}`;
  $('#code').textContent = `${pairing.code.slice(0, 3)} ${pairing.code.slice(3)}`;
}
function closePairing() {
  if (pairing) send({ type: 'pair-close', token: pairing.token });
  pairing = null;
}
setInterval(() => {
  if (!pairing || !$('#addDlg').open) return;
  const left = Math.round((pairing.expires - Date.now()) / 1000);
  if (left <= 0) { pairing = null; openPairing(); return; }
  $('#pairTtl').textContent = `Expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
}, 1000);

function readPairHash(hash) {
  const m = /#pair=([\w-]{16,64})\.([0-9a-f]{32})/.exec(hash || '');
  return m && { token: m[1], id: m[2] };
}

async function onPaired(peer) {
  const expect = pendingPair?.id;
  pendingPair = null;
  if (!peer || typeof peer.pub !== 'string' || (await idFromPub(peer.pub)) !== peer.id || (expect && expect !== peer.id)) {
    toast("Pairing failed: the other device's key didn't match.");
    return;
  }
  pairing = null;
  let c = contacts.get(peer.id);
  if (c && c.pub !== peer.pub) return toast('Pairing failed: key changed for a known device.');
  if (!c) {
    c = { id: peer.id, pub: peer.pub, addedAt: Date.now(), unread: 0 };
    contacts.set(c.id, c);
  }
  if (typeof peer.box === 'string' && peer.box && (await verify(peer.pub, `anydrop-box:${peer.box}`, String(peer.boxSig || '')))) c.box = peer.box;
  else toast("Paired, but the other device didn't send a valid encryption key. Update AnyDrop there and pair again.");
  c.name = cleanName(peer.name);
  c.device = deviceKey(peer.device);
  await saveContact(c);
  sendWatch();
  if ($('#addDlg').open) $('#addDlg').close();
  toast(`Added ${c.name}`);
  openChat(c.id);
}

// ---------- QR scanning (needs camera + BarcodeDetector: Chrome on Android over HTTPS) ----------
let scanStream = null, scanTimer = null;
async function startScan() {
  const msg = $('#scanMsg');
  if (!('BarcodeDetector' in window) || !navigator.mediaDevices?.getUserMedia) {
    msg.textContent = !window.isSecureContext
      ? "The camera needs HTTPS here. Open your phone's camera app and point it at the QR code instead: it opens AnyDrop and pairs."
      : "This browser can't scan in the app. Open your camera app and point it at the QR code instead.";
    $('#scanVideo').hidden = true;
    return;
  }
  $('#scanVideo').hidden = false;
  msg.textContent = 'Point the camera at the QR code on the other device.';
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const v = $('#scanVideo');
    v.srcObject = scanStream;
    await v.play();
    const det = new BarcodeDetector({ formats: ['qr_code'] });
    scanTimer = setInterval(async () => {
      const codes = await det.detect(v).catch(() => []);
      for (const c of codes) {
        const p = readPairHash(new URL(c.rawValue, location.href).hash);
        if (p) { stopScan(); msg.textContent = 'Pairing…'; pendingPair = p; send({ type: 'pair-join', token: p.token, ...profile }); return; }
      }
    }, 300);
  } catch {
    msg.textContent = "Couldn't open the camera. Use the code instead.";
  }
}
function stopScan() {
  clearInterval(scanTimer);
  scanStream?.getTracks().forEach((t) => t.stop());
  scanStream = null;
}

// ---------- notifications ----------
function notify(c, m) {
  if (document.visibilityState === 'visible' && m.chat === active) return;
  if (!('Notification' in window) || Notification.permission !== 'granted' || document.visibilityState === 'visible') return;
  const n = new Notification(c.name, { body: m.kind === 'file' ? `📎 ${m.file.name}` : m.text.slice(0, 200), tag: c.id, icon: 'icon.svg' });
  n.onclick = () => { window.focus(); openChat(c.id); n.close(); };
}

// ---------- UI: rendering ----------
function avatar(target, id, device, isOnline) {
  target.innerHTML = I[DEVICES[deviceKey(device)][1]];
  target.style.setProperty('--h', parseInt(id.slice(0, 4), 16) % 360);
  target.classList.toggle('online', !!isOnline);
}
const timeFmt = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' });
const dateFmt = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
const dayStart = (t) => new Date(t).setHours(0, 0, 0, 0);
function dayLabel(t) {
  const d = (dayStart(Date.now()) - dayStart(t)) / 864e5;
  return d < 1 ? 'Today' : d < 2 ? 'Yesterday' : d < 7 ? new Date(t).toLocaleDateString(undefined, { weekday: 'long' }) : dateFmt.format(t);
}
const shortTime = (t) => (dayStart(t) === dayStart(Date.now()) ? timeFmt.format(t) : dayLabel(t) === 'Yesterday' ? 'Yesterday' : new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }));
function tickIcon(status) {
  const s = el('span');
  s.innerHTML = { pending: I.clock, sent: I.tick, delivered: I.ticks, read: I.ticks }[status] || '';
  const svgEl = s.firstElementChild;
  if (svgEl) svgEl.classList.add('tick', status === 'pending' ? 'clock' : status === 'read' ? 'read' : 'x');
  return svgEl || s;
}
function fmtSize(b) {
  if (b < 1024) return `${Math.round(b)} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
  return `${b.toFixed(b < 10 ? 1 : 0)} ${u[i]}`;
}
const isTyping = (id) => (typingUntil.get(id) || 0) > Date.now();
function presence(id) {
  if (isTyping(id)) return ['typing…', 'typing'];
  if (online.has(id)) return ['online', 'on']; // text goes through the server, so no need to wait for P2P
  const seen = contacts.get(id)?.lastSeen;
  if (!seen) return ['offline', ''];
  return [`last seen ${dayStart(seen) === dayStart(Date.now()) ? 'today' : dayLabel(seen).toLowerCase()} at ${timeFmt.format(seen)}`, ''];
}

function renderConn() {
  $('#connDot').classList.toggle('on', wsUp);
  $('#connText').textContent = wsUp ? deviceLabel(profile.device) : 'Connecting…';
}
function renderMe() {
  $('#meName').textContent = profile.name;
  avatar($('#meAvatar'), me.id, profile.device, false);
  renderConn();
}

function renderChats() {
  const q = $('#search').value.trim().toLowerCase();
  const list = [...contacts.values()]
    .filter((c) => !q || c.name.toLowerCase().includes(q))
    .sort((a, b) => (b.last?.ts || b.addedAt) - (a.last?.ts || a.addedAt));
  $('#noChats').hidden = contacts.size > 0;
  $('#chats').replaceChildren(...list.map((c) => {
    const li = el('li', 'chat-item');
    li.classList.toggle('active', c.id === active);
    li.classList.toggle('unread', c.unread > 0);
    li.tabIndex = 0;
    li.setAttribute('role', 'button');
    const av = el('span', 'avatar');
    avatar(av, c.id, c.device, online.has(c.id));
    const body = el('div', 'body');
    const top = el('div', 'top');
    top.append(el('span', 'name', c.name), el('time', '', c.last ? shortTime(c.last.ts) : ''));
    const bot = el('div', 'bot');
    const pv = el('span', 'preview');
    if (isTyping(c.id)) { pv.textContent = 'typing…'; pv.classList.add('typing'); }
    else if (c.last) {
      if (c.last.dir === 'out') pv.append(tickIcon(c.last.status));
      pv.append(document.createTextNode(c.last.text));
    } else pv.textContent = deviceLabel(c.device);
    bot.append(pv);
    if (c.unread) bot.append(el('span', 'badge', c.unread > 99 ? '99+' : String(c.unread)));
    body.append(top, bot);
    li.append(av, body);
    li.onclick = () => openChat(c.id);
    li.onkeydown = (e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), openChat(c.id));
    return li;
  }));
  const total = [...contacts.values()].reduce((s, c) => s + (c.unread || 0), 0);
  document.title = total ? `(${total}) AnyDrop` : 'AnyDrop';
}

function renderHead() {
  if (!active) return;
  const c = contacts.get(active);
  if (!c) return;
  $('#peerName').textContent = c.name;
  avatar($('#peerAvatar'), c.id, c.device, online.has(c.id));
  const [txt, cls] = presence(c.id);
  const s = $('#peerStatus');
  s.textContent = txt;
  s.className = cls;
}

function renderNotice() {
  if (!active) return;
  const c = contacts.get(active);
  const n = $('#notice');
  const pending = shown.some((m) => m.dir === 'out' && m.status === 'pending');
  const files = shown.some((m) => m.dir === 'out' && m.kind === 'file' && (m.status === 'pending' || m.status === 'sent'));
  if (!canSeal(c)) n.textContent = `Pair with ${c.name} again to send messages: this pairing is from an older AnyDrop without encryption keys.`;
  else if (pending && !wsUp) n.textContent = "You're offline. Messages will go out when AnyDrop reconnects.";
  else if (files && !online.has(active)) n.textContent = `Files are sent directly, so they go when ${c.name} is online with AnyDrop open.`;
  else n.textContent = '';
  n.hidden = !n.textContent;
}

async function openChat(id) {
  if (!contacts.has(id)) return;
  active = id;
  shown = await db.chat(id);
  $('#app').classList.add('in-chat');
  $('#welcome').hidden = true;
  $('#chat').hidden = false;
  renderHead();
  renderShown(true);
  renderChats();
  renderNotice();
  markRead(id);
  if (matchMedia('(min-width: 721px)').matches) $('#input').focus();
}
function closeChat() {
  active = null;
  shown = [];
  $('#app').classList.remove('in-chat');
  $('#chat').hidden = true;
  $('#welcome').hidden = false;
  renderChats();
}

function upsertShown(m) {
  const i = shown.findIndex((x) => x.key === m.key);
  if (i >= 0) shown[i] = m;
  else shown.push(m);
  const box = $('#msgs');
  const node = box.querySelector(`[data-key="${CSS.escape(m.key)}"]`);
  if (node && i >= 0) { node.replaceWith(msgNode(m)); renderNotice(); return; }
  renderShown(m.dir === 'out' || box.scrollHeight - box.scrollTop - box.clientHeight < 120);
}

function renderShown(toBottom = false) {
  const box = $('#msgs');
  shown.sort((a, b) => a.ts - b.ts);
  const nodes = [];
  let day = null;
  for (const m of shown) {
    const d = dayStart(m.ts);
    if (d !== day) { day = d; nodes.push(el('div', 'day', dayLabel(m.ts))); }
    nodes.push(msgNode(m));
  }
  for (const [key, v] of incoming) if (key.startsWith(`${active}:`)) nodes.push(incomingNode(key, v));
  box.replaceChildren(...nodes);
  if (toBottom) box.scrollTop = box.scrollHeight;
  renderNotice();
}

function linkify(text) {
  const frag = document.createDocumentFragment();
  let last = 0;
  for (const m of text.matchAll(/\bhttps?:\/\/[^\s<>"']+/g)) {
    frag.append(text.slice(last, m.index));
    const a = el('a', '', m[0]);
    a.href = m[0]; a.target = '_blank'; a.rel = 'noopener noreferrer';
    frag.append(a);
    last = m.index + m[0].length;
  }
  frag.append(text.slice(last));
  return frag;
}

function msgNode(m) {
  const b = el('div', `msg ${m.dir}`);
  b.dataset.key = m.key;
  if (m.kind === 'file') {
    if (!urls.has(m.key) && m.blob) urls.set(m.key, URL.createObjectURL(m.blob));
    const url = urls.get(m.key);
    if (url && /^image\/(png|jpe?g|gif|webp|avif)$/.test(m.file.type)) {
      const img = el('img', 'thumb');
      img.src = url; img.alt = m.file.name; img.loading = 'lazy';
      b.append(img);
    }
    const f = el('div', 'file');
    const fi = el('span', 'fi');
    fi.innerHTML = I.file;
    const fm = el('div', 'fm');
    fm.append(el('b', '', m.file.name));
    const sent = progress.get(m.key);
    const sub = el('small', '', fmtSize(m.file.size));
    fm.append(sub);
    if (sent != null && m.file.size) {
      const p = el('div', 'prog');
      const s = el('span');
      s.style.width = `${(sent / m.file.size) * 100}%`;
      p.append(s); fm.append(p);
    }
    f.append(fi, fm);
    if (url) {
      const a = el('a', '', m.dir === 'in' ? 'Save' : 'Open');
      a.href = url; a.download = m.file.name;
      f.append(a);
    }
    b.append(f);
  } else {
    b.append(el('span', 'text'));
    b.firstChild.append(linkify(m.text));
  }
  const meta = el('span', 'meta', timeFmt.format(m.ts));
  if (m.dir === 'out') meta.append(tickIcon(m.status));
  b.append(meta);
  return b;
}

function incomingNode(key, v) {
  const b = el('div', 'msg in');
  b.dataset.key = key;
  const f = el('div', 'file');
  const fi = el('span', 'fi');
  fi.innerHTML = I.file;
  const fm = el('div', 'fm');
  fm.append(el('b', '', v.meta.name), el('small', '', `Receiving · ${fmtSize(v.meta.size)}`));
  const p = el('div', 'prog');
  const s = el('span');
  s.style.width = `${(v.got / (v.meta.size || 1)) * 100}%`;
  p.append(s); fm.append(p);
  f.append(fi, fm);
  b.append(f);
  return b;
}

function paintProgress(key, frac) {
  const node = document.querySelector(`[data-key="${CSS.escape(key)}"]`);
  if (!node) return;
  let p = node.querySelector('.prog span');
  if (!p) {
    const bar = el('div', 'prog');
    p = el('span');
    bar.append(p);
    node.querySelector('.fm')?.append(bar);
  }
  p.style.width = `${Math.min(100, frac * 100)}%`;
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3000);
}

// ---------- UI: events ----------
$('#addBtn').innerHTML = I.add;
$('#backBtn').innerHTML = I.back;
$('#attachBtn').innerHTML = I.clip;
$('#attachBtn2').innerHTML = I.file;
$('#sendBtn').innerHTML = I.send;

$('#search').oninput = renderChats;
$('#backBtn').onclick = closeChat;

const input = $('#input');
const grow = () => { input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 140)}px`; };
let lastTyping = 0;
input.oninput = () => {
  grow();
  if (active && input.value && Date.now() - lastTyping > 2500) {
    lastTyping = Date.now();
    post(active, { k: 'typing' }, { live: true });
  }
};
input.onkeydown = (e) => {
  const touch = matchMedia('(pointer: coarse)').matches;
  if (e.key === 'Enter' && !e.shiftKey && !touch && !e.isComposing) { e.preventDefault(); $('#composer').requestSubmit(); }
};
$('#composer').onsubmit = (e) => {
  e.preventDefault();
  if (!active || !input.value.trim()) return;
  sendText(active, input.value);
  input.value = '';
  lastTyping = 0;
  grow();
  input.focus();
};
input.onpaste = (e) => {
  const files = [...(e.clipboardData?.files || [])];
  if (files.length && active) { e.preventDefault(); sendFiles(active, files); }
};

const pick = () => { $('#picker').value = ''; $('#picker').click(); };
$('#attachBtn').onclick = pick;
$('#attachBtn2').onclick = pick;
$('#picker').onchange = (e) => active && sendFiles(active, [...e.target.files]);

let dragDepth = 0;
const chatEl = $('#chat');
chatEl.addEventListener('dragenter', (e) => { if (e.dataTransfer?.types.includes('Files')) { dragDepth++; $('#dropHint').hidden = false; } });
chatEl.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('#dropHint').hidden = true; } });
chatEl.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0; $('#dropHint').hidden = true;
  if (active && e.dataTransfer.files.length) sendFiles(active, [...e.dataTransfer.files]);
});
document.addEventListener('dragover', (e) => e.preventDefault());
document.addEventListener('drop', (e) => e.preventDefault());

document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && active) markRead(active); });
window.addEventListener('focus', () => active && markRead(active));
setInterval(() => { renderHead(); }, 30000);

// add-device dialog
let currentTab = 'show';
function setTab(tab) {
  currentTab = tab;
  for (const b of document.querySelectorAll('[data-tab]')) b.setAttribute('aria-selected', String(b.dataset.tab === tab));
  for (const p of document.querySelectorAll('[data-pane]')) p.hidden = p.dataset.pane !== tab;
  $('#pairErr').textContent = '';
  if (tab === 'scan') startScan(); else stopScan();
  if (tab === 'show') openPairing();
  if (tab === 'code') $('#codeIn').focus();
}
const openAdd = () => { $('#addDlg').showModal(); setTab(currentTab); };
$('#addBtn').onclick = openAdd;
$('#addBtn2').onclick = openAdd;
for (const b of document.querySelectorAll('[data-tab]')) b.onclick = () => setTab(b.dataset.tab);
$('#addClose').onclick = () => $('#addDlg').close();
$('#addDlg').addEventListener('close', () => { stopScan(); closePairing(); });
$('#joinForm').onsubmit = (e) => {
  e.preventDefault();
  $('#pairErr').textContent = '';
  const code = $('#codeIn').value.replace(/\D/g, '');
  if (code.length !== 6) { $('#pairErr').textContent = 'Enter the 6-digit code shown on the other device.'; return; }
  if (!send({ type: 'pair-join', code, ...profile })) $('#pairErr').textContent = 'Not connected to the server yet.';
  $('#codeIn').value = '';
};

// this-device dialog
$('#meDeviceIn').replaceChildren(...Object.entries(DEVICES).map(([k, [label]]) => { const o = el('option', '', label); o.value = k; return o; }));
$('#meBtn').onclick = () => {
  $('#meNameIn').value = profile.name;
  $('#meDeviceIn').value = profile.device;
  $('#meId').textContent = fingerprint(me.id);
  renderNotifBtn();
  $('#meDlg').showModal();
};
$('#meCancel').onclick = () => $('#meDlg').close();
$('#meForm').onsubmit = async () => {
  profile = { name: cleanName($('#meNameIn').value, profile.name), device: deviceKey($('#meDeviceIn').value) };
  await db.put('kv', profile, 'profile');
  renderMe();
  for (const l of links.values()) chatSend(l, { t: 'hello', ...profile });
  for (const id of contacts.keys()) post(id, { k: 'profile', ...profile });
};
function renderNotifBtn() {
  const b = $('#notifBtn');
  const p = 'Notification' in window ? Notification.permission : 'unsupported';
  b.textContent = { granted: 'On', denied: 'Blocked in browser settings', unsupported: 'Not supported here' }[p] || 'Turn on';
  b.disabled = p !== 'default';
}
$('#notifBtn').onclick = async () => { await Notification.requestPermission(); renderNotifBtn(); };

// contact dialog
$('#peerBtn').onclick = () => {
  const c = contacts.get(active);
  if (!c) return;
  avatar($('#pdAvatar'), c.id, c.device, online.has(c.id));
  $('#pdName').textContent = c.name;
  $('#pdType').textContent = `${deviceLabel(c.device)} · ${presence(c.id)[0]}`;
  $('#pdId').textContent = fingerprint(c.id);
  $('#peerDlg').showModal();
};
$('#pdClose').onclick = () => $('#peerDlg').close();
$('#pdClear').onclick = async () => {
  const c = contacts.get(active);
  if (!c || !confirm(`Clear all messages with ${c.name} on this device?`)) return;
  await db.clearChat(c.id);
  for (const [k, u] of urls) if (k.startsWith(`${c.id}:`)) { URL.revokeObjectURL(u); urls.delete(k); }
  delete c.last; c.unread = 0;
  await saveContact(c);
  $('#peerDlg').close();
  openChat(c.id);
};
$('#pdRemove').onclick = async () => {
  const c = contacts.get(active);
  if (!c || !confirm(`Remove ${c.name}? Its chat is deleted from this device, and you'll need to pair again to talk.`)) return;
  await db.clearChat(c.id);
  await db.del('contacts', c.id);
  contacts.delete(c.id);
  const l = links.get(c.id);
  if (l) dropLink(l, false);
  sendWatch();
  $('#peerDlg').close();
  closeChat();
};

$('#useHere').onclick = () => { replaced = false; $('#replaced').hidden = true; connect(); };

// ---------- start ----------
async function start() {
  if (!window.RTCPeerConnection) toast("This browser doesn't support WebRTC, so messages can't be sent.");
  pendingPair = readPairHash(location.hash);
  if (pendingPair) history.replaceState(null, '', location.pathname + location.search);
  me = await loadIdentity();
  box = await loadBoxKey(me);
  profile = (await db.get('kv', 'profile')) || null;
  if (!profile) {
    const device = detectDevice();
    profile = { name: defaultName(device), device };
    await db.put('kv', profile, 'profile');
  }
  for (const c of await db.all('contacts')) contacts.set(c.id, c);
  if (pendingPair && pendingPair.id === me.id) pendingPair = null; // scanned our own code
  try {
    const cfg = await (await fetch('/api/config')).json();
    if (cfg.iceServers) iceServers = cfg.iceServers;
    lanUrl = cfg.lanUrl || null;
  } catch {}
  renderMe();
  renderChats();
  connect();
}
start().catch((e) => { console.error(e); toast(`AnyDrop couldn't start: ${e.message}`); });
