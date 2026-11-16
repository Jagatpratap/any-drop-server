// AnyDrop client.
//
// Text goes through the server, sealed end to end (seal.js): the server holds the
// sealed box until the other device acks it, so the sender can go offline. Receipts,
// typing and name changes travel the same way. The server can't read any of it.
// Files are "drops": the request goes sealed through the server, and only after the
// other device accepts do the bytes go device-to-device over WebRTC ("file:<id>:<i>"
// data channels). Calls use their own RTCPeerConnection. The server only passes the
// signed offers/answers/ICE.
// Ticks: clock = not on the server yet, ✓ = server has it, ✓✓ = delivered, blue = read.

import { db } from './db.js';
import { loadIdentity, verify, idFromPub, fingerprint } from './identity.js';
import { loadBoxKey, seal, open as unseal } from './seal.js';

const CHUNK = 64 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const LINK_TIMEOUT = 15000;
const MAX_TEXT = 20000;
const MAX_ITEMS = 100;           // files per drop
const MAX_DROP_JSON = 30000;     // keep a drop request well under the server's 48 KiB box limit
const RING_TIMEOUT = 45000;

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
  call: svg('<path d="M5 4h3.5l1.7 4.3-2.2 1.4a11 11 0 005.3 5.3l1.4-2.2L19 14.5V18a2 2 0 01-2 2A15 15 0 013 6a2 2 0 012-2z"/>'),
  video: svg('<rect x="2.5" y="6" width="13" height="12" rx="2"/><path d="M15.5 10.5l6-3.5v10l-6-3.5"/>'),
  videoOff: svg('<path d="M15.5 10.5l6-3.5v10l-6-3.5M2.5 8v8a2 2 0 002 2h9M7 6h6.5a2 2 0 012 2v6M3 3l18 18"/>'),
  mic: svg('<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5.5 11a6.5 6.5 0 0013 0M12 17.5V21"/>'),
  micOff: svg('<path d="M15 10V6a3 3 0 00-5.6-1.5M9 9v2a3 3 0 004.9 2.3M5.5 11a6.5 6.5 0 0010.6 5M18.5 11a6.5 6.5 0 01-.4 2.2M12 17.5V21M3 3l18 18"/>'),
  hangup: svg('<path d="M3.5 14.5l2.7-2a2 2 0 00.6-2.2l-.4-1.3a14 14 0 0111.2 0l-.4 1.3a2 2 0 00.6 2.2l2.7 2a1.5 1.5 0 002-.2l.5-.6a1.6 1.6 0 000-2.2A16 16 0 001 12.3a1.6 1.6 0 000 2.2l.5.6a1.5 1.5 0 002 .2z"/>'),
  close: svg('<path d="M6 6l12 12M18 6L6 18"/>'),
  left: svg('<path d="M15 5l-7 7 7 7"/>'),
  right: svg('<path d="M9 5l7 7-7 7"/>'),
  download: svg('<path d="M12 4v11M7 10.5l5 5 5-5M5 20h14"/>'),
  image: svg('<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.8"/><path d="M21 16l-5-5-9 9"/>'),
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
const xfers = new Map();         // drop msg key -> { dc, link, i, bytes } (the item moving now)
const urls = new Map();          // msg key or blob key -> object URL
let call = null;                 // the call in progress (only one at a time)
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
    c.last = { key: m.key, ts: m.ts, dir: m.dir, status: m.kind === 'call' ? null : m.status, text: previewOf(m) };
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
    case 'sent': if (contacts.has(m.to)) ctlSent(m.to, m.mid) || setStatus(m.to, m.mid, 'sent'); break;
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
      if (call) endCall('hangup');
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
    for (const m of msgs) {
      if (m.dir === 'out' && m.kind === 'text' && m.status === 'pending') await post(c.id, { k: 'text', text: m.text, ts: m.ts }, { mid: m.id });
      if (m.dir === 'out' && m.kind === 'drop' && m.status === 'pending' && m.state !== 'canceled') await post(c.id, { k: 'drop', ts: m.ts, items: m.items }, { mid: m.id });
      if (m.kind === 'drop' && m.ctl && !m.ctl.sent) await sendCtl(m);
    }
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
    } else if (d.k === 'drop') {
      const items = cleanItems(d.items);
      if (!items) { console.warn('dropped a bad drop request from', it.from); continue; }
      const key = keyOf(c.id, it.mid);
      if (!(await db.get('messages', key))) {
        await gotMessage({ key, id: it.mid, chat: c.id, dir: 'in', kind: 'drop', items, ts: tsOf(d.ts), status: 'delivered', state: 'asking', got: items.map(() => false) });
        if (c.autoAccept) await respondDrop(key, true);
      }
      if (!delivered.has(c.id)) delivered.set(c.id, []);
      delivered.get(c.id).push(it.mid);
    } else if (DROP_CTL[d.k] && typeof d.id === 'string') {
      await onDropCtl(c, d.k, d.id);
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
      if (call?.peer === id && !call.answered) endCall('cancel', false);
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
  link.gone = new Promise((r) => (link.kill = r)); // resolves when the link is dropped
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
  link.kill();
  if (links.get(link.peer) === link) links.delete(link.peer);
  for (const [k, x] of xfers) if (x.link === link) { xfers.delete(k); paintDrop(k); }
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
  if (typeof d.op === 'string' && typeof d.call === 'string') return onCallSignal(c, d);
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
    receiveItem(link, dc);
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
  // Accepted drops waiting for this device go now (or resume where they stopped).
  pumpDrops(link.peer);
}

// Status changes run one at a time: a "read" and an "ack" often arrive back to back
// and must not overwrite each other. Status only ever moves forward.
const RANK = { pending: 0, sent: 1, delivered: 2, read: 3 };
// Every read-modify-write of a stored message goes through this one queue.
// fn changes the message in place; returning false means "nothing changed".
let msgChain = Promise.resolve();
function mutate(key, fn) {
  const p = msgChain.then(async () => {
    const m = await db.get('messages', key);
    if (!m) return null;
    if ((await fn(m)) !== false) await saveMsg(m);
    return m;
  });
  msgChain = p.catch(console.warn);
  return p.catch((e) => (console.warn(e), null));
}
const setStatus = (chat, id, status) => mutate(keyOf(chat, id), (m) => {
  if (m.dir !== 'out' || m.kind === 'call' || !(RANK[status] > (RANK[m.status] ?? -1))) return false;
  m.status = status;
});

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

// ---------- drops: files and photo collections, sent only after the receiver accepts ----------
// The request ({k:'drop'}) goes sealed through the server; the answer comes back the same
// way. Bytes go over the P2P link, one "file:<id>:<i>" channel per item, in order.
const isImg = (mime) => /^image\/(png|jpe?g|gif|webp|avif|bmp)$/i.test(mime || '');
const blobKey = (m, i) => `${m.key}:${i}`;
const totalSize = (items) => items.reduce((s, x) => s + x.size, 0);
const DROP_CTL = { 'drop-ok': 'ok', 'drop-no': 'no', 'drop-cancel': 'cx', 'drop-done': 'done' };
const cleanFileName = (s) => String(s ?? '').replace(/[\u0000-\u001f\u007f/\\]/g, '_').trim().slice(0, 255) || 'file';

function cleanItems(items) {
  if (!Array.isArray(items) || items.length < 1 || items.length > MAX_ITEMS) return null;
  const out = [];
  for (const x of items) {
    const size = Number(x?.size);
    if (!Number.isSafeInteger(size) || size < 0) return null;
    out.push({ name: cleanFileName(x.name), size, mime: String(x.mime ?? '').slice(0, 100) });
  }
  return out;
}

function dropWhat(items) {
  const n = items.length;
  if (items.every((x) => isImg(x.mime))) return n === 1 ? '1 photo' : `${n} photos`;
  return n === 1 ? items[0].name : `${n} files`;
}
const dropTitle = (items) => `${dropWhat(items)} · ${fmtSize(totalSize(items))}`;

// A control answer has a fixed mid ("<drop id>-ok" ...), so a retransmit is deduplicated by
// the server and its "sent" confirmation tells us which drop it belongs to.
function ctlFor(id, k) {
  const mid = id.length <= 58 ? `${id}-${DROP_CTL[k]}` : uid();
  return { k, mid, sent: false };
}
const sendCtl = (m) => post(m.chat, { k: m.ctl.k, id: m.id }, { mid: m.ctl.mid });
function ctlSent(peer, mid) {
  const x = /^(.+)-(ok|no|cx|done)$/.exec(mid);
  if (!x) return false;
  mutate(keyOf(peer, x[1]), (m) => {
    if (m.kind !== 'drop' || m.ctl?.mid !== mid || m.ctl.sent) return false;
    m.ctl.sent = true;
  });
  return true;
}

async function sendFiles(peer, files) {
  files = files.filter((f) => f instanceof Blob);
  if (!files.length) return;
  if (!canSeal(contacts.get(peer))) return toast('Pair with this device again to send files (its encryption key is missing).');
  // One drop per selection; split big selections (item count, and the size of the request).
  const groups = [];
  let cur = [], len = 0;
  for (const f of files) {
    const it = { name: cleanFileName(f.name), size: f.size, mime: String(f.type || '').slice(0, 100) };
    const l = JSON.stringify(it).length + 1;
    if (cur.length && (cur.length >= MAX_ITEMS || len + l > MAX_DROP_JSON)) { groups.push(cur); cur = []; len = 0; }
    cur.push([it, f]); len += l;
  }
  if (cur.length) groups.push(cur);
  for (const g of groups) {
    const id = uid();
    const m = { key: keyOf(peer, id), id, chat: peer, dir: 'out', kind: 'drop', items: g.map((x) => x[0]), ts: Date.now(), status: 'pending', state: 'asking', okd: g.map(() => false) };
    for (let i = 0; i < g.length; i++) await db.put('blobs', g[i][1], blobKey(m, i));
    await saveMsg(m);
    post(peer, { k: 'drop', ts: m.ts, items: m.items }, { mid: id });
  }
  renderNotice();
}

// Receiver: Accept / Decline.
async function respondDrop(key, ok) {
  const m = await mutate(key, (d) => {
    if (d.kind !== 'drop' || d.dir !== 'in' || d.state !== 'asking') return false;
    d.state = ok ? 'receiving' : 'declined';
    d.ctl = ctlFor(d.id, ok ? 'drop-ok' : 'drop-no');
  });
  if (m?.ctl && !m.ctl.sent) sendCtl(m);
  if (ok && m) ensureLink(m.chat);
}

// Sender: Cancel (while asking or sending).
async function cancelDrop(key) {
  let changed = false;
  const m = await mutate(key, (d) => {
    if (d.kind !== 'drop' || d.dir !== 'out' || !['asking', 'sending'].includes(d.state)) return false;
    d.state = 'canceled';
    d.ctl = ctlFor(d.id, 'drop-cancel');
    changed = true;
  });
  if (!changed) return;
  abortXfer(key);
  sendCtl(m);
}

function abortXfer(key) {
  const x = xfers.get(key);
  if (!x) return;
  xfers.delete(key);
  try { x.dc.close(); } catch {}
  paintDrop(key);
}

async function onDropCtl(c, k, id) {
  const key = keyOf(c.id, id);
  let pump = false, stop = false;
  await mutate(key, (m) => {
    if (m.kind !== 'drop') return false;
    if (m.dir === 'out') {
      if (k === 'drop-ok' && m.state === 'asking') { m.state = 'sending'; pump = true; }
      else if (k === 'drop-no' && ['asking', 'sending'].includes(m.state)) { m.state = 'declined'; stop = true; }
      else if (k === 'drop-done' && !['done', 'declined'].includes(m.state)) { m.state = 'done'; m.okd = m.okd.map(() => true); stop = true; }
      else return false;
    } else if (k === 'drop-cancel' && ['asking', 'receiving'].includes(m.state)) { m.state = 'canceled'; stop = true; }
    else return false;
  });
  if (stop) abortXfer(key);
  if (pump) pumpDrops(c.id);
}

// Sender: transmit every accepted drop to this peer, oldest first, one item at a time.
function pumpDrops(peer) {
  const link = links.get(peer);
  if (!link?.open) { ensureLink(peer); return; }
  link.fileChain = link.fileChain.then(async () => {
    const list = (await db.chat(peer)).filter((m) => m.dir === 'out' && m.kind === 'drop' && m.state === 'sending');
    for (const m of list) if (!link.dead) await sendDrop(link, m.key);
  }).catch((e) => console.warn('drop send', e));
}

async function sendDrop(link, key) {
  let tries = 0, last = -1;
  for (;;) {
    if (link.dead) return;
    const m = await db.get('messages', key);
    if (!m || m.state !== 'sending') return;
    const i = m.okd.indexOf(false);
    if (i < 0) { await mutate(key, (d) => { if (d.state !== 'sending') return false; d.state = 'done'; }); return; }
    const blob = await db.get('blobs', blobKey(m, i));
    if (!blob || blob.size !== m.items[i].size) {
      await mutate(key, (d) => { if (d.state !== 'sending') return false; d.state = 'failed'; });
      return toast(`Couldn't send ${m.items[i].name}: the file is no longer on this device.`);
    }
    if (await sendItem(link, m, i, blob)) {
      tries = 0;
      await mutate(key, (d) => { if (d.okd[i]) return false; d.okd[i] = true; });
      continue;
    }
    if (link.dead) return; // resumes from this item on the next link
    tries = i === last ? tries + 1 : 1;
    last = i;
    if (tries >= 3) {
      // The link is fine but the receiver keeps refusing this item.
      await mutate(key, (d) => { if (d.state !== 'sending') return false; d.state = 'failed'; });
      return;
    }
    await sleep(1500);
  }
}

async function sendItem(link, m, i, blob) {
  const it = m.items[i];
  let dc;
  try { dc = link.pc.createDataChannel(`file:${m.id}:${i}`, { ordered: true }); } catch { return false; }
  dc.binaryType = 'arraybuffer';
  dc.bufferedAmountLowThreshold = 1024 * 1024;
  const x = { dc, link, i, bytes: 0 };
  xfers.set(m.key, x);
  paintDrop(m.key);
  let closed = false;
  const shut = new Promise((r) => { dc.onclose = () => { closed = true; r(false); }; });
  try {
    const opened = await Promise.race([new Promise((r) => { dc.onopen = () => r(true); }), shut, link.gone.then(() => false), sleep(10000).then(() => false)]);
    if (!opened) return false;
    const acked = new Promise((r) => { dc.onmessage = (e) => e.data === 'ok' && r(true); });
    dc.send(JSON.stringify({ drop: m.id, i, name: it.name, size: it.size, mime: it.mime }));
    for (let off = 0; off < it.size; off += CHUNK) {
      if (closed || link.dead || xfers.get(m.key) !== x) return false;
      const buf = await blob.slice(off, off + CHUNK).arrayBuffer();
      while (dc.bufferedAmount > HIGH_WATER && dc.readyState === 'open') await new Promise((r) => { dc.onbufferedamountlow = r; setTimeout(r, 250); });
      if (dc.readyState !== 'open') return false;
      dc.send(buf);
      x.bytes = off + buf.byteLength;
      paintDrop(m.key);
    }
    dc.send('end');
    // The receiver answers "ok" once it has stored the item.
    return await Promise.race([acked, shut, link.gone.then(() => false), sleep(120000).then(() => false)]);
  } catch {
    return false;
  } finally {
    if (xfers.get(m.key) === x) xfers.delete(m.key);
    try { dc.close(); } catch {}
  }
}

// Receiver: one channel per item. Refused unless the drop is accepted, the index exists
// and the header matches what the request promised. A partial item is thrown away.
function receiveItem(link, dc) {
  const peer = link.peer;
  const lab = /^file:([A-Za-z0-9_-]{1,64}):(\d{1,3})$/.exec(dc.label);
  const refuse = () => { try { dc.close(); } catch {} return false; };
  if (!lab) return refuse();
  const i = Number(lab[2]);
  let m = null, it = null, x = null, header = false, finished = false, parts = [], got = 0;
  let chain = (async () => {
    const d = await db.get('messages', keyOf(peer, lab[1]));
    if (!d || d.kind !== 'drop' || d.dir !== 'in' || d.state !== 'receiving' || i >= d.items.length) return refuse();
    m = d; it = d.items[i];
    return true;
  })();
  const frame = async (data) => {
    if (!header) {
      let h = null;
      if (typeof data === 'string') try { h = JSON.parse(data); } catch {}
      if (h?.drop !== m.id || Number(h.i) !== i || Number(h.size) !== it.size) return refuse();
      header = true;
      if (m.got[i]) { finished = true; dc.send('ok'); return false; } // already stored: just confirm
      x = { dc, link, i, bytes: 0 };
      xfers.set(m.key, x);
      paintDrop(m.key);
      return true;
    }
    if (typeof data !== 'string') {
      got += data.byteLength;
      if (got > it.size) return refuse();
      parts.push(data);
      x.bytes = got;
      paintDrop(m.key);
      return true;
    }
    if (data !== 'end') return true;
    if (got !== it.size) return refuse();
    const blob = new Blob(parts, { type: it.mime || 'application/octet-stream' });
    parts = [];
    let stored = false, all = false;
    const fresh = await mutate(m.key, async (d) => {
      if (d.state !== 'receiving') return false;
      await db.put('blobs', blob, blobKey(d, i));
      d.got[i] = true;
      stored = true;
      if (d.got.every(Boolean)) { d.state = 'done'; d.ctl = ctlFor(d.id, 'drop-done'); all = true; }
    });
    if (xfers.get(m.key) === x) xfers.delete(m.key);
    if (!stored) return refuse();
    finished = true;
    try { dc.send('ok'); } catch {}
    setTimeout(() => { try { dc.close(); } catch {} }, 500);
    if (all) sendCtl(fresh);
    return false;
  };
  dc.onmessage = (e) => {
    const data = e.data;
    chain = chain.then((go) => (go ? frame(data) : false)).catch((err) => (console.warn('file receive', err), refuse()));
  };
  dc.onclose = () => {
    parts = [];
    if (!finished && m && xfers.get(m.key) === x && x) { xfers.delete(m.key); paintDrop(m.key); }
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

function markRead(chat) {
  const c = contacts.get(chat);
  const unread = shown.filter((m) => m.chat === chat && m.dir === 'in' && m.kind !== 'call' && m.status !== 'read');
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
  const body = m.kind === 'drop' ? `${c.name} wants to send ${dropTitle(m.items)}` : m.kind === 'text' ? m.text.slice(0, 200) : previewOf(m);
  const n = new Notification(c.name, { body, tag: c.id, icon: 'icon.svg' });
  n.onclick = () => { window.focus(); openChat(c.id); n.close(); };
}

// ---------- UI: rendering ----------
function previewOf(m) {
  if (m.kind === 'file') return `📎 ${m.file.name}`;
  if (m.kind === 'drop') {
    const n = m.items.length;
    if (m.items.every((x) => isImg(x.mime))) return `📷 ${n === 1 ? 'Photo' : `${n} photos`}`;
    return `📎 ${n === 1 ? m.items[0].name : `${n} files`}`;
  }
  if (m.kind === 'call') return `${m.video ? '🎥' : '📞'} ${callLabel(m)}`;
  return String(m.text || '').slice(0, 120);
}
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
  const can = online.has(c.id) && !call && wsUp;
  $('#voiceBtn').disabled = !can;
  $('#videoBtn').disabled = !can;
}

function renderNotice() {
  if (!active) return;
  const c = contacts.get(active);
  const n = $('#notice');
  const pending = shown.some((m) => m.dir === 'out' && m.status === 'pending');
  const files = shown.some((m) => m.kind === 'drop' && busyDrop(m));
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
  if (m.kind === 'call') return callNode(m);
  const b = el('div', `msg ${m.dir}`);
  b.dataset.key = m.key;
  if (m.kind === 'drop') {
    b.classList.add('drop');
    dropBody(b, m);
  } else if (m.kind === 'file') {
    // Files from before drops existed: shown as they were, read-only.
    if (!urls.has(m.key) && m.blob) urls.set(m.key, URL.createObjectURL(m.blob));
    const url = urls.get(m.key);
    if (url && isImg(m.file.type)) {
      const img = el('img', 'thumb');
      img.src = url; img.alt = m.file.name; img.loading = 'lazy';
      b.append(img);
    }
    const f = el('div', 'file');
    const fi = el('span', 'fi');
    fi.innerHTML = I.file;
    const fm = el('div', 'fm');
    fm.append(el('b', '', m.file.name), el('small', '', fmtSize(m.file.size)));
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

// ---------- drop bubbles ----------
// Which items this device has the bytes of (the sender has all of them).
const hasItem = (m, i) => m.dir === 'out' || !!m.got?.[i];
const busyDrop = (m) => m.state === 'sending' || m.state === 'receiving';

async function itemUrl(m, i) {
  const k = blobKey(m, i);
  if (urls.has(k)) return urls.get(k);
  const blob = await db.get('blobs', k);
  if (!blob) return null;
  if (!urls.has(k)) urls.set(k, URL.createObjectURL(blob));
  return urls.get(k);
}

async function downloadItem(m, i) {
  const url = await itemUrl(m, i);
  if (!url) return toast('That file is not on this device.');
  const a = el('a');
  a.href = url; a.download = m.items[i].name;
  document.body.append(a); a.click(); a.remove();
}

function dropBody(b, m) {
  const imgs = [], files = [];
  m.items.forEach((x, i) => (isImg(x.mime) ? imgs : files).push(i));
  if (imgs.length) {
    const grid = el('div', `dgrid n${Math.min(imgs.length, 4)}`);
    imgs.slice(0, 4).forEach((i, n) => {
      const t = el('button', 'tile');
      t.type = 'button';
      t.setAttribute('aria-label', m.items[i].name);
      t.innerHTML = I.image;
      if (hasItem(m, i)) {
        itemUrl(m, i).then((url) => {
          if (!url) return;
          const img = el('img');
          img.src = url; img.alt = m.items[i].name; img.loading = 'lazy';
          t.replaceChildren(img, ...t.querySelectorAll('.more'));
        });
        t.onclick = () => openViewer(m, i);
      } else t.disabled = true;
      if (n === 3 && imgs.length > 4) t.append(el('span', 'more', `+${imgs.length - 3}`));
      grid.append(t);
    });
    b.append(grid);
  }
  if (files.length) {
    const list = el('div', 'dlist');
    for (const i of files.slice(0, 5)) {
      const x = m.items[i];
      const f = el('div', 'file');
      const fi = el('span', 'fi');
      fi.innerHTML = I.file;
      const fm = el('div', 'fm');
      fm.append(el('b', '', x.name), el('small', '', fmtSize(x.size)));
      f.append(fi, fm);
      if (hasItem(m, i)) {
        const a = el('button', 'link', m.dir === 'in' ? 'Save' : 'Open');
        a.type = 'button';
        a.onclick = () => downloadItem(m, i);
        f.append(a);
      }
      list.append(f);
    }
    if (files.length > 5) list.append(el('small', 'muted', `and ${files.length - 5} more`));
    b.append(list);
  }
  const head = el('div', 'dhead');
  head.append(el('b', 'dtitle', dropTitle(m.items)), el('small', `dstate ${m.state}`, dropLine(m)));
  b.append(head);
  if (busyDrop(m)) {
    const p = el('div', 'prog');
    const s = el('span');
    s.style.width = `${dropFrac(m) * 100}%`;
    p.append(s);
    b.append(p);
  }
  const btns = el('div', 'dbtns');
  const btn = (label, cls, fn) => { const x = el('button', `btn sm ${cls}`, label); x.type = 'button'; x.onclick = fn; btns.append(x); return x; };
  if (m.dir === 'in' && m.state === 'asking') {
    btn('Decline', 'ghost', () => respondDrop(m.key, false)).dataset.act = 'decline';
    btn('Accept', '', () => respondDrop(m.key, true)).dataset.act = 'accept';
  } else if (m.dir === 'out' && ['asking', 'sending'].includes(m.state)) {
    btn('Cancel', 'ghost', () => cancelDrop(m.key)).dataset.act = 'cancel';
  } else if (m.dir === 'in' && m.items.length > 1 && m.got?.some(Boolean)) {
    btn('Save all', 'ghost', async () => {
      for (let i = 0; i < m.items.length; i++) if (m.got[i]) { await downloadItem(m, i); await sleep(300); }
    }).dataset.act = 'saveall';
  }
  if (btns.childElementCount) b.append(btns);
}

function dropFrac(m) {
  const total = totalSize(m.items);
  const ok = m.dir === 'out' ? m.okd : m.got;
  let bytes = 0;
  m.items.forEach((x, i) => ok?.[i] && (bytes += x.size));
  const x = xfers.get(m.key);
  if (x && !ok?.[x.i]) bytes += x.bytes;
  return total ? Math.min(1, bytes / total) : ok?.every(Boolean) ? 1 : 0;
}

function dropLine(m) {
  const name = contacts.get(m.chat)?.name || 'the other device';
  const n = m.items.length;
  switch (m.state) {
    case 'asking': return m.dir === 'out' ? `Waiting for ${name} to accept` : `${name} wants to send ${n === 1 ? 'this' : 'these'}`;
    case 'sending': case 'receiving': {
      const x = xfers.get(m.key);
      const ok = m.dir === 'out' ? m.okd : m.got;
      if (!x && !linkOpen(m.chat)) return m.dir === 'out' ? `Accepted · sends when ${name} is online` : `Accepted · waiting for ${name}`;
      const at = x ? x.i + 1 : Math.min(ok.filter(Boolean).length + 1, n);
      return `${m.dir === 'out' ? 'Sending' : 'Receiving'} ${at} of ${n} · ${Math.floor(dropFrac(m) * 100)}%`;
    }
    case 'done': return m.dir === 'out' ? 'Delivered' : 'Received';
    case 'declined': return 'Declined';
    case 'canceled': return 'Canceled';
    case 'failed': return 'Failed';
  }
  return '';
}

// Progress repaints in place (at most once a frame): no thumbnail reloads.
const paintQueue = new Set();
function paintDrop(key) {
  if (!key.startsWith(`${active}:`)) return;
  if (!paintQueue.size) requestAnimationFrame(() => {
    for (const k of paintQueue) {
      const m = shown.find((x) => x.key === k);
      const node = document.querySelector(`[data-key="${CSS.escape(k)}"]`);
      if (!m || !node) continue;
      const st = node.querySelector('.dstate');
      if (st) st.textContent = dropLine(m);
      const bar = node.querySelector('.prog span');
      if (bar) bar.style.width = `${dropFrac(m) * 100}%`;
    }
    paintQueue.clear();
  });
  paintQueue.add(key);
}

// ---------- photo viewer ----------
let viewing = null; // { m, list: [item indices], at }
async function openViewer(m, i) {
  const list = m.items.map((x, j) => j).filter((j) => isImg(m.items[j].mime) && hasItem(m, j));
  viewing = { m, list, at: Math.max(0, list.indexOf(i)) };
  $('#viewer').hidden = false;
  showViewed();
}
async function showViewed() {
  if (!viewing) return;
  const { m, list, at } = viewing;
  const i = list[at];
  $('#vCount').textContent = list.length > 1 ? `${at + 1} of ${list.length}` : '';
  $('#vName').textContent = m.items[i].name;
  $('#vPrev').hidden = at === 0;
  $('#vNext').hidden = at === list.length - 1;
  const url = await itemUrl(m, i);
  if (viewing?.list[viewing.at] !== i) return;
  $('#vImg').src = url || '';
  $('#vImg').alt = m.items[i].name;
}
const stepViewer = (d) => {
  if (!viewing) return;
  const at = viewing.at + d;
  if (at < 0 || at >= viewing.list.length) return;
  viewing.at = at;
  showViewed();
};
function closeViewer() { viewing = null; $('#viewer').hidden = true; $('#vImg').removeAttribute('src'); }

// ---------- calls (voice and video): one extra RTCPeerConnection per call ----------
// call = { id, peer, video, dir, state, pc, local, remote, offer, iceIn, outIce, canIce,
//          answered, startedAt, ts, timer, muted, camOn, remoteCam }
// state: out: starting → calling → ringing → connecting → active; in: incoming → connecting → active
const fmtDur = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
function callLabel(m) {
  const kind = m.video ? 'video call' : 'voice call';
  const Kind = kind[0].toUpperCase() + kind.slice(1);
  if (m.outcome === 'answered') return `${m.dir === 'out' ? 'Outgoing' : 'Incoming'} ${kind} · ${fmtDur(m.dur || 0)}`;
  if (m.outcome === 'declined') return m.dir === 'in' ? `Declined ${kind}` : `${Kind} declined`;
  return m.dir === 'in' ? `Missed ${kind}` : `${Kind} · no answer`;
}
function callNode(m) {
  const row = el('div', `call-row${m.dir === 'in' && m.outcome === 'missed' ? ' missed' : ''}`);
  row.dataset.key = m.key;
  row.textContent = `${m.video ? '🎥' : '📞'} ${callLabel(m)} · ${timeFmt.format(m.ts)}`;
  return row;
}

function newCall(peer, id, video, dir) {
  return { id, peer, video, dir, state: dir === 'out' ? 'starting' : 'incoming', pc: null, local: null, remote: null, iceIn: [], outIce: [], canIce: false, answered: false, startedAt: 0, ts: Date.now(), muted: false, camOn: video, remoteCam: video };
}

const stopStream = (s) => s?.getTracks().forEach((t) => t.stop());
async function getMedia(video) {
  try {
    return await navigator.mediaDevices.getUserMedia({ audio: true, video: video ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' } : false });
  } catch (e) {
    if (!video) throw e;
    return navigator.mediaDevices.getUserMedia({ audio: true, video: false }); // no camera: voice only
  }
}

function setupPc(k) {
  const pc = new RTCPeerConnection({ iceServers });
  k.pc = pc;
  for (const t of k.local.getTracks()) pc.addTrack(t, k.local);
  pc.onicecandidate = (e) => {
    if (!e.candidate) return;
    const ice = e.candidate.toJSON();
    if (k.canIce) signal(k.peer, { op: 'ice', call: k.id, ice });
    else k.outIce.push(ice);
  };
  pc.ontrack = (e) => {
    k.remote = e.streams[0] || k.remote || new MediaStream();
    if (!e.streams[0]) k.remote.addTrack(e.track);
    const v = $('#remoteVideo');
    if (v.srcObject !== k.remote) { v.srcObject = k.remote; v.play().catch(() => {}); }
    e.track.onunmute = renderCall;
    renderCall();
  };
  pc.onconnectionstatechange = () => {
    if (call !== k) return;
    const st = pc.connectionState;
    if (st === 'connected') {
      clearTimeout(k.lost);
      if (!k.startedAt) { k.startedAt = Date.now(); k.state = 'active'; }
    } else if (st === 'disconnected') {
      clearTimeout(k.lost);
      k.lost = setTimeout(() => call === k && pc.connectionState !== 'connected' && endCall('hangup'), 12000);
    } else if (st === 'failed' || st === 'closed') {
      toast('Call lost');
      endCall('hangup');
      return;
    }
    renderCall();
  };
}
const flushIceIn = async (k) => { for (const ice of k.iceIn.splice(0)) await k.pc.addIceCandidate(ice).catch(() => {}); };

async function startCall(peer, video) {
  if (call || !online.has(peer) || !contacts.has(peer)) return;
  if (!navigator.mediaDevices?.getUserMedia) return toast(window.isSecureContext ? "This browser can't make calls." : 'Calls need HTTPS here.');
  const k = (call = newCall(peer, uid(), video, 'out'));
  showCall();
  try {
    k.local = await getMedia(video);
  } catch {
    if (call === k) { call = null; hideCall(); }
    return toast("Couldn't open the microphone.");
  }
  if (call !== k) return stopStream(k.local); // hung up meanwhile
  k.camOn = k.local.getVideoTracks().length > 0;
  showLocal(k);
  try {
    setupPc(k);
    await k.pc.setLocalDescription(await k.pc.createOffer());
    const sdp = { type: 'offer', sdp: k.pc.localDescription.sdp };
    const sig = await me.sign(sdpText(k.id, me.id, peer, sdp));
    if (call !== k) return;
    signal(peer, { op: 'ring', call: k.id, video, sdp, sig });
  } catch (e) {
    console.warn('call offer failed', e);
    return endCall('cancel');
  }
  // ICE only after the ring, so the other side knows the call first.
  k.canIce = true;
  for (const ice of k.outIce.splice(0)) signal(peer, { op: 'ice', call: k.id, ice });
  k.state = 'calling';
  k.timer = setTimeout(() => call === k && !k.answered && (toast('No answer'), endCall('timeout')), RING_TIMEOUT);
  renderCall();
}

async function acceptCall() {
  const k = call;
  if (!k || k.dir !== 'in' || k.state !== 'incoming') return;
  k.state = 'connecting';
  stopRing();
  clearTimeout(k.timer);
  renderCall();
  try {
    k.local = await getMedia(k.video);
  } catch {
    toast("Couldn't open the microphone.");
    return call === k && endCall('decline');
  }
  if (call !== k) return stopStream(k.local);
  k.camOn = k.local.getVideoTracks().length > 0;
  showLocal(k);
  try {
    setupPc(k);
    k.canIce = true;
    await k.pc.setRemoteDescription(k.offer);
    await flushIceIn(k);
    await k.pc.setLocalDescription(await k.pc.createAnswer());
    const sdp = { type: 'answer', sdp: k.pc.localDescription.sdp };
    const sig = await me.sign(sdpText(k.id, me.id, k.peer, sdp));
    if (call !== k) return;
    signal(k.peer, { op: 'answer', call: k.id, sdp, sig });
    k.answered = true;
    if (k.video && !k.camOn) signal(k.peer, { op: 'cam', call: k.id, on: false });
  } catch (e) {
    console.warn('call answer failed', e);
    endCall('hangup');
  }
  renderCall();
}

// Ends the call here, tells the other side (unless it told us), and writes the call log.
function endCall(why, tell = true) {
  const k = call;
  if (!k) return;
  call = null;
  if (tell) signal(k.peer, { op: 'end', call: k.id, why });
  clearTimeout(k.timer); clearTimeout(k.lost);
  stopRing();
  stopStream(k.local);
  try { k.pc?.close(); } catch {}
  hideCall();
  renderHead();
  const outcome = k.answered ? 'answered' : why === 'decline' ? 'declined' : 'missed';
  logCall(k, outcome);
}

async function logCall(k, outcome) {
  const id = `call-${k.id}`;
  const m = { key: keyOf(k.peer, id), id, chat: k.peer, dir: k.dir, kind: 'call', video: !!k.video, outcome, dur: k.startedAt ? Math.round((Date.now() - k.startedAt) / 1000) : 0, ts: k.ts, status: 'read' };
  if (await db.get('messages', m.key)) return;
  if (m.dir === 'in' && outcome === 'missed') await gotMessage(m);
  else await saveMsg(m);
}

async function onCallSignal(c, d) {
  const from = c.id;
  if (d.op === 'ring') {
    if (d.sdp?.type !== 'offer' || typeof d.sdp.sdp !== 'string' || !(await verify(c.pub, sdpText(d.call, from, me.id, d.sdp), String(d.sig || '')))) {
      console.warn('dropped unsigned or forged call offer from', from);
      return;
    }
    if (call) {
      if (call.id === d.call) return;
      // Both called each other at once: the lower id's call wins.
      if (call.peer === from && call.dir === 'out' && !call.answered && me.id > from) endCall('cancel');
      else if (call.peer === from && call.dir === 'out' && !call.answered) return;
      else {
        signal(from, { op: 'end', call: d.call, why: 'busy' });
        logCall({ id: d.call, peer: from, video: !!d.video, dir: 'in', ts: Date.now() }, 'missed');
        return;
      }
    }
    const k = (call = newCall(from, d.call, !!d.video, 'in'));
    k.offer = { type: 'offer', sdp: d.sdp.sdp };
    k.timer = setTimeout(() => call === k && k.state === 'incoming' && endCall('timeout', false), RING_TIMEOUT + 15000);
    signal(from, { op: 'ringing', call: k.id });
    startRing(true);
    showCall();
    if ('Notification' in window && Notification.permission === 'granted' && document.visibilityState !== 'visible') {
      const n = new Notification(c.name, { body: `Incoming ${k.video ? 'video' : 'voice'} call`, tag: `call-${k.id}`, icon: 'icon.svg' });
      n.onclick = () => { window.focus(); n.close(); };
    }
    return;
  }
  const k = call;
  if (!k || k.id !== d.call || k.peer !== from) return;
  switch (d.op) {
    case 'ringing':
      if (k.dir === 'out' && k.state === 'calling') { k.state = 'ringing'; startRing(false); renderCall(); }
      break;
    case 'answer':
      if (k.dir !== 'out' || k.answered || d.sdp?.type !== 'answer' || typeof d.sdp.sdp !== 'string') return;
      if (!(await verify(c.pub, sdpText(k.id, from, me.id, d.sdp), String(d.sig || '')))) {
        console.warn('dropped unsigned or forged call answer from', from);
        return;
      }
      if (call !== k || k.pc?.signalingState !== 'have-local-offer') return;
      k.answered = true;
      k.state = 'connecting';
      clearTimeout(k.timer);
      stopRing();
      await k.pc.setRemoteDescription({ type: 'answer', sdp: d.sdp.sdp });
      await flushIceIn(k);
      renderCall();
      break;
    case 'ice':
      if (!d.ice || typeof d.ice !== 'object') return;
      if (k.pc?.remoteDescription) await k.pc.addIceCandidate(d.ice).catch(() => {});
      else if (k.iceIn.length < 200) k.iceIn.push(d.ice); // before the pc / remote description exists
      break;
    case 'cam':
      k.remoteCam = d.on !== false;
      renderCall();
      break;
    case 'end':
      if (d.why === 'busy') toast(`${c.name} is on another call`);
      else if (d.why === 'decline' && k.dir === 'out') toast(`${c.name} declined`);
      endCall(['hangup', 'decline', 'busy', 'cancel', 'timeout'].includes(d.why) ? d.why : 'hangup', false);
      break;
  }
}

// Ring tones with WebAudio: incoming = two-tone ring, outgoing = soft ringback.
let ringer = null;
function startRing(incoming) {
  stopRing();
  try {
    const ac = new AudioContext();
    const beep = () => {
      const t0 = ac.currentTime;
      const tones = incoming ? [[880, 0], [660, 0.25], [880, 0.5], [660, 0.75]] : [[440, 0], [440, 0.45]];
      for (const [f, at] of tones) {
        const o = ac.createOscillator(), g = ac.createGain();
        o.frequency.value = f;
        g.gain.setValueAtTime(0, t0 + at);
        g.gain.linearRampToValueAtTime(incoming ? 0.2 : 0.06, t0 + at + 0.02);
        g.gain.linearRampToValueAtTime(0, t0 + at + (incoming ? 0.22 : 0.4));
        o.connect(g).connect(ac.destination);
        o.start(t0 + at); o.stop(t0 + at + 0.45);
      }
    };
    beep();
    ringer = { ac, t: setInterval(beep, incoming ? 2500 : 3500) };
  } catch {}
}
function stopRing() {
  if (!ringer) return;
  clearInterval(ringer.t);
  ringer.ac.close().catch(() => {});
  ringer = null;
}

// ---------- call screen ----------
let callTick = null;
function showCall() {
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
  closeViewer();
  $('#call').hidden = false;
  clearInterval(callTick);
  callTick = setInterval(renderCall, 1000);
  renderCall();
  renderHead();
}
function hideCall() {
  clearInterval(callTick);
  $('#call').hidden = true;
  $('#call').dataset.state = '';
  for (const v of [$('#remoteVideo'), $('#localVideo')]) { v.srcObject = null; }
}
function showLocal(k) {
  const v = $('#localVideo');
  v.srcObject = k.local.getVideoTracks().length ? k.local : null;
  if (v.srcObject) v.play().catch(() => {});
  renderCall();
}
function renderCall() {
  const k = call;
  if (!k) return;
  const c = contacts.get(k.peer);
  const box = $('#call');
  box.dataset.state = k.pc?.connectionState === 'connected' ? 'connected' : k.state;
  box.classList.toggle('video', k.video);
  $('#callName').textContent = c?.name || 'Device';
  avatar($('#callAvatar'), k.peer, c?.device, false);
  const kind = k.video ? 'Video call' : 'Voice call';
  $('#callStatus').textContent = k.startedAt ? fmtDur(Math.floor((Date.now() - k.startedAt) / 1000))
    : { starting: 'Starting…', calling: 'Calling…', ringing: 'Ringing…', incoming: 'Incoming', connecting: 'Connecting…' }[k.state] || '';
  $('#callKind').textContent = kind;
  const remoteVid = k.video && k.remoteCam && k.remote?.getVideoTracks().some((t) => t.readyState === 'live' && !t.muted);
  $('#remoteVideo').classList.toggle('on', !!remoteVid);
  box.classList.toggle('has-remote', !!remoteVid);
  $('#localVideo').hidden = !(k.local?.getVideoTracks().length && k.camOn);
  $('#callIncoming').hidden = k.state !== 'incoming';
  $('#callControls').hidden = k.state === 'incoming';
  $('#muteBtn').innerHTML = k.muted ? I.micOff : I.mic;
  $('#muteBtn').classList.toggle('off', k.muted);
  $('#muteBtn').setAttribute('aria-label', k.muted ? 'Unmute' : 'Mute');
  $('#camBtn').parentElement.hidden = !k.video || !k.local?.getVideoTracks().length;
  $('#camBtn').innerHTML = k.camOn ? I.video : I.videoOff;
  $('#camBtn').classList.toggle('off', !k.camOn);
  $('#camBtn').setAttribute('aria-label', k.camOn ? 'Turn camera off' : 'Turn camera on');
}
function hangUp() {
  if (!call) return;
  if (call.dir === 'in' && call.state === 'incoming') endCall('decline');
  else endCall(call.dir === 'out' && !call.answered ? 'cancel' : 'hangup');
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
$('#voiceBtn').innerHTML = I.call;
$('#videoBtn').innerHTML = I.video;
$('#acceptCall').innerHTML = I.call;
$('#declineCall').innerHTML = I.hangup;
$('#hangBtn').innerHTML = I.hangup;
$('#vPrev').innerHTML = I.left;
$('#vNext').innerHTML = I.right;
$('#vClose').innerHTML = I.close;
$('#vSave').innerHTML = I.download;

// calls
$('#voiceBtn').onclick = () => active && startCall(active, false);
$('#videoBtn').onclick = () => active && startCall(active, true);
$('#acceptCall').onclick = acceptCall;
$('#declineCall').onclick = hangUp;
$('#hangBtn').onclick = hangUp;
$('#muteBtn').onclick = () => {
  if (!call?.local) return;
  call.muted = !call.muted;
  for (const t of call.local.getAudioTracks()) t.enabled = !call.muted;
  renderCall();
};
$('#camBtn').onclick = () => {
  if (!call?.local) return;
  call.camOn = !call.camOn;
  for (const t of call.local.getVideoTracks()) t.enabled = call.camOn;
  if (call.answered || call.dir === 'out') signal(call.peer, { op: 'cam', call: call.id, on: call.camOn });
  renderCall();
};
window.addEventListener('pagehide', () => call && endCall(call.dir === 'out' && !call.answered ? 'cancel' : call.state === 'incoming' ? 'decline' : 'hangup'));

// photo viewer
$('#vPrev').onclick = () => stepViewer(-1);
$('#vNext').onclick = () => stepViewer(1);
$('#vClose').onclick = closeViewer;
$('#vSave').onclick = () => viewing && downloadItem(viewing.m, viewing.list[viewing.at]);
$('#viewer').onclick = (e) => e.target === e.currentTarget && closeViewer();
document.addEventListener('keydown', (e) => {
  if ($('#viewer').hidden) return;
  if (e.key === 'Escape') closeViewer();
  else if (e.key === 'ArrowLeft') stepViewer(-1);
  else if (e.key === 'ArrowRight') stepViewer(1);
});

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
  $('#pdAuto').checked = !!c.autoAccept;
  $('#peerDlg').showModal();
};
$('#pdClose').onclick = () => $('#peerDlg').close();
$('#pdAuto').onchange = (e) => {
  const c = contacts.get(active);
  if (!c) return;
  c.autoAccept = e.target.checked;
  saveContact(c);
};
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
  if (call?.peer === c.id) endCall('hangup');
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
