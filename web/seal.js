// End-to-end sealing for messages that go through the server's mailbox.
//
// Each device has a second P-256 key pair just for this ("box key"), signed by its
// identity key so a contact can check it came from that device.
//   key  = HKDF-SHA256(ECDH(myBox, peerBox).x, salt "anydrop", info "anydrop-msg-v1")
//   box  = base64url(iv[12] || AES-256-GCM(key, iv, aad, json))
//   aad  = "<from id>><to id>:<mid>"   (so the server can't relabel or replay a box)
// Same format on Android (Kotlin, mobile/android/.../Crypto.kt). See PROTOCOL.md.
import { db } from './db.js';
import { b64, unb64 } from './identity.js';

const subtle = globalThis.crypto?.subtle;
const te = new TextEncoder(), td = new TextDecoder();
const SALT = te.encode('anydrop'), INFO = te.encode('anydrop-msg-v1');
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
let noble;
const nb = async () => (noble ||= await import('./vendor/noble.js'));

/// This device's box key: { pub, sig } plus a way to derive shared keys.
export async function loadBoxKey(identity) {
  let k = await db.get('kv', 'box');
  if (!k) {
    if (subtle) {
      const pair = await subtle.generateKey(ECDH, false, ['deriveBits']);
      k = { kind: 'webcrypto', priv: pair.privateKey, pub: b64(await subtle.exportKey('raw', pair.publicKey)) };
    } else {
      const { p256 } = await nb();
      const d = p256.utils.randomSecretKey();
      k = { kind: 'js', d, pub: b64(p256.getPublicKey(d, false)) };
    }
    k.sig = await identity.sign(`anydrop-box:${k.pub}`);
    await db.put('kv', k, 'box');
  }
  return k;
}

const cache = new Map(); // peer box pub -> Promise<{ seal, open }>

export function pairKey(mine, peerPub) {
  const ck = `${mine.pub}|${peerPub}`;
  if (!cache.has(ck)) cache.set(ck, derive(mine, peerPub).catch((e) => { cache.delete(ck); throw e; }));
  return cache.get(ck);
}

async function derive(mine, peerPub) {
  const raw = unb64(peerPub);
  if (subtle && mine.kind === 'webcrypto') {
    const peer = await subtle.importKey('raw', raw, ECDH, false, []);
    const x = await subtle.deriveBits({ name: 'ECDH', public: peer }, mine.priv, 256);
    const ikm = await subtle.importKey('raw', x, 'HKDF', false, ['deriveKey']);
    const key = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: INFO }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return {
      seal: async (iv, aad, pt) => new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, pt)),
      open: async (iv, aad, ct) => new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct)),
    };
  }
  const { p256, hkdf, sha256, gcm } = await nb();
  const x = p256.getSharedSecret(mine.d, raw, true).slice(1);
  const key = hkdf(sha256, x, SALT, INFO, 32);
  return {
    seal: async (iv, aad, pt) => gcm(key, iv, aad).encrypt(pt),
    open: async (iv, aad, ct) => gcm(key, iv, aad).decrypt(ct),
  };
}

const aadOf = (from, to, mid) => te.encode(`${from}>${to}:${mid}`);

export async function seal(mine, peerPub, from, to, mid, obj) {
  const k = await pairKey(mine, peerPub);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await k.seal(iv, aadOf(from, to, mid), te.encode(JSON.stringify(obj)));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv); out.set(ct, 12);
  return b64(out);
}

/// Returns the parsed object, or null if the box is not genuine.
export async function open(mine, peerPub, from, to, mid, box) {
  try {
    const raw = unb64(box);
    if (raw.length < 12 + 16) return null;
    const k = await pairKey(mine, peerPub);
    const pt = await k.open(raw.slice(0, 12), aadOf(from, to, mid), raw.slice(12));
    return JSON.parse(td.decode(pt));
  } catch {
    return null;
  }
}
