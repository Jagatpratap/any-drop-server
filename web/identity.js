// Device identity: a P-256 key pair made on first launch and kept on this device.
// Your id is the first 16 bytes of sha256(public key), so nobody can claim it
// without your private key. No signup.
import { db } from './db.js';
import * as js from './p256.js';

const ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const SIG = { name: 'ECDSA', hash: 'SHA-256' };
const te = new TextEncoder();
const subtle = globalThis.crypto?.subtle;

export const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

const sha256 = async (bytes) => (subtle ? new Uint8Array(await subtle.digest('SHA-256', bytes)) : js.sha256(bytes));

export async function idFromPub(pubB64) {
  try { return hex((await sha256(unb64(pubB64))).slice(0, 16)); } catch { return ''; }
}

export async function loadIdentity() {
  let k = await db.get('kv', 'identity');
  if (!k) {
    if (subtle) {
      // Private key is non-extractable: page scripts can use it, not read it.
      const pair = await subtle.generateKey(ALG, false, ['sign', 'verify']);
      k = { kind: 'webcrypto', priv: pair.privateKey, pub: b64(await subtle.exportKey('raw', pair.publicKey)) };
    } else {
      const g = js.generate();
      k = { kind: 'js', d: g.d, pub: b64(g.pub) };
    }
    await db.put('kv', k, 'identity');
  }
  const sign = k.kind === 'js'
    ? async (text) => b64(js.sign(k.d, te.encode(text)))
    : async (text) => b64(await subtle.sign(SIG, k.priv, te.encode(text)));
  return { id: await idFromPub(k.pub), pub: k.pub, sign };
}

const keys = new Map();
export async function verify(pubB64, text, sigB64) {
  try {
    const msg = te.encode(text), sig = unb64(sigB64);
    if (!subtle) return js.verify(unb64(pubB64), msg, sig);
    let key = keys.get(pubB64);
    if (!key) keys.set(pubB64, (key = await subtle.importKey('raw', unb64(pubB64), ALG, false, ['verify'])));
    return await subtle.verify(SIG, key, sig, msg);
  } catch {
    return false;
  }
}

/// "a1b2 c3d4 …" - for comparing ids by eye.
export const fingerprint = (id) => id.match(/.{4}/g).join(' ');
