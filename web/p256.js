// Minimal P-256 ECDSA + SHA-256 in plain JS, used only when WebCrypto is missing
// (browsers hide crypto.subtle on plain-http LAN addresses like http://192.168.1.5).
// Produces the same formats as WebCrypto: raw public key 0x04||X||Y, signature r||s.
// Not constant-time; good enough for device identity on a home network.

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const G = [
  0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  1n,
];

const mod = (a, m = P) => { const r = a % m; return r < 0n ? r + m : r; };
function inv(a, m) {
  let [x, y, u, v] = [mod(a, m), m, 1n, 0n];
  while (x !== 0n) { const q = y / x; [x, y, u, v] = [y - q * x, x, v - q * u, u]; }
  if (y !== 1n) throw new Error('not invertible');
  return mod(v, m);
}

// Jacobian coordinates; Z = 0 is the point at infinity.
function dbl([X, Y, Z]) {
  if (Z === 0n || Y === 0n) return [0n, 1n, 0n];
  const delta = mod(Z * Z), gamma = mod(Y * Y), beta = mod(X * gamma);
  const alpha = mod(3n * (X - delta) * (X + delta));
  const X3 = mod(alpha * alpha - 8n * beta);
  const Z3 = mod((Y + Z) ** 2n - gamma - delta);
  const Y3 = mod(alpha * (4n * beta - X3) - 8n * gamma * gamma);
  return [X3, Y3, Z3];
}
function add(p, q) {
  if (p[2] === 0n) return q;
  if (q[2] === 0n) return p;
  const [X1, Y1, Z1] = p, [X2, Y2, Z2] = q;
  const Z1Z1 = mod(Z1 * Z1), Z2Z2 = mod(Z2 * Z2);
  const U1 = mod(X1 * Z2Z2), U2 = mod(X2 * Z1Z1);
  const S1 = mod(Y1 * Z2 * Z2Z2), S2 = mod(Y2 * Z1 * Z1Z1);
  const H = mod(U2 - U1), r = mod(2n * (S2 - S1));
  if (H === 0n) return r === 0n ? dbl(p) : [0n, 1n, 0n];
  const I = mod(4n * H * H), J = mod(H * I), V = mod(U1 * I);
  const X3 = mod(r * r - J - 2n * V);
  const Y3 = mod(r * (V - X3) - 2n * S1 * J);
  const Z3 = mod(((Z1 + Z2) ** 2n - Z1Z1 - Z2Z2) * H);
  return [X3, Y3, Z3];
}
function mul(p, k) {
  let r = [0n, 1n, 0n];
  for (let i = BigInt(k.toString(2).length - 1); i >= 0n; i--) {
    r = dbl(r);
    if ((k >> i) & 1n) r = add(r, p);
  }
  return r;
}
function affine([X, Y, Z]) {
  if (Z === 0n) throw new Error('infinity');
  const zi = inv(Z, P), zi2 = mod(zi * zi);
  return [mod(X * zi2), mod(Y * zi2 * zi)];
}

const toBig = (bytes) => bytes.reduce((a, b) => (a << 8n) | BigInt(b), 0n);
function toBytes(n, len = 32) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
function randScalar() {
  for (;;) {
    const k = toBig(crypto.getRandomValues(new Uint8Array(32)));
    if (k > 0n && k < N) return k;
  }
}

function decodePoint(raw) {
  if (raw.length !== 65 || raw[0] !== 4) throw new Error('bad key');
  const x = toBig(raw.subarray(1, 33)), y = toBig(raw.subarray(33));
  if (x >= P || y >= P || mod(y * y - (x * x * x - 3n * x + B)) !== 0n) throw new Error('not on curve');
  return [x, y, 1n];
}

export function generate() {
  const d = randScalar();
  const [x, y] = affine(mul(G, d));
  const pub = new Uint8Array(65);
  pub[0] = 4; pub.set(toBytes(x), 1); pub.set(toBytes(y), 33);
  return { d: toBytes(d), pub };
}

export function sign(dBytes, msg) {
  const d = toBig(dBytes), e = toBig(sha256(msg));
  for (;;) {
    const k = randScalar();
    const r = mod(affine(mul(G, k))[0], N);
    if (r === 0n) continue;
    const s = mod(inv(k, N) * (e + r * d), N);
    if (s === 0n) continue;
    const out = new Uint8Array(64);
    out.set(toBytes(r), 0); out.set(toBytes(s), 32);
    return out;
  }
}

export function verify(pubRaw, msg, sig) {
  try {
    if (sig.length !== 64) return false;
    const Q = decodePoint(pubRaw);
    const r = toBig(sig.subarray(0, 32)), s = toBig(sig.subarray(32));
    if (r <= 0n || r >= N || s <= 0n || s >= N) return false;
    const w = inv(s, N), e = toBig(sha256(msg));
    const X = add(mul(G, mod(e * w, N)), mul(Q, mod(r * w, N)));
    return X[2] !== 0n && mod(affine(X)[0], N) === r;
  } catch {
    return false;
  }
}

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(msg) {
  const len = msg.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(msg);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(len / 0x20000000));
  view.setUint32(padded.length - 4, (len << 3) >>> 0);
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      [hh, g, f, e, d, c, b, a] = [g, f, e, (d + t1) >>> 0, c, b, a, (t1 + t2) >>> 0];
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i]);
  return out;
}
