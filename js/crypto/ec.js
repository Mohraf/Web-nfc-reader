// Prime-field elliptic-curve arithmetic with BigInt.
// Used for PACE Generic Mapping (needs a custom generator, which WebCrypto cannot do)
// and for ECDSA verification of Document Signer signatures (incl. brainpool curves).
import { bigToBytes, bytesToBig, concat, randomBytes } from '../util/bytes.js';

export const mod = (a, m) => { const r = a % m; return r < 0n ? r + m : r; };

export function modInv(a, m) {
  let [r0, r1] = [mod(a, m), m], [s0, s1] = [1n, 0n];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}

export function modPow(b, e, m) {
  let r = 1n; b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}

// Jacobian coordinates internally; null represents the point at infinity.
function toJ(P) { return P ? [P.x, P.y, 1n] : null; }
function fromJ(c, J) {
  if (!J || J[2] === 0n) return null;
  const zi = modInv(J[2], c.p), zi2 = (zi * zi) % c.p;
  return { x: (J[0] * zi2) % c.p, y: (J[1] * zi2 * zi) % c.p };
}
function jDouble(c, J) {
  if (!J || J[1] === 0n) return null;
  const { p, a } = c; const [X, Y, Z] = J;
  const YY = (Y * Y) % p, S = (4n * X * YY) % p, ZZ = (Z * Z) % p;
  const M = mod(3n * X * X + a * ZZ * ZZ, p);
  const X3 = mod(M * M - 2n * S, p);
  const Y3 = mod(M * (S - X3) - 8n * YY * YY, p);
  return [X3, Y3, (2n * Y * Z) % p];
}
function jAdd(c, A, B) {
  if (!A) return B; if (!B) return A;
  const { p } = c;
  const Z1Z1 = (A[2] * A[2]) % p, Z2Z2 = (B[2] * B[2]) % p;
  const U1 = (A[0] * Z2Z2) % p, U2 = (B[0] * Z1Z1) % p;
  const S1 = (A[1] * B[2] * Z2Z2) % p, S2 = (B[1] * A[2] * Z1Z1) % p;
  if (U1 === U2) return S1 === S2 ? jDouble(c, A) : null;
  const H = mod(U2 - U1, p), R = mod(S2 - S1, p);
  const HH = (H * H) % p, HHH = (H * HH) % p, V = (U1 * HH) % p;
  const X3 = mod(R * R - HHH - 2n * V, p);
  const Y3 = mod(R * (V - X3) - S1 * HHH, p);
  return [X3, Y3, (A[2] * B[2] * H) % p];
}

export function add(c, P, Q) { return fromJ(c, jAdd(c, toJ(P), toJ(Q))); }

export function mul(c, k, P) {
  k = mod(k, c.n);
  let R = null, A = toJ(P);
  while (k > 0n) { if (k & 1n) R = jAdd(c, R, A); A = jDouble(c, A); k >>= 1n; }
  return fromJ(c, R);
}

export const G = (c) => ({ x: c.gx, y: c.gy });

export function onCurve(c, P) {
  if (!P) return false;
  return mod(P.y * P.y - (P.x * P.x * P.x + c.a * P.x + c.b), c.p) === 0n;
}

export function encodePoint(c, P) {
  return concat([0x04], bigToBytes(P.x, c.size), bigToBytes(P.y, c.size));
}

export function decodePoint(c, b) {
  if (b[0] !== 0x04 || b.length !== 1 + 2 * c.size) throw new Error('only uncompressed points supported');
  const P = { x: bytesToBig(b.subarray(1, 1 + c.size)), y: bytesToBig(b.subarray(1 + c.size)) };
  if (!onCurve(c, P)) throw new Error('point not on curve');
  return P;
}

export function randomScalar(c) {
  const len = Math.ceil(c.n.toString(16).length / 2) + 8;
  return mod(bytesToBig(randomBytes(len)), c.n - 1n) + 1n;
}

/** ECDSA verification. `hash` is the message digest, r/s BigInts. */
export function ecdsaVerify(c, Q, hash, r, s) {
  if (r <= 0n || r >= c.n || s <= 0n || s >= c.n) return false;
  const nBits = c.n.toString(2).length;
  let e = bytesToBig(hash);
  const hBits = hash.length * 8;
  if (hBits > nBits) e >>= BigInt(hBits - nBits);
  const w = modInv(s, c.n);
  const R = add(c, mul(c, (e * w) % c.n, G(c)), mul(c, (r * w) % c.n, Q));
  return !!R && mod(R.x, c.n) === r;
}
