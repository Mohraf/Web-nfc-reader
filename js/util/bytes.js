// Small byte helpers shared by every module. All binary data is Uint8Array.

export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();

export function fromHex(s) {
  const clean = s.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2) throw new Error('odd hex length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function concat(...parts) {
  const arrs = parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p)));
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

export const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
export const toAscii = (b) => String.fromCharCode(...b);
export const utf8 = (b) => new TextDecoder('utf-8', { fatal: false }).decode(b);

export function equal(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function xor(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** ISO/IEC 9797-1 padding method 2 (0x80 then zeros) to a multiple of `block`. */
export function pad(data, block) {
  const n = data.length + 1;
  const out = new Uint8Array(Math.ceil(n / block) * block);
  out.set(data);
  out[data.length] = 0x80;
  return out;
}

export function unpad(data) {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0x00) i--;
  if (i < 0 || data[i] !== 0x80) throw new Error('bad ISO 9797-1 padding');
  return data.slice(0, i);
}

export function randomBytes(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export function u32be(n) {
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

export function bigToBytes(n, len) {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  let b = fromHex(h);
  if (len !== undefined) {
    if (b.length > len) throw new Error('integer too large');
    if (b.length < len) b = concat(new Uint8Array(len - b.length), b);
  }
  return b;
}

export const bytesToBig = (b) => (b.length ? BigInt('0x' + hex(b)) : 0n);
