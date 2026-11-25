// BER-TLV / DER parsing and encoding (ISO 7816-4 + X.690 subset).
import { concat } from './bytes.js';

/** Parse one TLV at `off`. Tags are returned as numbers (e.g. 0x5F1F, 0x7F61). */
export function readTLV(buf, off = 0) {
  if (off >= buf.length) throw new Error('TLV: out of data');
  const tagStart = off;
  let tag = buf[off++];
  const constructed = (tag & 0x20) !== 0;
  if ((tag & 0x1f) === 0x1f) {
    let b;
    do { b = buf[off++]; tag = tag * 256 + b; } while (b & 0x80);
  }
  let len = buf[off++];
  if (len === 0x80) throw new Error('TLV: indefinite length not supported');
  if (len & 0x80) {
    const n = len & 0x7f; len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off++];
  }
  if (off + len > buf.length) throw new Error(`TLV: length ${len} exceeds data (tag ${tag.toString(16)})`);
  return { tag, constructed, start: tagStart, valueStart: off, end: off + len, length: len,
    value: buf.subarray(off, off + len), raw: buf.subarray(tagStart, off + len) };
}

/** Header length + value length for a TLV whose first bytes are given (used to size files). */
export function tlvTotalLength(head) {
  const t = readTLVHeader(head);
  return t.headerLength + t.length;
}

export function readTLVHeader(buf) {
  let off = 0, tag = buf[off++];
  if ((tag & 0x1f) === 0x1f) { let b; do { b = buf[off++]; tag = tag * 256 + b; } while (b & 0x80); }
  let len = buf[off++];
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[off++]; }
  return { tag, length: len, headerLength: off };
}

export function children(tlvOrBuf) {
  const buf = tlvOrBuf.value ?? tlvOrBuf;
  const out = []; let p = 0;
  while (p < buf.length) {
    if (buf[p] === 0x00 || buf[p] === 0xff) { p++; continue; } // padding bytes between objects
    const t = readTLV(buf, p); out.push(t); p = t.end;
  }
  return out;
}

/** Map of tag → first TLV among direct children. */
export function childMap(tlvOrBuf) {
  const m = new Map();
  for (const c of children(tlvOrBuf)) if (!m.has(c.tag)) m.set(c.tag, c);
  return m;
}

/** Depth-first search for the first TLV with `tag`. */
export function find(buf, tag) {
  let p = 0;
  while (p < buf.length) {
    let t;
    try { t = readTLV(buf, p); } catch { return null; }
    if (t.tag === tag) return t;
    if (t.constructed) { const r = find(t.value, tag); if (r) return r; }
    p = t.end;
  }
  return null;
}

export function encodeLength(n) {
  if (n < 0x80) return Uint8Array.of(n);
  if (n < 0x100) return Uint8Array.of(0x81, n);
  if (n < 0x10000) return Uint8Array.of(0x82, n >> 8, n & 0xff);
  return Uint8Array.of(0x83, n >> 16, (n >> 8) & 0xff, n & 0xff);
}

export function tagBytes(tag) {
  const out = [];
  do { out.unshift(tag & 0xff); tag = Math.floor(tag / 256); } while (tag > 0);
  return Uint8Array.from(out);
}

export function tlv(tag, ...value) {
  const v = concat(...value);
  return concat(tagBytes(tag), encodeLength(v.length), v);
}

// ---- ASN.1 value helpers ----
export function decodeOID(b) {
  const parts = [];
  let v = 0;
  for (let i = 0; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      if (parts.length === 0) { const f = v < 80 ? Math.floor(v / 40) : 2; parts.push(f, v - f * 40); }
      else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

export function encodeOID(s) {
  const p = s.split('.').map(Number);
  const out = [];
  const enc = (n) => { const t = [n & 0x7f]; n = Math.floor(n / 128); while (n > 0) { t.unshift((n & 0x7f) | 0x80); n = Math.floor(n / 128); } return t; };
  out.push(...enc(p[0] * 40 + p[1]));
  for (let i = 2; i < p.length; i++) out.push(...enc(p[i]));
  return Uint8Array.from(out);
}

export function decodeIntSmall(b) { let v = 0; for (const x of b) v = v * 256 + x; return v; }
