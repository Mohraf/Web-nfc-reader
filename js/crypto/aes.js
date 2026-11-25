// AES-128/192/256 block cipher, CBC and CMAC (for PACE + AES secure messaging).
// WebCrypto lacks raw ECB and CMAC, so this is a compact synchronous implementation.

const SBOX = new Uint8Array(256), INV = new Uint8Array(256);
(() => {
  let p = 1, q = 1;
  do {
    p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0);
    q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff; if (q & 0x80) q ^= 0x09;
    const x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
    SBOX[p] = (x ^ 0x63) & 0xff;
  } while (p !== 1);
  SBOX[0] = 0x63;
  for (let i = 0; i < 256; i++) INV[SBOX[i]] = i;
})();

const xt = (a) => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
const mul = (a, b) => { let r = 0; while (b) { if (b & 1) r ^= a; a = xt(a); b >>= 1; } return r; };

function expandKey(key) {
  const nk = key.length / 4;
  if (![4, 6, 8].includes(nk)) throw new Error('AES key must be 16, 24 or 32 bytes');
  const nr = nk + 6, w = new Uint8Array(16 * (nr + 1));
  w.set(key);
  let rcon = 1;
  for (let i = nk; i < 4 * (nr + 1); i++) {
    let t = w.slice((i - 1) * 4, i * 4);
    if (i % nk === 0) {
      t = Uint8Array.of(SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]);
      rcon = xt(rcon);
    } else if (nk > 6 && i % nk === 4) {
      t = t.map((b) => SBOX[b]);
    }
    for (let j = 0; j < 4; j++) w[i * 4 + j] = w[(i - nk) * 4 + j] ^ t[j];
  }
  return { w, nr };
}

const cache = new Map();
function ks(key) {
  const id = Array.from(key).join(',');
  let k = cache.get(id);
  if (!k) { if (cache.size > 32) cache.clear(); k = expandKey(key); cache.set(id, k); }
  return k;
}

export function aesEncryptBlock(key, block) {
  const { w, nr } = ks(key), s = Uint8Array.from(block);
  for (let i = 0; i < 16; i++) s[i] ^= w[i];
  for (let r = 1; r <= nr; r++) {
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    // ShiftRows (column-major state)
    const t = Uint8Array.from(s);
    for (let c = 0; c < 4; c++) for (let row = 1; row < 4; row++) s[c * 4 + row] = t[((c + row) % 4) * 4 + row];
    if (r !== nr) {
      for (let c = 0; c < 4; c++) {
        const a0 = s[c * 4], a1 = s[c * 4 + 1], a2 = s[c * 4 + 2], a3 = s[c * 4 + 3];
        s[c * 4] = xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3;
        s[c * 4 + 1] = a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3;
        s[c * 4 + 2] = a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3;
        s[c * 4 + 3] = xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3);
      }
    }
    for (let i = 0; i < 16; i++) s[i] ^= w[r * 16 + i];
  }
  return s;
}

export function aesDecryptBlock(key, block) {
  const { w, nr } = ks(key), s = Uint8Array.from(block);
  for (let i = 0; i < 16; i++) s[i] ^= w[nr * 16 + i];
  for (let r = nr - 1; r >= 0; r--) {
    const t = Uint8Array.from(s);
    for (let c = 0; c < 4; c++) for (let row = 1; row < 4; row++) s[((c + row) % 4) * 4 + row] = t[c * 4 + row];
    for (let i = 0; i < 16; i++) s[i] = INV[s[i]];
    for (let i = 0; i < 16; i++) s[i] ^= w[r * 16 + i];
    if (r !== 0) {
      for (let c = 0; c < 4; c++) {
        const a0 = s[c * 4], a1 = s[c * 4 + 1], a2 = s[c * 4 + 2], a3 = s[c * 4 + 3];
        s[c * 4] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
        s[c * 4 + 1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
        s[c * 4 + 2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
        s[c * 4 + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
      }
    }
  }
  return s;
}

export function aesCbcEncrypt(key, data, iv = new Uint8Array(16)) {
  if (data.length % 16) throw new Error('AES data not block aligned');
  const out = new Uint8Array(data.length); let prev = iv;
  for (let i = 0; i < data.length; i += 16) {
    const x = new Uint8Array(16);
    for (let j = 0; j < 16; j++) x[j] = data[i + j] ^ prev[j];
    prev = aesEncryptBlock(key, x); out.set(prev, i);
  }
  return out;
}

export function aesCbcDecrypt(key, data, iv = new Uint8Array(16)) {
  if (data.length % 16) throw new Error('AES data not block aligned');
  const out = new Uint8Array(data.length); let prev = iv;
  for (let i = 0; i < data.length; i += 16) {
    const c = data.subarray(i, i + 16), p = aesDecryptBlock(key, c);
    for (let j = 0; j < 16; j++) out[i + j] = p[j] ^ prev[j];
    prev = c;
  }
  return out;
}

function dbl(b) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 15; i++) out[i] = ((b[i] << 1) | (b[i + 1] >> 7)) & 0xff;
  out[15] = (b[15] << 1) & 0xff;
  if (b[0] & 0x80) out[15] ^= 0x87;
  return out;
}

/** AES-CMAC (NIST SP 800-38B / RFC 4493). Returns the full 16-byte tag. */
export function aesCmac(key, msg) {
  const L = aesEncryptBlock(key, new Uint8Array(16));
  const k1 = dbl(L), k2 = dbl(k1);
  const n = Math.max(1, Math.ceil(msg.length / 16));
  const complete = msg.length > 0 && msg.length % 16 === 0;
  const last = new Uint8Array(16);
  const tail = msg.subarray((n - 1) * 16);
  if (complete) { for (let i = 0; i < 16; i++) last[i] = tail[i] ^ k1[i]; }
  else { last.set(tail); last[tail.length] = 0x80; for (let i = 0; i < 16; i++) last[i] ^= k2[i]; }
  let x = new Uint8Array(16);
  for (let b = 0; b < n - 1; b++) {
    const y = new Uint8Array(16);
    for (let i = 0; i < 16; i++) y[i] = x[i] ^ msg[b * 16 + i];
    x = aesEncryptBlock(key, y);
  }
  for (let i = 0; i < 16; i++) last[i] ^= x[i];
  return aesEncryptBlock(key, last);
}
