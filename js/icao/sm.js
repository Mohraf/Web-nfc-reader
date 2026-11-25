// Secure Messaging (ICAO 9303-11 §9.8) for 3DES (after BAC / PACE-3DES) and AES (after PACE-AES).
// Implements both sides: terminal (wrap command / unwrap response) and chip (used by the simulator).
import { concat, pad, unpad, equal } from '../util/bytes.js';
import { tdesCbcEncrypt, tdesCbcDecrypt, retailMac, adjustParity } from '../crypto/des.js';
import { aesCbcEncrypt, aesCbcDecrypt, aesCmac, aesEncryptBlock } from '../crypto/aes.js';
import { sha1, sha256 } from '../crypto/hash.js';
import { tlv, children } from '../util/tlv.js';
import { encodeAPDU } from './apdu.js';

/** Key derivation function KDF(K, c) from ICAO 9303-11 §9.7.1. */
export async function kdf(secret, counter, cipher = '3DES', keyBits = 128) {
  const input = concat(secret, [0, 0, 0, counter]);
  if (cipher === '3DES') return adjustParity((await sha1(input)).slice(0, 16));
  if (keyBits === 128) return (await sha1(input)).slice(0, 16);
  const h = await sha256(input);
  return h.slice(0, keyBits / 8);
}

export class SMError extends Error {}

export class SecureMessaging {
  /** @param {{cipher:'3DES'|'AES', ksEnc:Uint8Array, ksMac:Uint8Array, ssc:Uint8Array}} o */
  constructor({ cipher, ksEnc, ksMac, ssc }) {
    this.cipher = cipher;
    this.ksEnc = ksEnc;
    this.ksMac = ksMac;
    this.ssc = Uint8Array.from(ssc);
    this.bs = cipher === 'AES' ? 16 : 8;
  }

  incSSC() {
    for (let i = this.ssc.length - 1; i >= 0; i--) { this.ssc[i] = (this.ssc[i] + 1) & 0xff; if (this.ssc[i] !== 0) break; }
  }

  iv() { return this.cipher === 'AES' ? aesEncryptBlock(this.ksEnc, this.ssc) : new Uint8Array(8); }

  encrypt(data) {
    const p = pad(data, this.bs);
    return this.cipher === 'AES' ? aesCbcEncrypt(this.ksEnc, p, this.iv()) : tdesCbcEncrypt(this.ksEnc, p);
  }

  decrypt(data) {
    const p = this.cipher === 'AES' ? aesCbcDecrypt(this.ksEnc, data, this.iv()) : tdesCbcDecrypt(this.ksEnc, data);
    return unpad(p);
  }

  /** MAC over pad(SSC || m), truncated to 8 bytes. */
  mac(m) {
    const n = pad(concat(this.ssc, m), this.bs);
    return this.cipher === 'AES' ? aesCmac(this.ksMac, n).slice(0, 8) : retailMac(this.ksMac, n);
  }

  // ---------- terminal side ----------
  wrapCommand({ cla, ins, p1, p2, data, le }) {
    const maskedCla = (cla & 0xf0) | 0x0c; // keep chaining bit, set SM bits
    const header = Uint8Array.of(maskedCla, ins, p1, p2);
    let doData = new Uint8Array(0), do97 = new Uint8Array(0);
    this.incSSC();
    if (data && data.length) {
      const enc = this.encrypt(data);
      doData = ins & 1 ? tlv(0x85, enc) : tlv(0x87, [0x01], enc);
    }
    if (le !== undefined) do97 = tlv(0x97, le > 256 ? [(le >> 8) & 0xff, le & 0xff] : [le === 256 ? 0 : le]);
    const cc = this.mac(concat(pad(header, this.bs), doData, do97));
    const body = concat(doData, do97, tlv(0x8e, cc));
    const extended = body.length > 255 || (le !== undefined && le > 256);
    return encodeAPDU({ cla: maskedCla, ins, p1, p2, data: body, le: extended ? 65536 : 256 });
  }

  unwrapResponse(resp) {
    const sw = (resp[resp.length - 2] << 8) | resp[resp.length - 1];
    const body = resp.subarray(0, resp.length - 2);
    this.incSSC();
    if (!body.length) throw new SMError(`Chip returned SW ${sw.toString(16).toUpperCase()} without secure messaging (session lost)`);
    let encObj = null, do99 = null, do8e = null;
    for (const t of children(body)) {
      if (t.tag === 0x87 || t.tag === 0x85) encObj = t;
      else if (t.tag === 0x99) do99 = t;
      else if (t.tag === 0x8e) do8e = t;
    }
    if (!do8e) throw new SMError('Response MAC missing');
    const m = concat(encObj ? encObj.raw : [], do99 ? do99.raw : []);
    if (!equal(this.mac(m), do8e.value)) throw new SMError('Response MAC invalid — secure channel broken');
    let data = new Uint8Array(0);
    if (encObj) data = this.decrypt(encObj.tag === 0x87 ? encObj.value.subarray(1) : encObj.value);
    const innerSW = do99 ? (do99.value[0] << 8) | do99.value[1] : sw;
    return { data, sw: innerSW };
  }

  // ---------- chip side (simulator) ----------
  unwrapCommand(apdu) {
    const [cla, ins, p1, p2] = apdu;
    let off = 4, lc = 0;
    if (apdu.length > 5 && apdu[4] === 0 && apdu.length > 7) { lc = (apdu[5] << 8) | apdu[6]; off = 7; }
    else if (apdu.length > 5) { lc = apdu[4]; off = 5; }
    const body = apdu.subarray(off, off + lc);
    this.incSSC();
    let encObj = null, do97 = null, do8e = null;
    for (const t of children(body)) {
      if (t.tag === 0x87 || t.tag === 0x85) encObj = t;
      else if (t.tag === 0x97) do97 = t;
      else if (t.tag === 0x8e) do8e = t;
    }
    if (!do8e) throw new SMError('command MAC missing');
    const m = concat(pad(Uint8Array.of(cla, ins, p1, p2), this.bs), encObj ? encObj.raw : [], do97 ? do97.raw : []);
    if (!equal(this.mac(m), do8e.value)) throw new SMError('command MAC invalid');
    const data = encObj ? this.decrypt(encObj.tag === 0x87 ? encObj.value.subarray(1) : encObj.value) : new Uint8Array(0);
    let le;
    if (do97) { le = do97.value.length === 1 ? (do97.value[0] || 256) : (((do97.value[0] << 8) | do97.value[1]) || 65536); }
    return { cla: cla & 0xf0, ins, p1, p2, data, le };
  }

  wrapResponse(data, sw, oddIns = false) {
    this.incSSC();
    const encObj = data && data.length ? (oddIns ? tlv(0x85, this.encrypt(data)) : tlv(0x87, [0x01], this.encrypt(data))) : new Uint8Array(0);
    const do99 = tlv(0x99, [sw >> 8, sw & 0xff]);
    const cc = this.mac(concat(encObj, do99));
    return concat(encObj, do99, tlv(0x8e, cc), [sw >> 8, sw & 0xff]);
  }
}
