// A software eMRTD chip (ICAO 9303) used by the in-browser simulator and the test-suite.
// Supports BAC, PACE ECDH-GM (MRZ or CAN), 3DES/AES secure messaging and READ BINARY.
import { ascii, bytesToBig, concat, equal, pad, randomBytes, xor } from '../util/bytes.js';
import { tlv, childMap, readTLV, decodeOID, children } from '../util/tlv.js';
import { tdesCbcEncrypt, tdesCbcDecrypt, retailMac } from '../crypto/des.js';
import { aesCbcEncrypt } from '../crypto/aes.js';
import { CURVES } from '../crypto/curves.js';
import { mul, add, G, encodePoint, decodePoint, randomScalar } from '../crypto/ec.js';
import { kdf, SecureMessaging } from '../icao/sm.js';
import { deriveBacKeys } from '../icao/bac.js';
import { pacePasswordKey, authToken } from '../icao/pace.js';
import { AID_EMRTD } from '../icao/card.js';

const SW = (sw, data = new Uint8Array(0)) => ({ data, sw });
const SFI_TO_FID = (sfi) => (sfi >= 1 && sfi <= 16 ? 0x0100 + sfi : 0x0100 + sfi);

export class VirtualChip {
  /**
   * @param doc {files: Map<fid, Uint8Array>, mrzInfo, can, bac:boolean, pace?:{oid, parameterId, cipher, keyBits}}
   */
  constructor(doc) {
    this.doc = doc;
    this.reset();
  }

  reset() {
    this.sm = null;
    this.selected = null;
    this.appSelected = false;
    this.challenge = null;
    this.pace = null;
  }

  async process(apdu) {
    const isSM = (apdu[0] & 0x0c) === 0x0c;
    if (isSM) {
      if (!this.sm) return this.out(SW(0x6987));
      let cmd;
      try { cmd = this.sm.unwrapCommand(apdu); } catch { this.sm = null; return this.out(SW(0x6988)); }
      const r = await this.handle(cmd);
      return this.sm ? this.sm.wrapResponse(r.data, r.sw, cmd.ins === 0xb1) : this.out(r);
    }
    if (this.sm) this.sm = null; // plain command aborts the secure channel (ICAO 9303-11 §9.8.4)
    const cmd = parsePlain(apdu);
    return this.out(await this.handle(cmd));
  }

  out(r) { return concat(r.data, [r.sw >> 8, r.sw & 0xff]); }

  async handle(c) {
    switch (c.ins) {
      case 0xa4: return this.select(c);
      case 0xb0: case 0xb1: return this.readBinary(c);
      case 0x84: return this.getChallenge(c);
      case 0x82: return this.externalAuth(c);
      case 0x22: return this.mseSetAT(c);
      case 0x86: return this.generalAuthenticate(c);
      default: return SW(0x6d00);
    }
  }

  select(c) {
    if (c.p1 === 0x04) {
      if (!equal(c.data, AID_EMRTD)) return SW(0x6a82);
      this.appSelected = true; this.selected = null;
      return SW(0x9000);
    }
    if (c.p1 === 0x02 || c.p1 === 0x00) {
      const fid = (c.data[0] << 8) | c.data[1];
      if (!this.doc.files.has(fid)) return SW(0x6a82);
      if (fid !== 0x011c && !this.sm) return SW(0x6982);
      this.selected = fid;
      return SW(0x9000);
    }
    return SW(0x6a86);
  }

  readBinary(c) {
    let offset;
    if (c.ins === 0xb1) {
      const m = childMap(c.data);
      offset = Number(bytesToBig(m.get(0x54).value));
    } else if (c.p1 & 0x80) {
      const fid = SFI_TO_FID(c.p1 & 0x1f);
      if (!this.doc.files.has(fid)) return SW(0x6a82);
      if (fid !== 0x011c && !this.sm) return SW(0x6982);
      this.selected = fid; offset = c.p2;
    } else {
      offset = (c.p1 << 8) | c.p2;
    }
    if (this.selected === null) return SW(0x6986);
    const f = this.doc.files.get(this.selected);
    if (offset >= f.length) return SW(0x6b00);
    const le = c.le ?? 256;
    const part = f.subarray(offset, Math.min(f.length, offset + le));
    const data = c.ins === 0xb1 ? tlv(0x53, part) : part;
    return SW(part.length < le ? 0x6282 : 0x9000, data);
  }

  // ---- BAC ----
  getChallenge() {
    if (!this.doc.bac) return SW(0x6d00);
    this.challenge = randomBytes(8);
    return SW(0x9000, this.challenge);
  }

  async externalAuth(c) {
    if (!this.doc.bac || !this.challenge || c.data.length !== 40) return SW(0x6985);
    const { kenc, kmac } = await deriveBacKeys(this.doc.mrzInfo);
    const e = c.data.subarray(0, 32), m = c.data.subarray(32);
    if (!equal(retailMac(kmac, pad(e, 8)), m)) return SW(0x6300);
    const S = tdesCbcDecrypt(kenc, e);
    const rndIFD = S.subarray(0, 8), rndIC = S.subarray(8, 16), kIFD = S.subarray(16, 32);
    if (!equal(rndIC, this.challenge)) return SW(0x6300);
    const kIC = randomBytes(16);
    const eIC = tdesCbcEncrypt(kenc, concat(rndIC, rndIFD, kIC));
    const resp = concat(eIC, retailMac(kmac, pad(eIC, 8)));
    const seed = xor(kIFD, kIC);
    this.sm = new SecureMessaging({ cipher: '3DES', ksEnc: await kdf(seed, 1), ksMac: await kdf(seed, 2), ssc: concat(rndIC.subarray(4), rndIFD.subarray(4)) });
    this.challenge = null;
    return SW(0x9000, resp);
  }

  // ---- PACE ----
  mseSetAT(c) {
    if (c.p1 !== 0xc1 || c.p2 !== 0xa4 || !this.doc.pace) return SW(0x6a86);
    const m = childMap(c.data);
    const oid = decodeOID(m.get(0x80).value);
    const ref = m.get(0x83).value[0];
    const pid = m.get(0x84)?.value[0];
    if (oid !== this.doc.pace.oid || pid !== this.doc.pace.parameterId) return SW(0x6a80);
    if (ref === 2 && !this.doc.can) return SW(0x6a88);
    this.pace = { step: 0, password: ref === 1 ? { type: 'MRZ', value: this.doc.mrzInfo } : { type: 'CAN', value: this.doc.can } };
    return SW(0x9000);
  }

  async generalAuthenticate(c) {
    const p = this.pace;
    if (!p) return SW(0x6985);
    const { cipher, keyBits, oid, parameterId } = this.doc.pace;
    const curve = CURVES[parameterId];
    const inner = children(readTLV(c.data, 0));
    const val = inner[0]?.value;
    const dyn = (tag, v) => SW(0x9000, tlv(0x7c, tlv(tag, v)));
    try {
      if (p.step === 0) {
        const kpi = await kdf(await pacePasswordKey(p.password), 3, cipher, keyBits);
        p.s = randomBytes(cipher === 'AES' ? 16 : 8);
        p.step = 1;
        return dyn(0x80, cipher === 'AES' ? aesCbcEncrypt(kpi, p.s) : tdesCbcEncrypt(kpi, p.s));
      }
      if (p.step === 1) {
        const termPub = decodePoint(curve, val);
        const priv = randomScalar(curve);
        const H = mul(curve, priv, termPub);
        const Gm = add(curve, mul(curve, bytesToBig(p.s), G(curve)), H);
        p.mapped = { ...curve, gx: Gm.x, gy: Gm.y };
        p.step = 2;
        return dyn(0x82, encodePoint(curve, mul(curve, priv, G(curve))));
      }
      if (p.step === 2) {
        p.termEph = decodePoint(curve, val);
        const priv = randomScalar(curve);
        p.chipEph = mul(p.mapped, priv, G(p.mapped));
        const K = encodePoint(curve, mul(p.mapped, priv, p.termEph)).subarray(1, 1 + curve.size);
        p.ksEnc = await kdf(K, 1, cipher, keyBits); p.ksMac = await kdf(K, 2, cipher, keyBits);
        p.step = 3;
        return dyn(0x84, encodePoint(curve, p.chipEph));
      }
      if (p.step === 3) {
        this.pace = null;
        if (!equal(val, authToken(cipher, p.ksMac, oid, curve, p.chipEph))) return SW(0x6300);
        const tIC = authToken(cipher, p.ksMac, oid, curve, p.termEph);
        const resp = SW(0x9000, tlv(0x7c, tlv(0x86, tIC)));
        this.sm = new SecureMessaging({ cipher, ksEnc: p.ksEnc, ksMac: p.ksMac, ssc: new Uint8Array(cipher === 'AES' ? 16 : 8) });
        return resp;
      }
    } catch {
      this.pace = null;
      return SW(0x6a80);
    }
    return SW(0x6985);
  }
}

function parsePlain(a) {
  const c = { cla: a[0], ins: a[1], p1: a[2], p2: a[3], data: new Uint8Array(0), le: undefined };
  if (a.length === 4) return c;
  if (a.length === 5) { c.le = a[4] || 256; return c; }
  if (a[4] === 0 && a.length >= 7) { // extended
    const lc = (a[5] << 8) | a[6];
    if (a.length === 7) { c.le = lc || 65536; return c; }
    c.data = a.subarray(7, 7 + lc);
    if (a.length > 7 + lc) c.le = ((a[7 + lc] << 8) | a[8 + lc]) || 65536;
    return c;
  }
  const lc = a[4];
  c.data = a.subarray(5, 5 + lc);
  if (a.length > 5 + lc) c.le = a[5 + lc] || 256;
  return c;
}

/** Build a VirtualChip from the serialisable simulator document format (base64 files). */
export function chipFromSimDoc(d, b64decode) {
  const files = new Map(Object.entries(d.files).map(([fid, b64]) => [parseInt(fid, 16), b64decode(b64)]));
  return new VirtualChip({ files, mrzInfo: d.mrzInfo, can: d.can, bac: d.bac, pace: d.pace });
}

export { ascii };
