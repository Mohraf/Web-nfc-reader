// Passive Authentication (ICAO 9303-11 §5.1): verify data-group hashes against EF.SOD and the
// Document Signer's signature over the SOD. Optionally check the DS certificate against a CSCA.
import { bytesToBig, concat, equal, fromHex, hex, toAscii, utf8 } from '../util/bytes.js';
import { readTLV, children, decodeOID, decodeIntSmall } from '../util/tlv.js';
import { digest } from '../crypto/hash.js';
import { curveByOid } from '../crypto/curves.js';
import { decodePoint, ecdsaVerify, modPow } from '../crypto/ec.js';

const HASH_OIDS = {
  '1.3.14.3.2.26': 'SHA-1', '2.16.840.1.101.3.4.2.4': 'SHA-224', '2.16.840.1.101.3.4.2.1': 'SHA-256',
  '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512',
};
const SIG_OIDS = {
  '1.2.840.10045.4.1': ['ECDSA', 'SHA-1'], '1.2.840.10045.4.3.1': ['ECDSA', 'SHA-224'], '1.2.840.10045.4.3.2': ['ECDSA', 'SHA-256'],
  '1.2.840.10045.4.3.3': ['ECDSA', 'SHA-384'], '1.2.840.10045.4.3.4': ['ECDSA', 'SHA-512'],
  '1.2.840.113549.1.1.5': ['RSA', 'SHA-1'], '1.2.840.113549.1.1.14': ['RSA', 'SHA-224'], '1.2.840.113549.1.1.11': ['RSA', 'SHA-256'],
  '1.2.840.113549.1.1.12': ['RSA', 'SHA-384'], '1.2.840.113549.1.1.13': ['RSA', 'SHA-512'], '1.2.840.113549.1.1.10': ['RSA-PSS', null],
  '1.2.840.113549.1.1.1': ['RSA', null],
};
const NAME_OIDS = { '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber', '2.5.4.7': 'L', '2.5.4.8': 'ST' };
const DIGEST_INFO_PREFIX = {
  'SHA-1': '3021300906052B0E03021A05000414', 'SHA-224': '302D300D06096086480165030402040500041C',
  'SHA-256': '3031300D060960864801650304020105000420', 'SHA-384': '3041300D060960864801650304020205000430',
  'SHA-512': '3051300D060960864801650304020305000440',
};

const kids = (t) => children(t.value);
const oidOf = (t) => decodeOID(t.value);

function parseName(t) {
  const parts = [];
  for (const rdn of kids(t)) for (const atv of kids(rdn)) {
    const [o, v] = kids(atv);
    parts.push([NAME_OIDS[oidOf(o)] || oidOf(o), v.tag === 0x1e ? new TextDecoder('utf-16be').decode(v.value) : utf8(v.value)]);
  }
  return { parts, text: parts.map(([k, v]) => `${k}=${v}`).join(', '), get: (k) => parts.find((p) => p[0] === k)?.[1] };
}

function parseTime(t) {
  const s = toAscii(t.value);
  const full = t.tag === 0x17 ? (+s.slice(0, 2) >= 50 ? '19' : '20') + s : s;
  return `${full.slice(0, 4)}-${full.slice(4, 6)}-${full.slice(6, 8)}`;
}

function parseSpki(spki) {
  const [alg, bits] = kids(spki);
  const [algOid, params] = kids(alg);
  const key = bits.value.subarray(1); // skip unused-bits byte
  const oid = oidOf(algOid);
  if (oid === '1.2.840.10045.2.1') {
    let curve = null;
    if (params?.tag === 0x06) curve = curveByOid(oidOf(params));
    else if (params?.tag === 0x30) curve = explicitCurve(params);
    return { type: 'EC', curve, point: curve ? decodePoint(curve, key) : null, raw: spki.raw };
  }
  if (oid === '1.2.840.113549.1.1.1' || oid === '1.2.840.113549.1.1.10') {
    const [n, e] = children(readTLV(key, 0).value);
    return { type: 'RSA', n: bytesToBig(n.value), e: bytesToBig(e.value), bits: (n.value.length - (n.value[0] === 0 ? 1 : 0)) * 8, raw: spki.raw };
  }
  return { type: oid, raw: spki.raw };
}

/** Explicit ECParameters (common in ePassport DS certificates). */
function explicitCurve(seq) {
  const [, fieldId, curveSeq, base, order] = kids(seq);
  const p = bytesToBig(kids(fieldId)[1].value);
  const [a, b] = kids(curveSeq).map((x) => bytesToBig(x.value));
  const size = Math.ceil(p.toString(16).length / 2);
  const g = base.value;
  return { name: 'explicit', size, p, a, b, gx: bytesToBig(g.subarray(1, 1 + size)), gy: bytesToBig(g.subarray(1 + size)), n: bytesToBig(order.value) };
}

export function parseCertificate(t) {
  const [tbs, sigAlg, sig] = kids(t);
  let f = kids(tbs);
  if (f[0].tag === 0xa0) f = f.slice(1);
  const [serial, , issuer, validity, subject, spki] = f;
  const [nb, na] = kids(validity);
  return {
    raw: t.raw, tbs: tbs.raw, serial: hex(serial.value), issuer: parseName(issuer), subject: parseName(subject),
    notBefore: parseTime(nb), notAfter: parseTime(na), publicKey: parseSpki(spki),
    sigAlg: parseAlg(sigAlg), signature: sig.value.subarray(1),
  };
}

function parseAlg(t) {
  const [o, params] = kids(t);
  const oid = oidOf(o);
  const [kind, hash] = SIG_OIDS[oid] || [null, HASH_OIDS[oid] || null];
  const alg = { oid, kind, hash };
  if (kind === 'RSA-PSS' && params) {
    alg.hash = 'SHA-1'; alg.saltLength = 20;
    for (const p of kids(params)) {
      if (p.tag === 0xa0) alg.hash = HASH_OIDS[oidOf(kids(kids(p)[0])[0])] || alg.hash;
      if (p.tag === 0xa2) alg.saltLength = decodeIntSmall(kids(p)[0].value);
    }
  }
  return alg;
}

async function verifySignature(pub, alg, hashAlg, data, sig) {
  const h = await digest(hashAlg, data);
  if (pub.type === 'EC') {
    if (!pub.curve) throw new Error('unknown EC curve in certificate');
    let r, s;
    if (sig[0] === 0x30) { const [rt, st] = children(readTLV(sig, 0).value); r = bytesToBig(rt.value); s = bytesToBig(st.value); }
    else { r = bytesToBig(sig.subarray(0, sig.length / 2)); s = bytesToBig(sig.subarray(sig.length / 2)); }
    return ecdsaVerify(pub.curve, pub.point, h, r, s);
  }
  if (pub.type === 'RSA') {
    const k = Math.ceil(pub.n.toString(16).length / 2);
    const m = modPow(bytesToBig(sig), pub.e, pub.n);
    let em = m.toString(16); em = em.padStart(k * 2, '0');
    if (alg.kind === 'RSA-PSS') return pssVerify(em, h, hashAlg, alg.saltLength ?? h.length, pub.n.toString(2).length - 1);
    const expected = '0001' + 'FF'.repeat(k - 3 - (DIGEST_INFO_PREFIX[hashAlg].length / 2 + h.length)) + '00' + DIGEST_INFO_PREFIX[hashAlg] + hex(h);
    return em.toUpperCase() === expected;
  }
  throw new Error('unsupported key type ' + pub.type);
}

async function pssVerify(emHex, mHash, hashAlg, sLen, emBits) {
  const em = fromHex(emHex.slice(emHex.length - Math.ceil(emBits / 8) * 2));
  const hLen = mHash.length, emLen = em.length;
  if (em[emLen - 1] !== 0xbc) return false;
  const maskedDB = em.subarray(0, emLen - hLen - 1), H = em.subarray(emLen - hLen - 1, emLen - 1);
  const mask = new Uint8Array(maskedDB.length);
  for (let c = 0, o = 0; o < mask.length; c++) {
    const d = await digest(hashAlg, concat(H, [c >>> 24, (c >>> 16) & 0xff, (c >>> 8) & 0xff, c & 0xff]));
    mask.set(d.subarray(0, Math.min(d.length, mask.length - o)), o); o += d.length;
  }
  const db = maskedDB.map((b, i) => b ^ mask[i]);
  db[0] &= 0xff >> (8 * emLen - emBits);
  const psLen = emLen - hLen - sLen - 2;
  for (let i = 0; i < psLen; i++) if (db[i] !== 0) return false;
  if (db[psLen] !== 0x01) return false;
  const salt = db.subarray(db.length - sLen);
  const h2 = await digest(hashAlg, concat(new Uint8Array(8), mHash, salt));
  return equal(h2, H);
}

export function parseSOD(sodBytes) {
  const outer = readTLV(sodBytes, 0); // tag 0x77
  const contentInfo = readTLV(outer.value, 0);
  const [, explicit] = kids(contentInfo);
  const signedData = kids(explicit)[0];
  const sd = kids(signedData);
  let i = 2;
  const encap = sd[i++];
  const [, eContentWrap] = kids(encap);
  const eContent = kids(eContentWrap)[0].value;
  const certs = [];
  if (sd[i].tag === 0xa0) { for (const c of kids(sd[i])) certs.push(parseCertificate(c)); i++; }
  if (sd[i].tag === 0xa1) i++;
  const signerInfo = kids(sd[i])[0];
  const si = kids(signerInfo);
  let j = 2;
  const digestAlg = parseAlg(si[j++]);
  let signedAttrs = null;
  if (si[j].tag === 0xa0) signedAttrs = si[j++];
  const sigAlg = parseAlg(si[j++]);
  const signature = si[j].value;

  const lso = kids(readTLV(eContent, 0));
  const hashAlg = HASH_OIDS[oidOf(kids(lso[1])[0])];
  const hashes = new Map();
  for (const dgh of kids(lso[2])) {
    const [n, h] = kids(dgh);
    hashes.set(decodeIntSmall(n.value), h.value);
  }
  return { eContent, certs, digestAlg, signedAttrs, sigAlg, signature, hashAlg, hashes };
}

/**
 * @param sodBytes EF.SOD
 * @param dgs Map<number, Uint8Array> data groups read from the chip
 * @param trustAnchors parsed CSCA certificates (optional)
 */
export async function passiveAuthentication(sodBytes, dgs, trustAnchors = []) {
  const sod = parseSOD(sodBytes);
  const result = { hashAlgorithm: sod.hashAlg, dataGroups: [], signature: null, signer: null, csca: null, errors: [] };
  for (const [n, data] of dgs) {
    const expected = sod.hashes.get(n);
    if (!expected) { result.dataGroups.push({ dg: n, ok: false, reason: 'not listed in SOD' }); continue; }
    result.dataGroups.push({ dg: n, ok: equal(await digest(sod.hashAlg, data), expected) });
  }
  const ds = sod.certs[0];
  if (ds) {
    result.signer = { subject: ds.subject.text, issuer: ds.issuer.text, country: ds.issuer.get('C') || ds.subject.get('C'),
      notBefore: ds.notBefore, notAfter: ds.notAfter, serial: ds.serial,
      key: ds.publicKey.type === 'RSA' ? `RSA ${ds.publicKey.bits}` : `EC ${ds.publicKey.curve?.name || '?'}` };
    try {
      let signedBytes = sod.eContent;
      const hashAlg = sod.sigAlg.hash || sod.digestAlg.hash;
      if (sod.signedAttrs) {
        // messageDigest attribute must equal hash(eContent); signature covers DER SET OF attributes
        let md = null;
        for (const attr of kids(sod.signedAttrs)) {
          const [o, vals] = kids(attr);
          if (oidOf(o) === '1.2.840.113549.1.9.4') md = kids(vals)[0].value;
        }
        const ok = md && equal(md, await digest(sod.digestAlg.hash, sod.eContent));
        if (!ok) throw new Error('messageDigest attribute does not match LDS security object');
        signedBytes = concat([0x31], sod.signedAttrs.raw.subarray(1));
      }
      result.signature = await verifySignature(ds.publicKey, sod.sigAlg, hashAlg, signedBytes, sod.signature);
    } catch (e) { result.signature = false; result.errors.push('SOD signature: ' + e.message); }
    // Chain to a trusted CSCA if one with a matching subject was supplied
    const anchor = trustAnchors.find((c) => c.subject.text === ds.issuer.text);
    if (anchor) {
      try {
        result.csca = { subject: anchor.subject.text, valid: await verifySignature(anchor.publicKey, ds.sigAlg, ds.sigAlg.hash || 'SHA-256', ds.tbs, ds.signature) };
      } catch (e) { result.csca = { subject: anchor.subject.text, valid: false }; result.errors.push('CSCA: ' + e.message); }
    }
  } else {
    result.errors.push('No Document Signer certificate embedded in SOD');
  }
  result.hashesOk = result.dataGroups.length > 0 && result.dataGroups.every((d) => d.ok);
  return result;
}

export function parseCertificateBytes(der) { return parseCertificate(readTLV(der, 0)); }
