// PACE v2 (ICAO 9303-11 §4.4) with ECDH Generic Mapping — the modern access protocol used by
// recent ePassports and ID cards (often mandatory: many cards issued since ~2018 have no BAC).
import { ascii, bytesToBig, concat, equal, pad } from '../util/bytes.js';
import { tlv, children, childMap, readTLV, decodeOID, encodeOID, decodeIntSmall } from '../util/tlv.js';
import { sha1 } from '../crypto/hash.js';
import { CURVES } from '../crypto/curves.js';
import { mul, add, G, encodePoint, decodePoint, randomScalar } from '../crypto/ec.js';
import { tdesCbcDecrypt, retailMac } from '../crypto/des.js';
import { aesCbcDecrypt, aesCmac } from '../crypto/aes.js';
import { kdf, SecureMessaging } from './sm.js';
import { CardError } from './apdu.js';

const PACE_PREFIX = '0.4.0.127.0.7.2.2.4.';
const MAPPINGS = { 1: 'DH-GM', 2: 'ECDH-GM', 3: 'DH-IM', 4: 'ECDH-IM', 6: 'ECDH-CAM' };
const CIPHERS = { 1: ['3DES', 112], 2: ['AES', 128], 3: ['AES', 192], 4: ['AES', 256] };

export function describePaceOid(oid) {
  if (!oid.startsWith(PACE_PREFIX)) return null;
  const [m, c] = oid.slice(PACE_PREFIX.length).split('.').map(Number);
  if (!MAPPINGS[m] || !CIPHERS[c]) return null;
  return { mapping: MAPPINGS[m], cipher: CIPHERS[c][0], keyBits: CIPHERS[c][1] };
}

/** Parse EF.CardAccess (a SET OF SecurityInfo) and return the PACEInfo entries. */
export function parseCardAccess(bytes) {
  const set = readTLV(bytes, 0);
  const infos = [];
  for (const seq of children(set)) {
    const parts = children(seq);
    if (!parts.length || parts[0].tag !== 0x06) continue;
    const oid = decodeOID(parts[0].value);
    const d = describePaceOid(oid);
    if (!d) { infos.push({ oid, kind: 'other' }); continue; }
    const version = parts[1] ? decodeIntSmall(parts[1].value) : null;
    const parameterId = parts[2] && parts[2].tag === 0x02 ? decodeIntSmall(parts[2].value) : null;
    infos.push({ oid, kind: 'PACE', version, parameterId, ...d, curve: CURVES[parameterId]?.name ?? null,
      supported: d.mapping === 'ECDH-GM' && !!CURVES[parameterId] });
  }
  return infos;
}

/** Choose the strongest PACEInfo this implementation supports. */
export function choosePace(infos) {
  const ok = infos.filter((i) => i.kind === 'PACE' && i.supported);
  ok.sort((a, b) => (b.cipher === 'AES') - (a.cipher === 'AES') || b.keyBits - a.keyBits);
  return ok[0] || null;
}

const decryptNonce = (cipher, key, z) => (cipher === 'AES' ? aesCbcDecrypt(key, z) : tdesCbcDecrypt(key, z));

export function authToken(cipher, ksMac, oid, curve, point) {
  const pkdo = tlv(0x7f49, tlv(0x06, encodeOID(oid)), tlv(0x86, encodePoint(curve, point)));
  return cipher === 'AES' ? aesCmac(ksMac, pkdo).slice(0, 8) : retailMac(ksMac, pad(pkdo, 8));
}

export async function pacePasswordKey(password) {
  // MRZ: K = SHA-1(MRZ_information); CAN: K = the CAN digits as ASCII
  return password.type === 'MRZ' ? sha1(ascii(password.value)) : ascii(password.value);
}

const dyn = (tag, v) => tlv(0x7c, v ? tlv(tag, v) : new Uint8Array(0));

function dynResponse(data, tag) {
  const outer = readTLV(data, 0);
  if (outer.tag !== 0x7c) throw new Error('PACE: malformed General Authenticate response');
  const m = childMap(outer);
  if (!m.has(tag)) throw new Error('PACE: missing tag 0x' + tag.toString(16));
  return { value: m.get(tag).value, all: m };
}

/**
 * Run PACE ECDH-GM.
 * @param card `transmit({cla,ins,p1,p2,data,le})` unprotected
 * @param password {type:'MRZ'|'CAN', value:string}
 * @param info chosen PACEInfo
 * @param rng optional {mapKey, ephKey} BigInt private keys (tests)
 */
export async function performPACE(card, password, info, rng = {}, onStep = () => {}) {
  const curve = CURVES[info.parameterId];
  const { cipher, keyBits, oid } = info;
  const kpi = await kdf(await pacePasswordKey(password), 3, cipher, keyBits);

  // 1. MSE:Set AT — select protocol, password and domain parameters
  const mse = concat(tlv(0x80, encodeOID(oid)), tlv(0x83, [password.type === 'MRZ' ? 1 : 2]), tlv(0x84, [info.parameterId]));
  let r = await card.transmit({ cla: 0x00, ins: 0x22, p1: 0xc1, p2: 0xa4, data: mse });
  if (r.sw !== 0x9000) throw new CardError(r.sw, 'PACE MSE:Set AT');

  const ga = async (cla, data, step) => {
    const res = await card.transmit({ cla, ins: 0x86, p1: 0, p2: 0, data, le: 256 });
    if (res.sw !== 0x9000) throw new CardError(res.sw, `PACE General Authenticate (${step})`);
    return res.data;
  };

  // 2. Encrypted nonce
  onStep('Requesting encrypted nonce');
  const z = dynResponse(await ga(0x10, dyn(0, null), 'nonce'), 0x80).value;
  const s = bytesToBig(decryptNonce(cipher, kpi, z));

  // 3. Generic Mapping: G' = s·G + H, H = shared ECDH point
  onStep('Mapping nonce (ECDH generic mapping)');
  const mapPriv = rng.mapKey ?? randomScalar(curve);
  const mapPub = mul(curve, mapPriv, G(curve));
  const chipMapPub = decodePoint(curve, dynResponse(await ga(0x10, dyn(0x81, encodePoint(curve, mapPub)), 'map'), 0x82).value);
  const H = mul(curve, mapPriv, chipMapPub);
  if (!H) throw new Error('PACE: invalid mapping point');
  const Gm = add(curve, mul(curve, s, G(curve)), H);
  const mapped = { ...curve, gx: Gm.x, gy: Gm.y };

  // 4. Ephemeral key agreement on the mapped generator
  onStep('Ephemeral key agreement');
  const ephPriv = rng.ephKey ?? randomScalar(curve);
  const ephPub = mul(mapped, ephPriv, G(mapped));
  const chipEphPub = decodePoint(curve, dynResponse(await ga(0x10, dyn(0x83, encodePoint(curve, ephPub)), 'key agreement'), 0x84).value);
  if (chipEphPub.x === ephPub.x && chipEphPub.y === ephPub.y) throw new Error('PACE: chip echoed terminal key');
  const S = mul(mapped, ephPriv, chipEphPub);
  const Kx = encodePoint(curve, S).subarray(1, 1 + curve.size);
  const ksEnc = await kdf(Kx, 1, cipher, keyBits);
  const ksMac = await kdf(Kx, 2, cipher, keyBits);

  // 5. Mutual authentication tokens
  onStep('Exchanging authentication tokens');
  const tPCD = authToken(cipher, ksMac, oid, curve, chipEphPub);
  const resp = dynResponse(await ga(0x00, dyn(0x85, tPCD), 'mutual authentication'), 0x86);
  if (!equal(resp.value, authToken(cipher, ksMac, oid, curve, ephPub))) throw new Error('PACE: chip authentication token invalid');

  return {
    sm: new SecureMessaging({ cipher, ksEnc, ksMac, ssc: new Uint8Array(cipher === 'AES' ? 16 : 8) }),
    debug: { kpi, s, Gm, Kx, ksEnc, ksMac, tPCD },
  };
}
