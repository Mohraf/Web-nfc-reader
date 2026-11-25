// Basic Access Control (ICAO 9303-11 §4.3). Establishes 3DES secure messaging from the MRZ.
import { ascii, concat, equal, pad, randomBytes, xor } from '../util/bytes.js';
import { sha1 } from '../crypto/hash.js';
import { tdesCbcEncrypt, tdesCbcDecrypt, retailMac } from '../crypto/des.js';
import { kdf, SecureMessaging } from './sm.js';
import { CardError } from './apdu.js';

export async function deriveBacKeys(mrzInfo) {
  const kseed = (await sha1(ascii(mrzInfo))).slice(0, 16);
  return { kseed, kenc: await kdf(kseed, 1), kmac: await kdf(kseed, 2) };
}

/**
 * @param card object with `transmit({cla,ins,p1,p2,data,le}) -> {data, sw}` (unprotected)
 * @param mrzInfo string from mrzKeyString()
 * @param rng optional overrides {rndIFD, kIFD} (tests)
 */
export async function performBAC(card, mrzInfo, rng = {}) {
  const { kenc, kmac } = await deriveBacKeys(mrzInfo);
  const ch = await card.transmit({ cla: 0x00, ins: 0x84, p1: 0, p2: 0, le: 8 });
  if (ch.sw !== 0x9000 || ch.data.length !== 8) throw new CardError(ch.sw, 'GET CHALLENGE');
  const rndIC = ch.data;
  const rndIFD = rng.rndIFD || randomBytes(8);
  const kIFD = rng.kIFD || randomBytes(16);
  const eIFD = tdesCbcEncrypt(kenc, concat(rndIFD, rndIC, kIFD));
  const mIFD = retailMac(kmac, pad(eIFD, 8));
  const r = await card.transmit({ cla: 0x00, ins: 0x82, p1: 0, p2: 0, data: concat(eIFD, mIFD), le: 40 });
  if (r.sw !== 0x9000) throw new CardError(r.sw, 'BAC EXTERNAL AUTHENTICATE');
  if (r.data.length !== 40) throw new Error('BAC: unexpected response length');
  const eIC = r.data.subarray(0, 32), mIC = r.data.subarray(32, 40);
  if (!equal(retailMac(kmac, pad(eIC, 8)), mIC)) throw new Error('BAC: chip MAC invalid');
  const R = tdesCbcDecrypt(kenc, eIC);
  if (!equal(R.subarray(0, 8), rndIC) || !equal(R.subarray(8, 16), rndIFD)) throw new Error('BAC: challenge mismatch');
  const kseed = xor(kIFD, R.subarray(16, 32));
  return new SecureMessaging({
    cipher: '3DES', ksEnc: await kdf(kseed, 1), ksMac: await kdf(kseed, 2),
    ssc: concat(rndIC.subarray(4, 8), rndIFD.subarray(4, 8)),
  });
}
