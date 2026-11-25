import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { tdesCbcEncrypt, tdesCbcDecrypt, retailMac } from '../js/crypto/des.js';
import { aesCbcEncrypt, aesCbcDecrypt, aesCmac, aesEncryptBlock } from '../js/crypto/aes.js';
import { digest } from '../js/crypto/hash.js';
import { CURVES } from '../js/crypto/curves.js';
import { mul, G, onCurve, encodePoint, decodePoint, ecdsaVerify } from '../js/crypto/ec.js';
import { hex, fromHex, bytesToBig, pad } from '../js/util/bytes.js';

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));

test('3DES CBC matches OpenSSL (2-key and 3-key)', () => {
  for (const kl of [16, 24]) {
    for (let t = 0; t < 5; t++) {
      const key = rnd(kl), iv = rnd(8), data = rnd(8 * (1 + t));
      const k24 = kl === 16 ? Buffer.concat([key, key.subarray(0, 8)]) : key;
      const c = crypto.createCipheriv('des-ede3-cbc', k24, iv).setAutoPadding(false);
      const ref = Buffer.concat([c.update(data), c.final()]);
      assert.equal(hex(tdesCbcEncrypt(key, data, iv)), hex(ref));
      assert.equal(hex(tdesCbcDecrypt(key, ref, iv)), hex(data));
    }
  }
});

test('AES block/CBC matches OpenSSL for 128/192/256', () => {
  for (const kl of [16, 24, 32]) {
    const key = rnd(kl), iv = rnd(16), data = rnd(48);
    const c = crypto.createCipheriv(`aes-${kl * 8}-cbc`, key, iv).setAutoPadding(false);
    const ref = Buffer.concat([c.update(data), c.final()]);
    assert.equal(hex(aesCbcEncrypt(key, data, iv)), hex(ref));
    assert.equal(hex(aesCbcDecrypt(key, ref, iv)), hex(data));
  }
});

test('AES-CMAC RFC 4493 vectors', () => {
  const key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
  assert.equal(hex(aesCmac(key, new Uint8Array(0))), 'BB1D6929E95937287FA37D129B756746');
  assert.equal(hex(aesCmac(key, fromHex('6bc1bee22e409f96e93d7e117393172a'))), '070A16B46B4D4144F79BDD9DD04A287C');
  assert.equal(hex(aesCmac(key, fromHex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'))), 'DFA66747DE9AE63030CA32611497C827');
  assert.equal(hex(aesEncryptBlock(key, fromHex('6bc1bee22e409f96e93d7e117393172a'))), '3AD77BB40D7A3660A89ECAF32466EF97');
});

test('Retail MAC equals 3DES-CBC-MAC construction', () => {
  // ISO 9797-1 alg 3 == DES-CBC with K1 over all blocks, then D(K2), E(K1) on last
  const key = rnd(16), data = pad(rnd(20), 8);
  const k1 = key.subarray(0, 8);
  const c = crypto.createCipheriv('des-ede3-cbc', Buffer.concat([k1, k1, k1]), Buffer.alloc(8)).setAutoPadding(false);
  const cbc = Buffer.concat([c.update(data), c.final()]);
  const h = cbc.subarray(cbc.length - 8);
  const d = crypto.createDecipheriv('des-ede3-ecb', Buffer.concat([key.subarray(8), key.subarray(8), key.subarray(8)]), null).setAutoPadding(false);
  const h2 = Buffer.concat([d.update(h), d.final()]);
  const e = crypto.createCipheriv('des-ede3-ecb', Buffer.concat([k1, k1, k1]), null).setAutoPadding(false);
  const ref = Buffer.concat([e.update(h2), e.final()]);
  assert.equal(hex(retailMac(key, data)), hex(ref));
});

test('SHA family incl. SHA-224', async () => {
  const d = rnd(100);
  for (const [a, n] of [['SHA-1', 'sha1'], ['SHA-224', 'sha224'], ['SHA-256', 'sha256'], ['SHA-384', 'sha384'], ['SHA-512', 'sha512']]) {
    assert.equal(hex(await digest(a, d)), crypto.createHash(n).update(d).digest('hex').toUpperCase());
  }
});

test('all PACE curves: generator on curve, order correct, ECDH matches OpenSSL', () => {
  const osslName = { 'NIST P-192': 'prime192v1', 'NIST P-224': 'secp224r1', 'NIST P-256': 'prime256v1', 'NIST P-384': 'secp384r1', 'NIST P-521': 'secp521r1' };
  for (const c of Object.values(CURVES)) {
    assert.ok(onCurve(c, G(c)), c.name);
    assert.equal(mul(c, c.n - 1n, G(c)).x, c.gx, c.name + ' (n-1)G');
    const name = osslName[c.name] || c.name;
    const a = crypto.createECDH(name); a.generateKeys();
    const b = crypto.createECDH(name); b.generateKeys();
    const ref = a.computeSecret(b.getPublicKey());
    const Q = decodePoint(c, new Uint8Array(b.getPublicKey()));
    const S = mul(c, bytesToBig(new Uint8Array(a.getPrivateKey())), Q);
    assert.equal(hex(encodePoint(c, S)).slice(2, 2 + c.size * 2), hex(ref), c.name);
  }
});

test('ECDSA verify against OpenSSL signature (brainpoolP256r1)', () => {
  const c = Object.values(CURVES).find((x) => x.name === 'brainpoolP256r1');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'brainpoolP256r1' });
  const msg = Buffer.from('hello');
  const sig = crypto.sign('sha256', msg, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  const raw = publicKey.export({ format: 'der', type: 'spki' });
  const Q = decodePoint(c, new Uint8Array(raw.subarray(raw.length - 65)));
  const h = new Uint8Array(crypto.createHash('sha256').update(msg).digest());
  assert.ok(ecdsaVerify(c, Q, h, bytesToBig(sig.subarray(0, 32)), bytesToBig(sig.subarray(32))));
  assert.ok(!ecdsaVerify(c, Q, h, bytesToBig(sig.subarray(0, 32)) + 1n, bytesToBig(sig.subarray(32))));
});
