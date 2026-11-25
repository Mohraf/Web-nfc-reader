// Builds js/sim/sim-data.js: two fictional SPECIMEN documents with a real ICAO LDS structure,
// signed by a throwaway demo PKI (generated with OpenSSL). Nothing here is a real document.
// Run: node tools/build-sim-data.mjs
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { tlv, encodeOID } from '../js/util/tlv.js';
import { ascii, concat } from '../js/util/bytes.js';
import { checkDigit, mrzKeyString } from '../js/icao/mrz.js';

const dir = mkdtempSync(join(tmpdir(), 'simpki-'));
const ossl = (...a) => execFileSync('openssl', a, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
const b64 = (b) => Buffer.from(b).toString('base64');

// ---------- demo PKI ----------
ossl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:secp384r1', '-nodes', '-keyout', 'csca.key', '-out', 'csca.pem',
  '-days', '7300', '-sha384', '-subj', '/C=KE/O=Simulator Demo PKI/CN=SIMULATOR DEMO CSCA (not a real authority)');
function makeDS(name, keyArgs, extra = []) {
  ossl('req', '-newkey', ...keyArgs, '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/C=KE/O=Simulator Demo PKI/CN=DEMO DOCUMENT SIGNER ${name.toUpperCase()}`);
  ossl('x509', '-req', '-in', `${name}.csr`, '-CA', 'csca.pem', '-CAkey', 'csca.key', '-CAcreateserial', '-out', `${name}.pem`, '-days', '3650', '-sha384', ...extra);
}
makeDS('ds-ec', ['ec', '-pkeyopt', 'ec_paramgen_curve:brainpoolP256r1']);
makeDS('ds-rsa', ['rsa:2048']);

// ---------- LDS helpers ----------
const pad = (s, n) => (s + '<'.repeat(n)).slice(0, n);
const sha256 = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const int = (n) => tlv(0x02, n < 128 ? [n] : [0, n]);
const seq = (...x) => tlv(0x30, ...x);

function faceDG2(jpeg, width, height, gender) {
  const imgInfo = Uint8Array.of(1, 0, width >> 8, width & 255, height >> 8, height & 255, 1, 2, 0, 0, 0, 0);
  const faceInfoLen = 20 + 12 + jpeg.length;
  const faceInfo = Uint8Array.of(faceInfoLen >>> 24, (faceInfoLen >> 16) & 255, (faceInfoLen >> 8) & 255, faceInfoLen & 255, 0, 0, gender, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  const recLen = 14 + faceInfoLen;
  const header = concat(ascii('FAC\x00010\x00'), [recLen >>> 24, (recLen >> 16) & 255, (recLen >> 8) & 255, recLen & 255], [0, 1]);
  const bdb = concat(header, faceInfo, imgInfo, jpeg);
  const bht = tlv(0xa1, tlv(0x80, [1, 1]), tlv(0x87, [1, 1]), tlv(0x88, [0, 8]));
  return tlv(0x75, tlv(0x7f61, tlv(0x02, [1]), tlv(0x7f60, bht, tlv(0x5f2e, bdb))));
}

function signSOD(dgs, dsName, cmsExtra = []) {
  const hashes = [...dgs.entries()].sort((a, b) => a[0] - b[0]).map(([n, b]) => seq(int(n), tlv(0x04, sha256(b))));
  const lso = seq(int(0), seq(tlv(0x06, encodeOID('2.16.840.1.101.3.4.2.1')), tlv(0x05)), seq(...hashes));
  writeFileSync(join(dir, 'lso.der'), lso);
  ossl('cms', '-sign', '-binary', '-nodetach', '-in', 'lso.der', '-signer', `${dsName}.pem`, '-inkey', `${dsName}.key`,
    '-outform', 'DER', '-out', 'sod.der', '-econtent_type', '2.23.136.1.1.1', '-md', 'sha256', '-nosmimecap', ...cmsExtra);
  return tlv(0x77, readFileSync(join(dir, 'sod.der')));
}

const cardAccess = (oid, pid) => tlv(0x31, seq(tlv(0x06, encodeOID(oid)), int(2), int(pid)));

function buildDoc({ id, label, kind, mrzLines, dg11, dg12, face, gender, can, bac, pace, ds, cmsExtra }) {
  const mrz = mrzLines.join('');
  const dg1 = tlv(0x61, tlv(0x5f1f, ascii(mrz)));
  const dg2 = faceDG2(readFileSync(`tools/assets/${face}.jpg`), 240, 300, gender);
  const tagList = (...t) => tlv(0x5c, ...t);
  const dg11b = tlv(0x6b, tagList(...Object.keys(dg11).map((k) => [parseInt(k, 16) >> 8, parseInt(k, 16) & 255]).flat()),
    ...Object.entries(dg11).map(([k, v]) => tlv(parseInt(k, 16), ascii(v))));
  const dg12b = tlv(0x6c, tagList(...Object.keys(dg12).map((k) => [parseInt(k, 16) >> 8, parseInt(k, 16) & 255]).flat()),
    ...Object.entries(dg12).map(([k, v]) => tlv(parseInt(k, 16), ascii(v))));
  const com = tlv(0x60, tlv(0x5f01, ascii('0107')), tlv(0x5f36, ascii('040000')), tlv(0x5c, [0x61, 0x75, 0x6b, 0x6c]));
  const dgs = new Map([[1, dg1], [2, dg2], [11, dg11b], [12, dg12b]]);
  const files = { '011E': b64(com), '0101': b64(dg1), '0102': b64(dg2), '010B': b64(dg11b), '010C': b64(dg12b), '011D': b64(signSOD(dgs, ds, cmsExtra)) };
  if (pace) files['011C'] = b64(cardAccess(pace.oid, pace.parameterId));
  const line2 = mrzLines[1];
  const access = kind === 'TD3'
    ? { documentNumber: line2.slice(0, 9).replace(/</g, ''), dateOfBirth: line2.slice(13, 19), dateOfExpiry: line2.slice(21, 27) }
    : { documentNumber: mrzLines[0].slice(5, 14).replace(/</g, ''), dateOfBirth: line2.slice(0, 6), dateOfExpiry: line2.slice(8, 14) };
  return { id, label, kind, mrzLines, access, can, bac, pace, mrzInfo: mrzKeyString(access), files };
}

// ---------- fictional passport (TD3) ----------
const p1 = pad('P<KENSPECIMEN<<AMANI<WANJIRU', 44);
const pDoc = 'AK0012345', pDob = '900115', pExp = '320301', pPers = pad('12345678', 14);
const p2a = pDoc + checkDigit(pDoc) + 'KEN' + pDob + checkDigit(pDob) + 'F' + pExp + checkDigit(pExp) + pPers + checkDigit(pPers);
const p2 = p2a + checkDigit(p2a.slice(0, 10) + p2a.slice(13, 20) + p2a.slice(21, 43));

// ---------- fictional national ID card (TD1, Maisha-style layout) ----------
const iDoc = 'MC0001234', iDob = '850704', iExp = '340704';
const i1 = pad('IDKEN' + iDoc + checkDigit(iDoc) + '<<<<<<<<<<<<<<<', 30);
const i2a = iDob + checkDigit(iDob) + 'M' + iExp + checkDigit(iExp) + 'KEN' + pad('', 11);
const i2 = i2a + checkDigit(i1.slice(5, 30) + i2a.slice(0, 7) + i2a.slice(8, 15) + i2a.slice(18, 29));
const i3 = pad('SPECIMEN<<BARAKA<OTIENO', 30);

const docs = [
  buildDoc({ id: 'passport', label: 'Specimen ePassport (TD3) — PACE AES-128 + BAC', kind: 'TD3', mrzLines: [p1, p2],
    dg11: { '5F0E': 'SPECIMEN<<AMANI<WANJIRU', '5F2B': '19900115', '5F11': 'NAIROBI' },
    dg12: { '5F19': 'SIMULATED ISSUING AUTHORITY', '5F26': '20220301' },
    face: 'face-passport', gender: 2, can: '482193', bac: true,
    pace: { oid: '0.4.0.127.0.7.2.2.4.2.2', parameterId: 13, cipher: 'AES', keyBits: 128 }, ds: 'ds-ec' }),
  buildDoc({ id: 'idcard', label: 'Specimen ID card (TD1, Maisha-style) — PACE-only AES-256', kind: 'TD1', mrzLines: [i1, i2, i3],
    dg11: { '5F0E': 'SPECIMEN<<BARAKA<OTIENO', '5F2B': '19850704', '5F11': 'KISUMU', '5F10': '000000000' },
    dg12: { '5F19': 'SIMULATED REGISTRATION SERVICE', '5F26': '20240704' },
    face: 'face-idcard', gender: 1, can: '735104', bac: false,
    pace: { oid: '0.4.0.127.0.7.2.2.4.2.4', parameterId: 12, cipher: 'AES', keyBits: 256 }, ds: 'ds-rsa',
    cmsExtra: ['-keyopt', 'rsa_padding_mode:pss', '-keyopt', 'rsa_pss_saltlen:32'] }),
];

const csca = ossl('x509', '-in', 'csca.pem', '-outform', 'DER');
const out = `// AUTO-GENERATED by tools/build-sim-data.mjs — fictional SPECIMEN documents for the simulator.
// The demo CSCA below is a throwaway key pair; it is not, and does not imitate, any real authority.
export const DEMO_CSCA_B64 = '${b64(csca)}';
export const SIM_DOCS = ${JSON.stringify(docs, null, 2)};
`;
writeFileSync('js/sim/sim-data.js', out);
console.log('wrote js/sim/sim-data.js', (out.length / 1024).toFixed(1) + ' KB');
