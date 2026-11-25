// Logical Data Structure parsing (ICAO 9303-10): EF.COM, DG1, DG2, DG7, DG11, DG12, DG14, DG15.
import { toAscii, utf8 } from '../util/bytes.js';
import { readTLV, childMap, children, find, decodeOID } from '../util/tlv.js';
import { parseMRZ } from './mrz.js';

export const DG_TAGS = { 0x61: 1, 0x75: 2, 0x63: 3, 0x76: 4, 0x65: 5, 0x66: 6, 0x67: 7, 0x68: 8, 0x69: 9, 0x6a: 10, 0x6b: 11, 0x6c: 12, 0x6d: 13, 0x6e: 14, 0x6f: 15, 0x70: 16 };
export const DG_NAMES = {
  1: 'MRZ data', 2: 'Facial image', 3: 'Fingerprints (EAC protected)', 4: 'Iris (EAC protected)', 5: 'Portrait', 6: 'Reserved',
  7: 'Signature image', 8: 'Data features', 9: 'Structure features', 10: 'Substance features', 11: 'Additional personal details',
  12: 'Additional document details', 13: 'Optional details', 14: 'Chip Authentication keys', 15: 'Active Authentication key', 16: 'Persons to notify',
};

export function parseCOM(bytes) {
  const t = readTLV(bytes, 0);
  const m = childMap(t);
  const list = m.get(0x5c)?.value || new Uint8Array(0);
  return {
    ldsVersion: m.get(0x5f01) ? toAscii(m.get(0x5f01).value) : null,
    unicodeVersion: m.get(0x5f36) ? toAscii(m.get(0x5f36).value) : null,
    dataGroups: Array.from(list).map((x) => DG_TAGS[x]).filter(Boolean),
  };
}

export function parseDG1(bytes) {
  const mrz = find(readTLV(bytes, 0).value, 0x5f1f);
  if (!mrz) throw new Error('DG1 without MRZ');
  const s = toAscii(mrz.value);
  const fmt = s.length === 90 ? [30, 30, 30] : s.length === 72 ? [36, 36] : [44, 44];
  const lines = []; let o = 0; for (const n of fmt) { lines.push(s.slice(o, o + n)); o += n; }
  return parseMRZ(lines.join('\n'));
}

/** Extract the face image(s) from DG2 (ISO/IEC 19794-5 inside a CBEFF structure). */
export function parseDG2(bytes) {
  const images = [];
  const walk = (buf) => {
    for (const t of children(buf)) {
      if (t.tag === 0x5f2e || t.tag === 0x7f2e) images.push(extractFaceImage(t.value));
      else if (t.constructed) walk(t.value);
    }
  };
  walk(readTLV(bytes, 0).value);
  return images.filter(Boolean);
}

function extractFaceImage(b) {
  // Try the structured 19794-5 header first, fall back to scanning for image magic bytes.
  if (b[0] === 0x46 && b[1] === 0x41 && b[2] === 0x43 && b[3] === 0) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    let o = 14; // general header: 'FAC\0' + version(4) + record length(4) + #images(2)
    const nFeat = dv.getUint16(o + 4);
    const gender = b[o + 6];
    o += 20 + nFeat * 8;
    const dataType = b[o + 1];
    const width = dv.getUint16(o + 2), height = dv.getUint16(o + 4);
    o += 12;
    const data = b.slice(o);
    return { mime: dataType === 1 ? 'image/jp2' : 'image/jpeg', width, height, gender, data };
  }
  for (let i = 0; i < b.length - 4; i++) {
    if (b[i] === 0xff && b[i + 1] === 0xd8 && b[i + 2] === 0xff) return { mime: 'image/jpeg', data: b.slice(i) };
    if (b[i] === 0x00 && b[i + 1] === 0x00 && b[i + 2] === 0x00 && b[i + 3] === 0x0c && b[i + 4] === 0x6a) return { mime: 'image/jp2', data: b.slice(i) };
    if (b[i] === 0xff && b[i + 1] === 0x4f && b[i + 2] === 0xff && b[i + 3] === 0x51) return { mime: 'image/j2k', data: b.slice(i) };
  }
  return null;
}

export function parseDG7(bytes) {
  const t = find(readTLV(bytes, 0).value, 0x5f43);
  if (!t) return null;
  const d = t.value;
  return { mime: d[0] === 0xff && d[1] === 0xd8 ? 'image/jpeg' : 'image/jp2', data: d.slice() };
}

const text = (t) => utf8(t.value).replace(/<+/g, ' ').trim();

const DG11_FIELDS = {
  0x5f0e: 'fullName', 0x5f0f: 'otherNames', 0x5f10: 'personalNumber', 0x5f2b: 'fullDateOfBirth', 0x5f11: 'placeOfBirth',
  0x5f42: 'permanentAddress', 0x5f12: 'telephone', 0x5f13: 'profession', 0x5f14: 'title', 0x5f15: 'personalSummary',
  0x5f16: 'proofOfCitizenship', 0x5f17: 'otherTravelDocuments', 0x5f18: 'custodyInformation',
};
const DG12_FIELDS = {
  0x5f19: 'issuingAuthority', 0x5f26: 'dateOfIssue', 0x5f1b: 'endorsements', 0x5f1c: 'taxOrExitRequirements',
  0x5f55: 'dateOfPersonalization', 0x5f56: 'personalizationSystemSerial',
};

function parseFields(bytes, map) {
  const out = {};
  const walk = (buf) => {
    for (const t of children(buf)) {
      if (map[t.tag]) {
        const key = map[t.tag];
        const v = text(t);
        out[key] = out[key] ? [].concat(out[key], v) : v;
      } else if (t.constructed) walk(t.value);
    }
  };
  walk(readTLV(bytes, 0).value);
  return out;
}

export const parseDG11 = (b) => parseFields(b, DG11_FIELDS);
export const parseDG12 = (b) => parseFields(b, DG12_FIELDS);

/** DG14 SecurityInfos: report which advanced protocols the chip offers. */
export function parseDG14(bytes) {
  const set = readTLV(readTLV(bytes, 0).value, 0);
  return children(set).map((seq) => {
    const p = children(seq);
    const oid = p[0]?.tag === 0x06 ? decodeOID(p[0].value) : '?';
    let kind = 'Other';
    if (oid.startsWith('0.4.0.127.0.7.2.2.3.')) kind = 'Chip Authentication';
    else if (oid.startsWith('0.4.0.127.0.7.2.2.1.')) kind = 'Chip Authentication public key';
    else if (oid.startsWith('0.4.0.127.0.7.2.2.4.')) kind = 'PACE';
    else if (oid.startsWith('0.4.0.127.0.7.2.2.2')) kind = 'Terminal Authentication';
    else if (oid === '2.23.136.1.1.5') kind = 'Active Authentication';
    return { oid, kind };
  });
}
