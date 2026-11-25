// High-level orchestration: connect → PACE or BAC → read data groups → passive authentication.
import { Card, FID } from './card.js';
import { parseCardAccess, choosePace, performPACE } from './pace.js';
import { performBAC } from './bac.js';
import { mrzKeyString } from './mrz.js';
import { parseCOM, parseDG1, parseDG2, parseDG7, parseDG11, parseDG12, parseDG14 } from './lds.js';
import { passiveAuthentication } from './passive-auth.js';
import { CardError } from './apdu.js';

/**
 * @param transport {connect(), transceive(Uint8Array) → Promise<Uint8Array>, disconnect()}
 * @param opts {
 *   access: {type:'MRZ', documentNumber, dateOfBirth, dateOfExpiry} | {type:'CAN', can},
 *   readPhoto?: boolean, readExtra?: boolean, trustAnchors?: Certificate[],
 *   onStatus?(text, fraction?), onApdu?(entry)
 * }
 */
export async function readDocument(transport, opts) {
  const status = opts.onStatus || (() => {});
  const started = performance.now();
  const result = { access: null, chip: {}, dataGroups: {}, raw: {}, timings: {} };

  status('Waiting for the document — hold it flat against the back of the phone');
  result.chip.tag = await transport.connect();
  const card = new Card(transport, { onApdu: opts.onApdu });
  if (result.chip.tag?.maxTransceiveLength && result.chip.tag.maxTransceiveLength < 261) card.chunk = Math.min(card.chunk, result.chip.tag.maxTransceiveLength - 40);

  const mrzInfo = opts.access.type === 'MRZ' ? mrzKeyString(opts.access) : null;
  const password = mrzInfo ? { type: 'MRZ', value: mrzInfo } : { type: 'CAN', value: String(opts.access.can).trim() };
  if (password.type === 'CAN' && !/^\d{6}$/.test(password.value)) throw new Error('CAN must be 6 digits');

  // --- EF.CardAccess tells us whether PACE is available (read before selecting the applet)
  status('Reading chip capabilities (EF.CardAccess)');
  let paceInfos = [];
  try {
    const ca = await card.readFile(FID.CardAccess, { sfi: 0x1c });
    result.raw.cardAccess = ca;
    paceInfos = parseCardAccess(ca);
  } catch { /* no CardAccess → BAC-only document */ }
  result.chip.paceOptions = paceInfos.filter((p) => p.kind === 'PACE');
  const pace = choosePace(paceInfos);

  // --- Access control
  if (pace) {
    status(`Authenticating with PACE (${pace.mapping}, ${pace.cipher}-${pace.keyBits}, ${pace.curve})`);
    try {
      const { sm } = await performPACE(card, password, pace, {}, (s) => status('PACE: ' + s));
      card.sm = sm;
      result.access = { protocol: 'PACE', ...pick(pace, ['mapping', 'cipher', 'keyBits', 'curve', 'oid']), password: password.type };
      await card.selectApplication();
    } catch (e) {
      if (!mrzInfo || (e instanceof CardError && e.sw === 0x6300)) throw e;
      status('PACE failed (' + e.message + '), falling back to BAC');
      card.sm = null;
    }
  } else if (result.chip.paceOptions.length) {
    status('Chip offers only PACE variants this demo does not implement (DH / Integrated Mapping) — trying BAC');
  }
  if (!card.sm) {
    if (!mrzInfo) throw new Error('This chip does not support PACE with the CAN here. Use the MRZ details instead.');
    status('Authenticating with BAC (Basic Access Control)');
    await card.selectApplication();
    card.sm = await performBAC(card, mrzInfo);
    result.access = { protocol: 'BAC', cipher: '3DES', keyBits: 112, password: 'MRZ' };
  }
  result.timings.auth = Math.round(performance.now() - started);

  // --- Data groups
  const readDG = async (label, fid, key) => {
    status(`Reading ${label}`, 0);
    const bytes = await card.readFile(fid, { onProgress: (f) => status(`Reading ${label}`, f) });
    result.raw[key] = bytes;
    return bytes;
  };
  const com = parseCOM(await readDG('EF.COM', FID.COM, 'COM'));
  result.chip.ldsVersion = com.ldsVersion;
  result.chip.dataGroupsPresent = com.dataGroups;
  const dgBytes = new Map();
  const want = [1, 11, 12, 14, 15];
  if (opts.readPhoto !== false) want.push(2);
  if (opts.readExtra) want.push(7);
  for (const n of want.sort((a, b) => a - b)) {
    if (!com.dataGroups.includes(n)) continue;
    try {
      const b = await readDG(`DG${n}`, FID.DG(n), 'DG' + n);
      dgBytes.set(n, b);
    } catch (e) {
      result.dataGroups['DG' + n + 'Error'] = e.message;
      if (n === 1) throw e;
    }
  }
  const parse = { 1: parseDG1, 2: parseDG2, 7: parseDG7, 11: parseDG11, 12: parseDG12, 14: parseDG14, 15: () => ({ present: true }) };
  for (const [n, b] of dgBytes) {
    try { result.dataGroups['DG' + n] = parse[n](b); } catch (e) { result.dataGroups['DG' + n + 'Error'] = 'parse: ' + e.message; }
  }

  // --- Passive authentication
  try {
    const sod = await readDG('EF.SOD (security object)', FID.SOD, 'SOD');
    status('Verifying data integrity (passive authentication)');
    result.passiveAuth = await passiveAuthentication(sod, dgBytes, opts.trustAnchors || []);
  } catch (e) {
    result.passiveAuth = { errors: [e.message], dataGroups: [] };
  }
  result.timings.total = Math.round(performance.now() - started);
  status('Done');
  await transport.disconnect?.();
  return result;
}

const pick = (o, keys) => Object.fromEntries(keys.map((k) => [k, o[k]]));
