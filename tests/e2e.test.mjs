// End-to-end: reader ↔ virtual chip, through every access path, plus passive authentication.
import test from 'node:test';
import assert from 'node:assert/strict';
import { SIM_DOCS, DEMO_CSCA_B64 } from '../js/sim/sim-data.js';
import { SimulatorTransport, b64decode } from '../js/transports/simulator.js';
import { readDocument } from '../js/icao/reader.js';
import { parseCertificateBytes } from '../js/icao/passive-auth.js';

const fast = (doc, mutate) => {
  const d = structuredClone(doc);
  mutate?.(d);
  return new SimulatorTransport(d, { tapDelay: 0, latency: 0 });
};
const passport = SIM_DOCS.find((d) => d.id === 'passport');
const idcard = SIM_DOCS.find((d) => d.id === 'idcard');
const anchors = [parseCertificateBytes(b64decode(DEMO_CSCA_B64))];

test('passport via PACE (MRZ) — full read and passive auth incl. CSCA chain', async () => {
  const r = await readDocument(fast(passport), { access: { type: 'MRZ', ...passport.access }, trustAnchors: anchors });
  assert.equal(r.access.protocol, 'PACE');
  assert.equal(r.access.curve, 'brainpoolP256r1');
  assert.equal(r.dataGroups.DG1.surname, 'SPECIMEN');
  assert.equal(r.dataGroups.DG1.givenNames, 'AMANI WANJIRU');
  assert.ok(r.dataGroups.DG1.valid);
  assert.equal(r.dataGroups.DG2[0].mime, 'image/jpeg');
  assert.equal(r.dataGroups.DG11.placeOfBirth, 'NAIROBI');
  assert.equal(r.passiveAuth.hashesOk, true);
  assert.equal(r.passiveAuth.signature, true, JSON.stringify(r.passiveAuth.errors));
  assert.equal(r.passiveAuth.csca?.valid, true);
});

test('passport via BAC when CardAccess is absent', async () => {
  const t = fast(passport, (d) => { delete d.files['011C']; d.pace = null; });
  const r = await readDocument(t, { access: { type: 'MRZ', ...passport.access } });
  assert.equal(r.access.protocol, 'BAC');
  assert.equal(r.dataGroups.DG1.documentNumber, passport.access.documentNumber);
  assert.ok(r.passiveAuth.hashesOk && r.passiveAuth.signature);
});

test('ID card via PACE with CAN, AES-256 / P-256, RSA-PSS signed SOD', async () => {
  const r = await readDocument(fast(idcard), { access: { type: 'CAN', can: idcard.can }, trustAnchors: anchors });
  assert.equal(r.access.protocol, 'PACE');
  assert.equal(r.access.keyBits, 256);
  assert.equal(r.access.password, 'CAN');
  assert.equal(r.dataGroups.DG1.format, 'TD1');
  assert.equal(r.dataGroups.DG1.givenNames, 'BARAKA OTIENO');
  assert.ok(r.passiveAuth.hashesOk);
  assert.equal(r.passiveAuth.signature, true, JSON.stringify(r.passiveAuth.errors));
  assert.equal(r.passiveAuth.csca?.valid, true);
});

test('wrong MRZ is rejected with an authentication error (PACE and BAC)', async () => {
  const bad = { type: 'MRZ', ...passport.access, dateOfBirth: '900116' };
  await assert.rejects(readDocument(fast(passport), { access: bad }), /Authentication failed/);
  const t = fast(passport, (d) => { delete d.files['011C']; d.pace = null; });
  await assert.rejects(readDocument(t, { access: bad }), /Authentication failed/);
});

test('wrong CAN is rejected; PACE-only card refuses BAC fallback', async () => {
  await assert.rejects(readDocument(fast(idcard), { access: { type: 'CAN', can: '000000' } }), /Authentication failed/);
});

test('tampered data group is detected by passive authentication', async () => {
  const t = fast(passport, (d) => {
    const dg11 = b64decode(d.files['010B']);
    dg11[dg11.length - 1] ^= 0x01;
    d.files['010B'] = Buffer.from(dg11).toString('base64');
  });
  const r = await readDocument(t, { access: { type: 'MRZ', ...passport.access } });
  assert.equal(r.passiveAuth.hashesOk, false);
  assert.equal(r.passiveAuth.dataGroups.find((x) => x.dg === 11).ok, false);
});
