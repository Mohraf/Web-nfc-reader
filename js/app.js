// UI controller: a step-by-step flow (document → access key → prepare → position → scan → result).
// All protocol work lives in js/icao; transports in js/transports.
import { readDocument } from './icao/reader.js';
import { checkDigit, normDocNumber, parseMRZ, mrzDateToISO } from './icao/mrz.js';
import { parseCertificateBytes } from './icao/passive-auth.js';
import { DG_NAMES } from './icao/lds.js';
import { hex } from './util/bytes.js';
import { SIM_DOCS, DEMO_CSCA_B64 } from './sim/sim-data.js';
import { SimulatorTransport, b64decode } from './transports/simulator.js';
import { AndroidBridgeTransport } from './transports/android-bridge.js';
import { webNfcSupported, probeWebNfc, webToNativeAvailable, probeWebToNative } from './transports/ndef-probe.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const store = {
  get(k, d) { try { const v = localStorage.getItem('cir.' + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('cir.' + k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
};

const state = {
  source: 'sim', doc: store.get('doc', 'passport'), access: 'MRZ', nativeStatus: 'absent',
  busy: false, cancelled: false, transport: null, lastResult: null, logLines: [], stack: ['doc'], progress: 0,
};

const COUNTRIES = { KEN: 'Kenya', UGA: 'Uganda', TZA: 'Tanzania', RWA: 'Rwanda', BDI: 'Burundi', SSD: 'South Sudan', COD: 'DR Congo', SOM: 'Somalia', ETH: 'Ethiopia', UTO: 'Utopia (specimen)' };
const country = (c) => (c ? (COUNTRIES[c] ? `${COUNTRIES[c]} (${c})` : c) : '—');
const SEX = { M: 'Male', F: 'Female', '<': 'Unspecified', X: 'Unspecified' };
const fmtDate = (iso) => {
  const m = /^(\d{4})-?(\d{2})-?(\d{2})$/.exec(iso || '');
  if (!m) return iso || '—';
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
};

// ---------------------------------------------------------------- navigation
const LABELS = {
  doc: 'Step 1 of 3 · Document', key: 'Step 2 of 3 · Details', prep: 'Step 3 of 3 · Chip', position: 'Step 3 of 3 · Chip',
  scan: 'Step 3 of 3 · Chip', result: 'Result', about: 'How it works',
};
function show(name) {
  for (const s of document.querySelectorAll('.screen')) {
    const on = s.dataset.screen === name;
    s.hidden = !on;
    s.classList.toggle('enter', on);
  }
  $('step-label').textContent = LABELS[name];
  $('btn-back').setAttribute('aria-hidden', String(state.stack.length <= 1));
  $('btn-about').setAttribute('aria-hidden', String(name === 'about'));
  window.scrollTo({ top: 0 });
}
function go(name) { if (state.stack.at(-1) !== name) state.stack.push(name); show(name); }
function back() {
  if (state.stack.at(-1) === 'scan') cancelScan();
  if (state.stack.length > 1) state.stack.pop();
  show(state.stack.at(-1));
}
function reset(name = 'doc') { state.stack = [name]; show(name); }

// ---------------------------------------------------------------- environment
async function detectEnvironment() {
  state.nativeStatus = AndroidBridgeTransport.present() ? await AndroidBridgeTransport.status() : 'absent';
  const chips = [];
  if (state.nativeStatus === 'ready') chips.push(['ok', 'Phone NFC ready']);
  else if (state.nativeStatus === 'disabled') chips.push(['warn', 'NFC is turned off']);
  else if (state.nativeStatus === 'unsupported') chips.push(['bad', 'No NFC on this phone']);
  else chips.push(['', 'Browser only: no chip access']);
  if (webNfcSupported()) chips.push(['', 'Web NFC (tags only)']);
  if (webToNativeAvailable()) chips.push(['', 'WebToNative (tags only)']);
  $('env').innerHTML = chips.map(([c, t]) => `<span class="chip ${c}">${esc(t)}</span>`).join('');
  $('btn-webnfc').disabled = !webNfcSupported();
  $('btn-wtn').disabled = !webToNativeAvailable();
}

function sourceHint() {
  if (state.source === 'sim') return 'Runs the real protocol against a virtual chip with fictional specimen data. No document needed.';
  switch (state.nativeStatus) {
    case 'ready': return 'Uses this phone’s NFC reader.';
    case 'disabled': return 'Turn on NFC in Android settings, then come back.';
    case 'unsupported': return 'This phone has no NFC hardware. Use the simulator.';
    default: return 'Browsers can’t talk to ID chips. Install the Chip ID Reader Android app to read a real document, or use the simulator.';
  }
}

// ---------------------------------------------------------------- form state
function setSource(src) {
  state.source = src;
  for (const b of document.querySelectorAll('[data-source]')) b.setAttribute('aria-checked', String(b.dataset.source === src));
  $('source-hint').textContent = sourceHint();
  if (src === 'sim') fillSpecimen();
  else { for (const id of ['in-doc', 'in-dob', 'in-doe', 'in-can', 'in-mrz']) $(id).value = ''; renderKey(); }
  updatePosition();
}

function setDoc(doc) {
  state.doc = doc;
  store.set('doc', doc);
  for (const b of document.querySelectorAll('[data-doc]')) b.setAttribute('aria-checked', String(b.dataset.doc === doc));
  $('doc-figure').innerHTML = doc === 'passport' ? PASSPORT_TIP : IDCARD_TIP;
  if (state.source === 'sim') fillSpecimen();
  updatePosition();
}

function setAccess(mode) {
  state.access = mode;
  for (const b of document.querySelectorAll('[data-access]')) b.setAttribute('aria-selected', String(b.dataset.access === mode));
  $('pane-mrz').hidden = mode !== 'MRZ';
  $('pane-can').hidden = mode !== 'CAN';
  $('key-error').hidden = true;
}

function updatePosition() {
  const sim = state.source === 'sim';
  $('pos-lead').textContent = sim
    ? 'In simulator mode there’s nothing to hold. Tap Continue to run the scan against the virtual chip.'
    : state.doc === 'passport'
      ? 'Close the passport and hold the top back of your phone flat against the cover with the chip symbol for 5–10 seconds.'
      : 'Hold the top back of your phone flat against the card for 5–10 seconds.';
  $('btn-scan-label').textContent = sim ? 'Run simulated scan' : 'Continue';
  $('btn-scan').disabled = !sim && state.nativeStatus !== 'ready';
}

function fillSpecimen() {
  const d = SIM_DOCS.find((x) => x.id === state.doc);
  $('in-doc').value = d.access.documentNumber;
  $('in-dob').value = d.access.dateOfBirth;
  $('in-doe').value = d.access.dateOfExpiry;
  $('in-can').value = d.can;
  $('in-mrz').value = d.mrzLines.join('\n');
  $('mrz-parse-msg').textContent = '';
  renderKey();
}

function renderKey() {
  const raw = normDocNumber($('in-doc').value);
  const doc = raw.padEnd(9, '<');
  const dob = $('in-dob').value.replace(/\D/g, '');
  const doe = $('in-doe').value.replace(/\D/g, '');
  const part = (v, n) => (v.length === n ? `${esc(v)}<span class="cd">${checkDigit(v)}</span>` : `<span class="empty">${esc(v.padEnd(n, '·'))}·</span>`);
  $('mrz-key').innerHTML = (raw ? `${esc(doc)}<span class="cd">${checkDigit(doc)}</span>` : '<span class="empty">··········</span>') + part(dob, 6) + part(doe, 6);
  for (const [id, v] of [['in-dob', dob], ['in-doe', doe]]) $(id).setAttribute('aria-invalid', String(!!v && !/^\d{6}$/.test(v)));
}

function onMrzPaste() {
  const text = $('in-mrz').value.trim();
  const msg = $('mrz-parse-msg');
  if (!text) { msg.textContent = ''; return; }
  try {
    const m = parseMRZ(text);
    $('in-doc').value = m.documentNumber; $('in-dob').value = m.dateOfBirth; $('in-doe').value = m.dateOfExpiry;
    renderKey();
    const bad = Object.entries(m.checks).filter(([, v]) => !v).map(([k]) => k);
    msg.textContent = bad.length ? `Check digit mismatch in: ${bad.join(', ')}. Fix any misread characters.` : `${m.format === 'TD1' ? 'ID card' : 'Passport'} MRZ recognised. All check digits are valid.`;
    if (m.format === 'TD1') setDoc('idcard');
    if (m.format === 'TD3') setDoc('passport');
  } catch (e) { msg.textContent = e.message; }
}

function validateKey() {
  const err = $('key-error');
  let m = '';
  if (state.access === 'MRZ') {
    if (!normDocNumber($('in-doc').value)) m = 'Enter the document number from the MRZ.';
    else if (!/^\d{6}$/.test($('in-dob').value.trim())) m = 'Enter the date of birth as YYMMDD, for example 900115.';
    else if (!/^\d{6}$/.test($('in-doe').value.trim())) m = 'Enter the expiry date as YYMMDD, for example 320301.';
  } else if (!/^\d{6}$/.test($('in-can').value.trim())) m = 'The CAN is 6 digits.';
  err.textContent = m; err.hidden = !m;
  return !m;
}

// ---------------------------------------------------------------- scan progress
const PHASES = ['connect', 'access', 'read', 'verify'];
function phaseOf(t) {
  if (/^Waiting/.test(t)) return 'connect';
  if (/^(Reading chip cap|Authenticat|PACE|Chip offers)/.test(t)) return 'access';
  if (/^Reading/.test(t)) return 'read';
  if (/^Verifying/.test(t)) return 'verify';
  if (t === 'Done') return 'done';
  return null;
}
function friendly(t, f) {
  const pct = f !== undefined ? ` · ${Math.round(f * 100)}%` : '';
  if (/^Waiting/.test(t)) return 'Searching for chip…';
  if (/^Reading chip cap/.test(t)) return 'Chip found · checking security';
  if (/^(Authenticat|PACE|Chip offers)/.test(t)) return 'Unlocking the chip…';
  if (/DG2/.test(t)) return 'Reading photo' + pct;
  if (/DG1\b/.test(t)) return 'Reading MRZ data';
  if (/DG11|DG12/.test(t)) return 'Reading personal details';
  if (/DG7/.test(t)) return 'Reading signature image';
  if (/SOD/.test(t)) return 'Reading the chip’s signature';
  if (/^Reading/.test(t)) return 'Reading chip data';
  if (/^Verifying/.test(t)) return 'Checking authenticity…';
  return t;
}
const BASE = { connect: 0, access: 8, read: 30, verify: 94, done: 100 };
let filesStarted = 0, lastFile = '';
function onStatus(text, fraction) {
  const p = phaseOf(text);
  if (p) {
    setPhase(p);
    if (p !== 'connect') { $('hero').dataset.state = 'reading'; $('hero-title').textContent = 'Reading your chip'; $('scan-lead').textContent = 'Keep the phone still until the scan finishes.'; }
  }
  if (p === 'read') {
    const label = text.replace(/\s.*/, '') + text.split(' ')[1];
    if (label !== lastFile) { lastFile = label; filesStarted++; }
    state.progress = Math.max(state.progress, 30 + 64 * Math.min(1, (filesStarted - 1 + (fraction ?? 0)) / 6));
  } else if (p) {
    state.progress = Math.max(state.progress, BASE[p]);
  }
  $('ring-fill').style.strokeDasharray = `${state.progress} 100`;
  $('status-text').textContent = friendly(text, fraction);
}
function setPhase(p, failed = false) {
  const idx = p === 'done' ? PHASES.length : PHASES.indexOf(p);
  for (const li of $('steps').children) {
    const i = PHASES.indexOf(li.dataset.step);
    li.className = i < idx ? 'done' : i === idx ? (failed ? 'failed' : 'active') : '';
  }
}
function resetScanView() {
  state.progress = 0; filesStarted = 0; lastFile = '';
  $('hero').dataset.state = 'searching';
  $('hero-title').textContent = 'Ready to scan';
  $('scan-lead').textContent = state.source === 'sim' ? 'Connecting to the virtual chip…' : 'Slowly move your phone across the document until the chip is found.';
  $('status-pill').className = 'pill';
  $('status-text').textContent = 'Searching for chip…';
  $('ring-fill').style.strokeDasharray = '0 100';
  $('error-actions').hidden = true;
  $('btn-cancel').hidden = false;
  for (const li of $('steps').children) li.className = '';
}

function logApdu(e) {
  const plain = hex(e.bytes).replace(/(..)/g, '$1 ').trim();
  const short = plain.length > 120 ? plain.slice(0, 120) + ` … (${e.bytes.length} bytes)` : plain;
  state.logLines.push(`<span class="${e.dir === 'C' ? 'c' : ''}">${e.dir === 'C' ? '>' : '<'} ${esc(short)}</span>` + (e.wire ? `\n<span class="w">  wire ${e.wire.length} bytes, secure messaging</span>` : ''));
  if (state.logLines.length > 600) state.logLines.splice(0, state.logLines.length - 600);
}

// ---------------------------------------------------------------- trust anchors
function trustAnchors() {
  const out = [];
  for (const der of [b64decode(DEMO_CSCA_B64), ...store.get('csca', []).map(b64decode)]) { try { out.push(parseCertificateBytes(der)); } catch { /* skip */ } }
  return out;
}
function renderCscaCount() { const n = store.get('csca', []).length; $('csca-count').textContent = n ? `${n} added on this device` : 'None added yet'; }
async function importCsca(files) {
  const added = store.get('csca', []);
  for (const f of files) {
    const bytes = new Uint8Array(await f.arrayBuffer());
    const pem = new TextDecoder().decode(bytes).match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g);
    for (const der of pem ? pem.map((p) => b64decode(p.replace(/-----[^-]+-----|\s/g, ''))) : [bytes]) {
      try { parseCertificateBytes(der); added.push(btoa(String.fromCharCode(...der))); } catch { /* not a certificate */ }
    }
  }
  store.set('csca', added);
  renderCscaCount();
}

// ---------------------------------------------------------------- scan
async function scan() {
  if (state.busy) return;
  const access = state.access === 'MRZ'
    ? { type: 'MRZ', documentNumber: $('in-doc').value, dateOfBirth: $('in-dob').value.trim(), dateOfExpiry: $('in-doe').value.trim() }
    : { type: 'CAN', can: $('in-can').value.trim() };
  const transport = state.source === 'sim' ? new SimulatorTransport(SIM_DOCS.find((x) => x.id === state.doc)) : new AndroidBridgeTransport();
  Object.assign(state, { busy: true, cancelled: false, transport, logLines: [] });
  go('scan');
  resetScanView();
  setPhase('connect');
  try {
    const result = await readDocument(transport, {
      access, readPhoto: $('opt-photo').checked, readExtra: $('opt-extra').checked,
      trustAnchors: trustAnchors(), onStatus, onApdu: logApdu,
    });
    if (state.cancelled) return;
    state.lastResult = result;
    setPhase('done');
    $('ring-fill').style.strokeDasharray = '100 100';
    navigator.vibrate?.(60);
    renderResult(result, transport);
    state.stack = ['doc', 'result'];
    show('result');
  } catch (e) {
    if (state.cancelled) return;
    const phase = [...$('steps').children].find((li) => li.className === 'active')?.dataset.step || 'connect';
    setPhase(phase, true);
    $('hero').dataset.state = 'error';
    $('hero-title').textContent = 'Scan didn’t finish';
    $('scan-lead').textContent = friendlyError(e);
    $('status-pill').className = 'pill error';
    $('status-text').textContent = /Authentication failed/.test(e.message) ? 'Chip refused the details' : 'Connection interrupted';
    $('error-actions').hidden = false;
    $('btn-cancel').hidden = true;
    try { await transport.disconnect?.(); } catch { /* ignore */ }
  } finally {
    state.busy = false;
  }
}

function cancelScan() {
  if (!state.busy) return;
  state.cancelled = true;
  state.busy = false;
  state.transport?.disconnect?.().catch(() => {});
}

function friendlyError(e) {
  const m = e?.message || String(e);
  if (/Authentication failed/.test(m)) return 'The details don’t match the chip. Check the document number and both dates against the MRZ (O and 0, I and 1 are easy to mix up), or use the CAN.';
  if (/lost|TagLost|not connected/i.test(m)) return 'The connection to the chip was lost. Keep the phone flat and still against the document for the whole scan.';
  if (/No document detected/.test(m)) return 'No chip was found. Move the phone slowly over the document, starting near the camera.';
  return m;
}

// ---------------------------------------------------------------- result
const ICON = {
  ok: '<svg viewBox="0 0 24 24"><path d="M6 12.5l4 4 8-9" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  warn: '<svg viewBox="0 0 24 24"><path d="M12 8v5M12 16.5v.01" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/><circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>',
  bad: '<svg viewBox="0 0 24 24"><path d="M8 8l8 8M16 8l-8 8" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>',
  lock: '<svg viewBox="0 0 24 24"><rect x="5" y="10.5" width="14" height="10" rx="2.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>',
};

function renderResult(r, transport) {
  const dg1 = r.dataGroups.DG1 || {}, dg11 = r.dataGroups.DG11 || {}, dg12 = r.dataGroups.DG12 || {};
  const img = r.dataGroups.DG2?.[0];
  const pa = r.passiveAuth || {};
  const a = r.access || {};
  const isCard = dg1.format === 'TD1';
  const sim = state.source === 'sim';

  let photo = '<div class="portrait">No photo read</div>';
  if (img?.mime === 'image/jpeg') photo = `<img class="portrait" src="${URL.createObjectURL(new Blob([img.data], { type: img.mime }))}" alt="Photo from the chip">`;
  else if (img) photo = `<div class="portrait">JPEG 2000 photo, in JSON export</div>`;

  const checks = [];
  checks.push(['ok', 'lock', 'Chip unlocked securely', `${a.protocol}${a.mapping ? ' ' + a.mapping : ''} · ${a.cipher}${a.keyBits ? '-' + a.keyBits : ''}${a.curve ? ' · ' + a.curve : ''}`]);
  if (pa.hashesOk) checks.push(['ok', 'ok', 'Data hasn’t been altered', `All ${pa.dataGroups.length} data groups match the chip’s signed hashes`]);
  else if (pa.dataGroups?.length) checks.push(['bad', 'bad', 'Data doesn’t match', pa.dataGroups.filter((d) => !d.ok).map((d) => 'DG' + d.dg).join(', ') + ' failed the hash check']);
  else checks.push(['warn', 'warn', 'Integrity not checked', 'The chip’s security object could not be read']);
  if (pa.signature === true) checks.push(['ok', 'ok', 'Signed by the document signer', pa.signer?.subject || '']);
  else if (pa.signature === false) checks.push(['bad', 'bad', 'Signature invalid', (pa.errors || []).join('; ')]);
  if (pa.csca?.valid) checks.push(['ok', 'ok', 'Issuer is trusted', pa.csca.subject]);
  else if (pa.csca) checks.push(['bad', 'bad', 'Issuer check failed', pa.csca.subject]);
  else checks.push(['warn', 'warn', 'Issuer not verified', 'Add the issuing country’s CSCA certificate under How it works']);
  if (!dg1.valid) checks.push(['warn', 'warn', 'MRZ check digit mismatch', 'The chip’s MRZ data has an inconsistent check digit']);

  const allGood = pa.hashesOk && pa.signature === true;
  const personal = dg11.personalNumber || dg1.personalNumber || dg1.optionalData1 || '';
  const details = [
    ['Nationality', country(dg1.nationality)],
    ['Issuing state', country(dg1.issuingState)],
    ...(personal ? [['Personal number', personal]] : []),
    ...(dg11.placeOfBirth ? [['Place of birth', dg11.placeOfBirth]] : []),
    ...(dg12.dateOfIssue ? [['Date of issue', fmtDate(dg12.dateOfIssue)]] : []),
    ...(dg12.issuingAuthority ? [['Issued by', dg12.issuingAuthority]] : []),
  ];
  const tech = [
    ['Read with', esc(sim ? 'Simulator (fictional specimen)' : transport.name)],
    ['Chip offers', esc(r.chip.paceOptions?.length ? r.chip.paceOptions.map((p) => `PACE ${p.mapping} ${p.cipher}-${p.keyBits}${p.curve ? ' ' + p.curve : ''}`).join('; ') : 'BAC only')],
    ['Data groups', esc((r.chip.dataGroupsPresent || []).map((n) => `DG${n}`).join(', '))],
    ['Hash check', pa.dataGroups?.length ? `<span class="dg-chips">${pa.dataGroups.map((d) => `<span class="chip ${d.ok ? 'ok' : 'bad'}" title="${esc(DG_NAMES[d.dg] || '')}">DG${d.dg}</span>`).join('')}</span>` : '—'],
    ['Document signer', esc(pa.signer ? `${pa.signer.key}, valid ${pa.signer.notBefore} to ${pa.signer.notAfter}` : '—')],
    ...(r.dataGroups.DG14 ? [['DG14 protocols', esc([...new Set(r.dataGroups.DG14.map((x) => x.kind))].join(', ') + ' (not run)')]] : []),
    ...(r.dataGroups.DG15 ? [['Active Authentication', 'Key present (not run)']] : []),
    ...Object.entries(r.dataGroups).filter(([k]) => k.endsWith('Error')).map(([k, v]) => [k.replace('Error', ''), esc(v)]),
    ['Time', `${(r.timings.auth / 1000).toFixed(1)} s to unlock · ${(r.timings.total / 1000).toFixed(1)} s total`],
  ];

  $('result').innerHTML = `
    <span class="icon-tile lg ${allGood ? 'ok' : ''}" aria-hidden="true">${allGood ? ICON.ok : ICON.warn}</span>
    <h1 class="title" id="t-result">${allGood ? 'Chip read and verified' : 'Chip read, with warnings'}</h1>
    <p class="lead">${allGood ? 'The details below come straight from the chip and match its digital signature.' : 'Some checks didn’t pass. See the security checks below.'}</p>
    <article class="id-card">
      <div class="id-card-top">
        <span class="id-card-kind">${esc(country(dg1.issuingState).replace(/ \(.*/, ''))} · ${isCard ? 'ID card' : 'Passport'}</span>
        ${sim ? '<span class="sample-tag">Specimen</span>' : '<span class="id-chip" aria-hidden="true"></span>'}
      </div>
      <div class="id-card-body">
        ${photo}
        <div>
          <h2 class="id-name"><span class="id-surname">${esc(dg1.surname)}</span>${esc(dg1.givenNames)}</h2>
          <dl class="id-facts">
            <div><dt>Document no.</dt><dd>${esc(dg1.documentNumber)}</dd></div>
            <div><dt>Sex</dt><dd>${esc(SEX[dg1.sex] || dg1.sex)}</dd></div>
            <div><dt>Born</dt><dd>${esc(fmtDate(dg11.fullDateOfBirth || mrzDateToISO(dg1.dateOfBirth, 'birth')))}</dd></div>
            <div><dt>Expires</dt><dd>${esc(fmtDate(mrzDateToISO(dg1.dateOfExpiry, 'expiry')))}</dd></div>
          </dl>
        </div>
      </div>
      <div class="mrz-strip">${esc((dg1.lines || []).join('\n'))}</div>
    </article>
    <div class="list-card">
      ${checks.map(([tone, icon, title, sub]) => `<div class="row"><span class="icon-tile ${tone}" aria-hidden="true">${ICON[icon]}</span><span class="row-text"><strong>${esc(title)}</strong><span>${esc(sub)}</span></span></div>`).join('')}
    </div>
    <div class="list-card">
      ${details.map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><span>${esc(v || '—')}</span></div>`).join('')}
    </div>
    <details class="disclosure">
      <summary>Technical details</summary>
      <div class="list-card">${tech.map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><span>${v}</span></div>`).join('')}</div>
    </details>
    <details class="disclosure">
      <summary>APDU log (${state.logLines.length / 2 | 0} commands)</summary>
      <pre class="log-body">${state.logLines.join('\n')}</pre>
    </details>`;
}

function resultJSON() {
  const r = state.lastResult;
  if (!r) return '{}';
  const enc = (b) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(''));
  return JSON.stringify(r, (k, v) => (v instanceof Uint8Array ? { base64: enc(v) } : typeof v === 'function' ? undefined : v), 2);
}
function download() {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([resultJSON()], { type: 'application/json' }));
  a.download = `chip-${state.lastResult?.dataGroups?.DG1?.documentNumber || 'read'}.json`;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
async function copyJSON() {
  const btn = $('btn-copy');
  try { await navigator.clipboard.writeText(resultJSON()); btn.textContent = 'Copied'; } catch { btn.textContent = 'Copy blocked'; }
  setTimeout(() => { btn.textContent = 'Copy JSON'; }, 1600);
}

// ---------------------------------------------------------------- NDEF probes
async function runProbe(kind) {
  const out = $('probe-out');
  out.textContent = 'Waiting for a tag… hold it to the back of the phone.';
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 30000);
    out.textContent = JSON.stringify(kind === 'webnfc' ? await probeWebNfc({ signal: ctrl.signal }) : await probeWebToNative(), null, 2);
  } catch (e) { out.textContent = e.name === 'AbortError' ? 'Timed out without a tag.' : `Error: ${e.message}`; }
}

// ---------------------------------------------------------------- where-to-find tips
const PASSPORT_TIP = `
<svg class="doc-mini" viewBox="0 0 92 62" aria-hidden="true">
  <rect x="1" y="1" width="90" height="60" rx="6" fill="var(--surface-2)" stroke="var(--line)" stroke-width="1.5"/>
  <rect x="6" y="7" width="17" height="21" rx="2" fill="var(--line)"/>
  <rect x="28" y="8" width="40" height="4" rx="2" fill="var(--line)"/><rect x="28" y="16" width="52" height="4" rx="2" fill="var(--line)"/>
  <rect x="4" y="40" width="84" height="17" rx="3" fill="var(--accent-soft)" stroke="var(--accent)" stroke-width="1.2"/>
  <path d="M8 46h76M8 51.5h76" stroke="var(--accent)" stroke-width="2" stroke-dasharray="2.5 1.5"/>
</svg>
<p><strong>Passport:</strong> the MRZ is the two lines at the bottom of the photo page. Line 2 starts with the document number, then the birth date and expiry date.</p>`;
const IDCARD_TIP = `
<svg class="doc-mini" viewBox="0 0 92 62" aria-hidden="true">
  <rect x="1" y="1" width="90" height="60" rx="7" fill="var(--surface-2)" stroke="var(--line)" stroke-width="1.5"/>
  <rect x="7" y="7" width="13" height="10" rx="2" fill="none" stroke="var(--muted)" stroke-width="1.2"/>
  <rect x="4" y="27" width="84" height="30" rx="3" fill="var(--accent-soft)" stroke="var(--accent)" stroke-width="1.2"/>
  <path d="M8 34h76M8 42h76M8 50h76" stroke="var(--accent)" stroke-width="2" stroke-dasharray="2.5 1.5"/>
</svg>
<p><strong>ID card:</strong> the MRZ is the three lines on the back. Line 1 holds the document number, line 2 the birth and expiry dates. A 6-digit CAN on the front works too.</p>`;

// ---------------------------------------------------------------- boot
async function boot() {
  document.querySelectorAll('[data-source]').forEach((b) => b.addEventListener('click', () => setSource(b.dataset.source)));
  document.querySelectorAll('[data-doc]').forEach((b) => b.addEventListener('click', () => setDoc(b.dataset.doc)));
  document.querySelectorAll('[data-access]').forEach((b) => b.addEventListener('click', () => setAccess(b.dataset.access)));
  document.querySelectorAll('[data-go]').forEach((b) => b.addEventListener('click', () => go(b.dataset.go)));
  document.querySelectorAll('[data-back]').forEach((b) => b.addEventListener('click', back));
  $('btn-back').addEventListener('click', back);
  $('btn-about').addEventListener('click', () => go('about'));
  for (const id of ['in-doc', 'in-dob', 'in-doe']) $(id).addEventListener('input', () => { renderKey(); $('key-error').hidden = true; });
  $('in-can').addEventListener('input', () => { $('key-error').hidden = true; });
  $('in-mrz').addEventListener('input', onMrzPaste);
  const next = () => { if (validateKey()) go('prep'); };
  $('btn-key-next').addEventListener('click', next);
  for (const f of ['pane-mrz', 'pane-can']) $(f).addEventListener('submit', (e) => { e.preventDefault(); next(); });
  $('btn-scan').addEventListener('click', scan);
  $('btn-retry').addEventListener('click', () => { state.stack.pop(); scan(); });
  $('btn-cancel').addEventListener('click', back);
  $('btn-copy').addEventListener('click', copyJSON);
  $('btn-download').addEventListener('click', download);
  $('btn-clear').addEventListener('click', () => { state.lastResult = null; reset('doc'); });
  $('btn-webnfc').addEventListener('click', () => runProbe('webnfc'));
  $('btn-wtn').addEventListener('click', () => runProbe('wtn'));
  $('in-csca').addEventListener('change', (e) => importCsca(e.target.files));

  await detectEnvironment();
  setAccess('MRZ');
  renderCscaCount();
  setSource(state.nativeStatus === 'ready' || state.nativeStatus === 'disabled' ? 'native' : 'sim');
  setDoc(state.doc);
  reset('doc');

  if ('serviceWorker' in navigator && location.protocol === 'https:' && !AndroidBridgeTransport.present()) {
    navigator.serviceWorker.register('sw.js').catch(() => { /* not available here */ });
  }
}

boot();
