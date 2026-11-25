// UI controller. All protocol work lives in js/icao; transports in js/transports.
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
  source: 'sim',
  doc: store.get('doc', 'passport'),
  access: 'MRZ',
  nativeStatus: 'absent',
  busy: false,
  lastResult: null,
  isSample: false,
  logLines: [],
};

const COUNTRIES = { KEN: 'Kenya', UGA: 'Uganda', TZA: 'Tanzania', RWA: 'Rwanda', BDI: 'Burundi', SSD: 'South Sudan', COD: 'DR Congo', SOM: 'Somalia', ETH: 'Ethiopia', D: 'Germany', GBR: 'United Kingdom', USA: 'United States', UTO: 'Utopia (ICAO specimen)' };
const country = (c) => (c ? `${COUNTRIES[c] || c}${COUNTRIES[c] ? ` (${c})` : ''}` : '—');
const SEX = { M: 'Male', F: 'Female', '<': 'Unspecified', X: 'Unspecified' };
const fmtDate = (iso) => {
  const m = /^(\d{4})-?(\d{2})-?(\d{2})$/.exec(iso || '');
  if (!m) return iso || '—';
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
};

// ---------------------------------------------------------------- environment
async function detectEnvironment() {
  state.nativeStatus = AndroidBridgeTransport.present() ? await AndroidBridgeTransport.status() : 'absent';
  const chips = [];
  if (state.nativeStatus === 'ready') chips.push(['ok', 'Phone NFC ready']);
  else if (state.nativeStatus === 'disabled') chips.push(['warn', 'NFC is off']);
  else if (state.nativeStatus === 'unsupported') chips.push(['bad', 'No NFC on this phone']);
  else chips.push(['', 'No APDU bridge']);
  chips.push(webNfcSupported() ? ['ok', 'Web NFC (NDEF only)'] : ['', 'No Web NFC']);
  if (webToNativeAvailable()) chips.push(['ok', 'WebToNative (NDEF only)']);
  $('env').innerHTML = chips.map(([c, t]) => `<span class="chip ${c}">${esc(t)}</span>`).join('');
  $('btn-webnfc').disabled = !webNfcSupported();
  $('btn-wtn').disabled = !webToNativeAvailable();
}

function sourceHint() {
  if (state.source === 'sim') return 'Runs the real protocol against a virtual chip holding fictional specimen data. Use it to try the app anywhere.';
  switch (state.nativeStatus) {
    case 'ready': return 'Hold the document flat against the back of the phone. Passports: open the cover with the chip page (often the back cover). Keep it still until the read finishes.';
    case 'disabled': return 'NFC is turned off. Turn it on in Android settings, then come back.';
    case 'unsupported': return 'This phone has no NFC hardware.';
    default: return 'Reading a real chip needs the Android app shell, because browsers cannot send APDUs to a chip. Use the simulator here, or install the shell from the /android folder of this project.';
  }
}

// ---------------------------------------------------------------- form state
function setSource(src) {
  state.source = src;
  for (const b of document.querySelectorAll('[data-source]')) b.setAttribute('aria-checked', String(b.dataset.source === src));
  $('source-hint').textContent = sourceHint();
  if (src === 'sim') fillSpecimen();
  updateScanButton();
}

function setDoc(doc) {
  state.doc = doc;
  store.set('doc', doc);
  for (const b of document.querySelectorAll('[data-doc]')) b.setAttribute('aria-checked', String(b.dataset.doc === doc));
  $('doc-figure').innerHTML = doc === 'passport' ? PASSPORT_FIG : IDCARD_FIG;
  if (state.source === 'sim') fillSpecimen();
}

function setAccess(mode) {
  state.access = mode;
  for (const b of document.querySelectorAll('[data-access]')) b.setAttribute('aria-selected', String(b.dataset.access === mode));
  $('pane-mrz').hidden = mode !== 'MRZ';
  $('pane-can').hidden = mode !== 'CAN';
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
  const doc = normDocNumber($('in-doc').value).padEnd(9, '<');
  const dob = $('in-dob').value.replace(/\D/g, '');
  const doe = $('in-doe').value.replace(/\D/g, '');
  const part = (v, n) => (v.length === n ? `${esc(v)}<span class="cd">${checkDigit(v)}</span>` : `<span class="empty">${esc(v.padEnd(n, '·'))}·</span>`);
  const docOk = normDocNumber($('in-doc').value).length > 0;
  $('mrz-key').innerHTML = (docOk ? `${esc(doc)}<span class="cd">${checkDigit(doc)}</span>` : '<span class="empty">·········· </span>') + part(dob, 6) + part(doe, 6);
  for (const [id, ok] of [['in-dob', !dob || /^\d{6}$/.test(dob)], ['in-doe', !doe || /^\d{6}$/.test(doe)]]) $(id).setAttribute('aria-invalid', String(!ok));
}

function onMrzPaste() {
  const text = $('in-mrz').value.trim();
  const msg = $('mrz-parse-msg');
  if (!text) { msg.textContent = ''; return; }
  try {
    const m = parseMRZ(text);
    $('in-doc').value = m.documentNumber;
    $('in-dob').value = m.dateOfBirth;
    $('in-doe').value = m.dateOfExpiry;
    renderKey();
    const bad = Object.entries(m.checks).filter(([, v]) => !v).map(([k]) => k);
    msg.textContent = `${m.format} ${m.format === 'TD1' ? 'ID card' : 'document'} recognised${bad.length ? `. Check digit mismatch in: ${bad.join(', ')}. Correct any misread characters.` : ', all check digits valid.'}`;
    if (m.format === 'TD1') setDoc('idcard');
    if (m.format === 'TD3') setDoc('passport');
  } catch (e) {
    msg.textContent = e.message;
  }
}

function updateScanButton() {
  const btn = $('btn-scan');
  const disabled = state.busy || (state.source === 'native' && state.nativeStatus !== 'ready');
  btn.disabled = disabled;
  btn.classList.toggle('busy', state.busy);
  $('btn-scan-label').textContent = state.busy ? 'Reading…' : state.source === 'sim' ? 'Read simulated chip' : 'Read chip';
}

// ---------------------------------------------------------------- progress + log
const PHASES = ['connect', 'access', 'read', 'verify'];
function phaseOf(t) {
  if (/^Waiting/.test(t)) return 'connect';
  if (/^(Reading chip cap|Authenticat|PACE|Chip offers)/.test(t)) return 'access';
  if (/^Reading/.test(t)) return 'read';
  if (/^Verifying/.test(t)) return 'verify';
  if (t === 'Done') return 'done';
  return null;
}
function setPhase(p, failed = false) {
  const idx = p === 'done' ? PHASES.length : PHASES.indexOf(p);
  for (const li of $('steps').children) {
    const i = PHASES.indexOf(li.dataset.step);
    li.className = i < idx ? 'done' : i === idx ? (failed ? 'failed' : 'active') : '';
  }
}
let currentPhase = null;
function onStatus(text, fraction) {
  const p = phaseOf(text);
  if (p) { currentPhase = p; setPhase(p); }
  $('status').classList.remove('error');
  $('status-text').textContent = text;
  $('bar').hidden = fraction === undefined;
  if (fraction !== undefined) $('bar-fill').style.width = `${Math.round(fraction * 100)}%`;
}

function logApdu(e) {
  const tag = e.dir === 'C' ? '>' : '<';
  const plain = hex(e.bytes).replace(/(..)/g, '$1 ').trim();
  const short = plain.length > 120 ? plain.slice(0, 120) + ` … (${e.bytes.length} bytes)` : plain;
  state.logLines.push(`<span class="${e.dir === 'C' ? 'c' : ''}">${tag} ${esc(short)}</span>` + (e.wire ? `\n<span class="w">  wire ${e.wire.length} bytes, secure messaging</span>` : ''));
  if (state.logLines.length > 600) state.logLines.splice(0, state.logLines.length - 600);
  if (!$('log-wrap').hidden) { $('log').innerHTML = state.logLines.join('\n'); $('log').scrollTop = 1e9; }
  $('log-count').textContent = `(${state.logLines.length})`;
}

// ---------------------------------------------------------------- trust anchors
function trustAnchors() {
  const list = [b64decode(DEMO_CSCA_B64), ...store.get('csca', []).map(b64decode)];
  const out = [];
  for (const der of list) { try { out.push(parseCertificateBytes(der)); } catch { /* skip unreadable */ } }
  return out;
}
function renderCscaCount() {
  const n = store.get('csca', []).length;
  $('csca-count').textContent = n ? `${n} added on this device` : 'None added yet';
}
async function importCsca(files) {
  const added = store.get('csca', []);
  for (const f of files) {
    let bytes = new Uint8Array(await f.arrayBuffer());
    const text = new TextDecoder().decode(bytes);
    const pem = text.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g);
    const ders = pem ? pem.map((p) => b64decode(p.replace(/-----[^-]+-----|\s/g, ''))) : [bytes];
    for (const der of ders) {
      try { parseCertificateBytes(der); added.push(btoa(String.fromCharCode(...der))); } catch { /* not a certificate */ }
    }
  }
  store.set('csca', added);
  renderCscaCount();
}

// ---------------------------------------------------------------- scan
async function scan({ sample = false } = {}) {
  if (state.busy) return;
  const access = state.access === 'MRZ'
    ? { type: 'MRZ', documentNumber: $('in-doc').value, dateOfBirth: $('in-dob').value.trim(), dateOfExpiry: $('in-doe').value.trim() }
    : { type: 'CAN', can: $('in-can').value.trim() };

  let transport;
  if (state.source === 'sim') {
    const d = SIM_DOCS.find((x) => x.id === state.doc);
    transport = new SimulatorTransport(d, sample ? { tapDelay: 0, latency: 0 } : {});
  } else {
    transport = new AndroidBridgeTransport();
  }

  state.busy = true; state.logLines = []; currentPhase = 'connect';
  updateScanButton();
  $('log').innerHTML = '';
  $('log-wrap').hidden = !$('opt-log').checked;
  if (!sample) { $('result').innerHTML = ''; $('result-actions').hidden = true; }
  setPhase('connect');
  try {
    const result = await readDocument(transport, {
      access, readPhoto: $('opt-photo').checked, readExtra: $('opt-extra').checked,
      trustAnchors: trustAnchors(), onStatus, onApdu: logApdu,
    });
    state.lastResult = result; state.isSample = sample;
    setPhase('done');
    onStatus(sample
      ? 'Sample read from the simulator. Choose a reader and press Read to run it yourself.'
      : `Done in ${(result.timings.total / 1000).toFixed(1)} s.`);
    renderResult(result, transport);
    if (!sample) navigator.vibrate?.(60);
  } catch (e) {
    setPhase(currentPhase || 'connect', true);
    $('status').classList.add('error');
    $('status-text').textContent = friendlyError(e);
    $('bar').hidden = true;
    try { await transport.disconnect?.(); } catch { /* ignore */ }
  } finally {
    state.busy = false;
    updateScanButton();
    if (!$('log-wrap').hidden || state.logLines.length) { $('log').innerHTML = state.logLines.join('\n'); }
  }
}

function friendlyError(e) {
  const m = e?.message || String(e);
  if (/Authentication failed/.test(m)) return `${m}. The chip refused the key. Re-check the document number and both dates against the MRZ (O vs 0, I vs 1), or use the CAN.`;
  if (/lost|Tag was lost|TagLost/i.test(m)) return 'Connection to the chip was lost. Keep the document still against the phone for the whole read and try again.';
  return m;
}

// ---------------------------------------------------------------- rendering
function renderResult(r, transport) {
  const dg1 = r.dataGroups.DG1 || {};
  const dg11 = r.dataGroups.DG11 || {};
  const dg12 = r.dataGroups.DG12 || {};
  const img = r.dataGroups.DG2?.[0];
  const pa = r.passiveAuth || {};
  const isCard = dg1.format === 'TD1';
  const kind = isCard ? 'National ID card' : dg1.documentCode?.startsWith('P') ? 'Passport' : 'Travel document';

  let photo = '<div class="portrait">No photo read</div>';
  if (img) {
    if (img.mime === 'image/jpeg') {
      const url = URL.createObjectURL(new Blob([img.data], { type: img.mime }));
      photo = `<img class="portrait" src="${url}" alt="Facial image from the chip (DG2)">`;
    } else {
      photo = `<div class="portrait">JPEG 2000 photo (${Math.round(img.data.length / 1024)} KB). This browser can't display it; it is included in the JSON export.</div>`;
    }
  }

  const personal = dg11.personalNumber || dg1.personalNumber || dg1.optionalData1 || '';
  const facts = [
    ['Document no.', dg1.documentNumber],
    ['Nationality', country(dg1.nationality)],
    ['Date of birth', fmtDate(dg11.fullDateOfBirth || mrzDateToISO(dg1.dateOfBirth, 'birth'))],
    ['Sex', SEX[dg1.sex] || dg1.sex],
    ['Date of expiry', fmtDate(mrzDateToISO(dg1.dateOfExpiry, 'expiry'))],
    ['Issuing state', country(dg1.issuingState)],
    ...(personal ? [['Personal no.', personal]] : []),
    ...(dg11.placeOfBirth ? [['Place of birth', dg11.placeOfBirth]] : []),
    ...(dg12.dateOfIssue ? [['Date of issue', fmtDate(dg12.dateOfIssue)]] : []),
    ...(dg12.issuingAuthority ? [['Issued by', dg12.issuingAuthority]] : []),
  ];

  const verdicts = [];
  const a = r.access || {};
  verdicts.push(['ok plain', `${a.protocol}${a.mapping ? ' ' + a.mapping : ''} · ${a.cipher}${a.keyBits ? '-' + a.keyBits : ''}${a.curve ? ' · ' + a.curve : ''}`]);
  if (pa.hashesOk) verdicts.push(['ok', 'Data matches chip signature']);
  else if (pa.dataGroups?.length) verdicts.push(['bad', 'Data hash mismatch']);
  else verdicts.push(['warn', 'Integrity not checked']);
  if (pa.signature === true) verdicts.push(['ok', 'Document signer signature valid']);
  else if (pa.signature === false) verdicts.push(['bad', 'Signer signature invalid']);
  if (pa.csca?.valid) verdicts.push(['ok', 'Issuer certificate trusted']);
  else if (pa.csca && !pa.csca.valid) verdicts.push(['bad', 'Issuer certificate check failed']);
  else verdicts.push(['warn', 'Issuer not verified (no CSCA loaded)']);
  if (!dg1.valid) verdicts.push(['warn', 'MRZ check digit mismatch']);

  const sec = [
    ['Access control', `${a.protocol} using ${a.password === 'CAN' ? 'the CAN' : 'the MRZ'}${r.chip.paceOptions?.length && a.protocol === 'BAC' ? ' (chip also lists PACE options this demo does not support)' : ''}`],
    ['Chip offers', r.chip.paceOptions?.length ? r.chip.paceOptions.map((p) => `PACE ${p.mapping} ${p.cipher}-${p.keyBits}${p.curve ? ' ' + p.curve : ''}`).join('; ') : 'BAC only'],
    ['Data groups on chip', (r.chip.dataGroupsPresent || []).map((n) => `DG${n}`).join(', ') + (r.chip.ldsVersion ? ` · LDS ${r.chip.ldsVersion.replace(/^(\d\d)(\d\d)$/, (m, x, y) => `${+x}.${+y}`)}` : '')],
    ['Hash check', pa.dataGroups?.length ? `<span class="dg-hashes">${pa.dataGroups.map((d) => `<span class="chip ${d.ok ? 'ok' : 'bad'}" title="${esc(DG_NAMES[d.dg] || '')}">DG${d.dg}</span>`).join('')}</span> ${esc(pa.hashAlgorithm || '')}` : '—'],
    ['Document signer', pa.signer ? esc(`${pa.signer.subject} · ${pa.signer.key} · valid ${pa.signer.notBefore} to ${pa.signer.notAfter}`) : '—'],
    ['Issuer (CSCA)', pa.csca ? esc(pa.csca.subject) : esc(pa.signer?.issuer || '—') + ' · not verified'],
  ];
  if (r.dataGroups.DG14) sec.push(['Advanced protocols (DG14)', esc([...new Set(r.dataGroups.DG14.map((x) => x.kind))].join(', ')) + ' · not run in this demo']);
  if (r.dataGroups.DG15) sec.push(['Active Authentication (DG15)', 'Key present · not run in this demo']);
  for (const e of pa.errors || []) sec.push(['Note', esc(e)]);
  const errs = Object.entries(r.dataGroups).filter(([k]) => k.endsWith('Error'));
  for (const [k, v] of errs) sec.push([k.replace('Error', ''), esc(v)]);
  sec.push(['Timing', `${(r.timings.auth / 1000).toFixed(1)} s to unlock · ${(r.timings.total / 1000).toFixed(1)} s total · ${state.logLines.length / 2 | 0} commands`]);

  const sig = r.dataGroups.DG7;
  const sigHtml = sig && sig.mime === 'image/jpeg' ? `<p class="extra-title">Signature (DG7)</p><img src="${URL.createObjectURL(new Blob([sig.data], { type: sig.mime }))}" alt="Holder signature" style="max-height:70px;max-width:100%">` : '';

  $('result').innerHTML = `
    <article class="card-doc">
      <div class="card-doc-head"><span class="kind">${esc(kind)} · ${esc(dg1.format || '')}</span>${state.source === 'sim' ? '<span class="sample">Simulator · fictional specimen</span>' : `<span class="sample">${esc(transport.name)}</span>`}</div>
      <div class="card-doc-body">
        ${photo}
        <div style="min-width:0">
          <h3 class="name"><small>${esc(dg1.surname || '')}</small>${esc(dg1.givenNames || '')}</h3>
          <dl class="facts">${facts.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v || '—')}</dd></div>`).join('')}</dl>
          ${sigHtml}
        </div>
      </div>
      <div class="mrz-block">${esc((dg1.lines || []).join('\n'))}</div>
    </article>
    <div class="verdicts">${verdicts.map(([c, t]) => `<span class="chip ${c}">${esc(t)}</span>`).join('')}</div>
    <div class="sec-list">${sec.map(([k, v]) => `<div class="sec-row"><span>${esc(k)}</span><span>${v}</span></div>`).join('')}</div>`;
  $('result-actions').hidden = false;
}

function resultJSON() {
  const r = state.lastResult;
  if (!r) return '{}';
  const enc = (b) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(''));
  return JSON.stringify(r, (k, v) => {
    if (v instanceof Uint8Array) return { base64: enc(v) };
    if (k === 'get' || typeof v === 'function') return undefined;
    return v;
  }, 2);
}

function download() {
  const blob = new Blob([resultJSON()], { type: 'application/json' });
  const a = document.createElement('a');
  const dg1 = state.lastResult?.dataGroups?.DG1;
  a.href = URL.createObjectURL(blob);
  a.download = `chip-${dg1?.documentNumber || 'read'}.json`;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

async function copyJSON() {
  const btn = $('btn-copy');
  try { await navigator.clipboard.writeText(resultJSON()); btn.textContent = 'Copied'; }
  catch { btn.textContent = 'Copy blocked'; }
  setTimeout(() => { btn.textContent = 'Copy JSON'; }, 1600);
}

function clearResult() {
  state.lastResult = null;
  $('result').innerHTML = '<div class="empty-state">No chip read yet. Fill in the MRZ details or CAN, then press Read.</div>';
  $('result-actions').hidden = true;
  setPhase(null);
  for (const li of $('steps').children) li.className = '';
  onStatus('Ready.');
}

// ---------------------------------------------------------------- NDEF probes
async function runProbe(kind) {
  const out = $('probe-out');
  out.textContent = 'Waiting for a tag… hold it to the back of the phone.';
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 30000);
    const r = kind === 'webnfc' ? await probeWebNfc({ signal: ctrl.signal }) : await probeWebToNative();
    out.textContent = JSON.stringify(r, null, 2);
  } catch (e) {
    out.textContent = e.name === 'AbortError' ? 'Timed out without a tag.' : `Error: ${e.message}`;
  }
}

// ---------------------------------------------------------------- figures
const PASSPORT_FIG = `
<svg viewBox="0 0 140 96" role="img" aria-label="Passport data page with the two MRZ lines at the bottom">
  <rect x="1" y="1" width="138" height="94" rx="5" fill="var(--surface)" stroke="var(--line)" stroke-width="1.5"/>
  <rect x="8" y="12" width="26" height="33" rx="2" fill="var(--line)"/>
  <rect x="40" y="13" width="52" height="4" rx="2" fill="var(--line)"/><rect x="40" y="22" width="70" height="4" rx="2" fill="var(--line)"/>
  <rect x="40" y="31" width="40" height="4" rx="2" fill="var(--line)"/><rect x="40" y="40" width="58" height="4" rx="2" fill="var(--line)"/>
  <rect x="5" y="64" width="130" height="25" rx="3" fill="var(--accent-soft)" stroke="var(--accent)" stroke-width="1.5"/>
  <text x="70" y="74" font-family="var(--font-mono)" font-size="6" fill="var(--accent)" text-anchor="middle">P&lt;KENSURNAME&lt;&lt;GIVEN&lt;NAMES&lt;&lt;&lt;</text>
  <text x="70" y="84" font-family="var(--font-mono)" font-size="6" fill="var(--accent)" text-anchor="middle"><tspan font-weight="700">AK0012345</tspan>4KEN<tspan font-weight="700">900115</tspan>9F<tspan font-weight="700">320301</tspan>…</text>
</svg>
<figcaption><strong>Passport:</strong> copy the document number, date of birth and expiry date from the two MRZ lines at the bottom of the photo page (bold parts).</figcaption>`;

const IDCARD_FIG = `
<svg viewBox="0 0 140 90" role="img" aria-label="ID card back with three MRZ lines">
  <rect x="1" y="1" width="138" height="88" rx="7" fill="var(--surface)" stroke="var(--line)" stroke-width="1.5"/>
  <rect x="10" y="10" width="20" height="16" rx="2.5" fill="none" stroke="var(--muted)" stroke-width="1.2"/>
  <path d="M10 18h20M20 10v16" stroke="var(--muted)" stroke-width="0.8"/>
  <rect x="40" y="12" width="60" height="4" rx="2" fill="var(--line)"/><rect x="40" y="21" width="44" height="4" rx="2" fill="var(--line)"/>
  <rect x="5" y="44" width="130" height="40" rx="3" fill="var(--accent-soft)" stroke="var(--accent)" stroke-width="1.5"/>
  <text x="70" y="55" font-family="var(--font-mono)" font-size="6.4" fill="var(--accent)" text-anchor="middle">IDKEN<tspan font-weight="700">MC0001234</tspan>0&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;</text>
  <text x="70" y="66" font-family="var(--font-mono)" font-size="6.4" fill="var(--accent)" text-anchor="middle"><tspan font-weight="700">850704</tspan>8M<tspan font-weight="700">340704</tspan>1KEN&lt;&lt;&lt;&lt;&lt;</text>
  <text x="70" y="77" font-family="var(--font-mono)" font-size="6.4" fill="var(--accent)" text-anchor="middle">SURNAME&lt;&lt;GIVEN&lt;NAMES&lt;&lt;&lt;</text>
</svg>
<figcaption><strong>ID card:</strong> the MRZ is the three lines on the back. Line 1 holds the document number, line 2 the birth and expiry dates. If the front shows a 6-digit CAN, you can use that instead.</figcaption>`;

// ---------------------------------------------------------------- boot
async function boot() {
  document.querySelectorAll('[data-source]').forEach((b) => b.addEventListener('click', () => setSource(b.dataset.source)));
  document.querySelectorAll('[data-doc]').forEach((b) => b.addEventListener('click', () => setDoc(b.dataset.doc)));
  document.querySelectorAll('[data-access]').forEach((b) => b.addEventListener('click', () => setAccess(b.dataset.access)));
  for (const id of ['in-doc', 'in-dob', 'in-doe']) $(id).addEventListener('input', renderKey);
  $('in-mrz').addEventListener('input', onMrzPaste);
  for (const f of ['pane-mrz', 'pane-can']) $(f).addEventListener('submit', (e) => { e.preventDefault(); scan(); });
  $('btn-scan').addEventListener('click', () => scan());
  $('btn-copy').addEventListener('click', copyJSON);
  $('btn-download').addEventListener('click', download);
  $('btn-clear').addEventListener('click', clearResult);
  $('btn-webnfc').addEventListener('click', () => runProbe('webnfc'));
  $('btn-wtn').addEventListener('click', () => runProbe('wtn'));
  $('in-csca').addEventListener('change', (e) => importCsca(e.target.files));
  $('opt-log').addEventListener('change', () => { $('log-wrap').hidden = !$('opt-log').checked && !state.logLines.length; $('log-wrap').open = $('opt-log').checked; $('log').innerHTML = state.logLines.join('\n'); });
  $('env').innerHTML = '<span class="chip">Checking…</span>';

  await detectEnvironment();
  setDoc(state.doc);
  setAccess('MRZ');
  renderCscaCount();
  if (state.nativeStatus === 'ready' || state.nativeStatus === 'disabled') {
    setSource('native');
    $('in-doc').value = ''; $('in-dob').value = ''; $('in-doe').value = ''; $('in-can').value = '';
    renderKey();
    clearResult();
  } else {
    // No chip access here: open with a finished sample read so the page shows what it does.
    $('src-native').title = 'Needs the Android app shell';
    setSource('sim');
    await scan({ sample: true });
  }

  if ('serviceWorker' in navigator && location.protocol === 'https:' && !AndroidBridgeTransport.present()) {
    navigator.serviceWorker.register('sw.js').catch(() => { /* not available in this context */ });
  }
}

boot();
