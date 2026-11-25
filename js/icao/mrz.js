// MRZ helpers: check digits, BAC/PACE key material, and TD1/TD2/TD3 parsing (ICAO 9303 Parts 3-5).

const val = (c) => {
  if (c >= '0' && c <= '9') return c.charCodeAt(0) - 48;
  if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 55;
  return 0; // '<' and anything else
};

export function checkDigit(s) {
  const w = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < s.length; i++) sum += val(s[i]) * w[i % 3];
  return String(sum % 10);
}

export const normDocNumber = (s) => s.toUpperCase().replace(/[^A-Z0-9]/g, '');

/** "MRZ_information" used as BAC seed / PACE password (ICAO 9303-11 §9.7.1 / §4.4.3.3). */
export function mrzKeyString({ documentNumber, dateOfBirth, dateOfExpiry }) {
  let doc = normDocNumber(documentNumber);
  if (!doc) throw new Error('Document number is required');
  if (!/^\d{6}$/.test(dateOfBirth)) throw new Error('Date of birth must be YYMMDD');
  if (!/^\d{6}$/.test(dateOfExpiry)) throw new Error('Date of expiry must be YYMMDD');
  const docField = doc.padEnd(9, '<');
  return docField + checkDigit(docField) + dateOfBirth + checkDigit(dateOfBirth) + dateOfExpiry + checkDigit(dateOfExpiry);
}

const clean = (s) => s.replace(/<+$/g, '').replace(/</g, ' ').trim();

function names(field) {
  const [primary, secondary = ''] = field.split('<<');
  return { surname: clean(primary), givenNames: clean(secondary) };
}

function check(value, digit) { return checkDigit(value) === digit; }

/**
 * Parse MRZ text (DG1 content or user-pasted lines). Returns fields + check-digit results.
 * Supports TD1 (3x30, ID cards e.g. Kenya Maisha card), TD2 (2x36) and TD3 (2x44, passports).
 */
export function parseMRZ(text) {
  const raw = text.toUpperCase().replace(/[^A-Z0-9<\n]/g, '');
  let lines = raw.split('\n').filter(Boolean);
  if (lines.length === 1) {
    const s = lines[0];
    if (s.length === 90) lines = [s.slice(0, 30), s.slice(30, 60), s.slice(60)];
    else if (s.length === 88) lines = [s.slice(0, 44), s.slice(44)];
    else if (s.length === 72) lines = [s.slice(0, 36), s.slice(36)];
  }
  const L = lines.map((l) => l.trim());
  let r;
  if (L.length === 3 && L.every((l) => l.length === 30)) {
    const [a, b, c] = L;
    let docNo = a.slice(5, 14), docCd = a.slice(14, 15), optional1 = a.slice(15, 30);
    if (docCd === '<') { // long document number continues in optional data
      const ext = optional1.replace(/<.*$/, '');
      docNo = docNo + ext.slice(0, -1); docCd = ext.slice(-1); optional1 = optional1.slice(ext.length + 1);
    }
    r = { format: 'TD1', documentCode: clean(a.slice(0, 2)), issuingState: clean(a.slice(2, 5)),
      documentNumber: docNo.replace(/</g, ''), optionalData1: clean(optional1),
      dateOfBirth: b.slice(0, 6), sex: b[7], dateOfExpiry: b.slice(8, 14), nationality: clean(b.slice(15, 18)),
      optionalData2: clean(b.slice(18, 29)), ...names(c),
      checks: { documentNumber: check(docNo, docCd), dateOfBirth: check(b.slice(0, 6), b[6]), dateOfExpiry: check(b.slice(8, 14), b[14]),
        composite: check(a.slice(5, 30) + b.slice(0, 7) + b.slice(8, 15) + b.slice(18, 29), b[29]) } };
  } else if (L.length === 2 && L.every((l) => l.length === 44)) {
    const [a, b] = L;
    r = { format: 'TD3', documentCode: clean(a.slice(0, 2)), issuingState: clean(a.slice(2, 5)), ...names(a.slice(5)),
      documentNumber: b.slice(0, 9).replace(/</g, ''), nationality: clean(b.slice(10, 13)), dateOfBirth: b.slice(13, 19),
      sex: b[20], dateOfExpiry: b.slice(21, 27), personalNumber: clean(b.slice(28, 42)),
      checks: { documentNumber: check(b.slice(0, 9), b[9]), dateOfBirth: check(b.slice(13, 19), b[19]), dateOfExpiry: check(b.slice(21, 27), b[27]),
        personalNumber: b[42] === '<' ? /^<*$/.test(b.slice(28, 42)) : check(b.slice(28, 42), b[42]),
        composite: check(b.slice(0, 10) + b.slice(13, 20) + b.slice(21, 43), b[43]) } };
  } else if (L.length === 2 && L.every((l) => l.length === 36)) {
    const [a, b] = L;
    r = { format: 'TD2', documentCode: clean(a.slice(0, 2)), issuingState: clean(a.slice(2, 5)), ...names(a.slice(5)),
      documentNumber: b.slice(0, 9).replace(/</g, ''), nationality: clean(b.slice(10, 13)), dateOfBirth: b.slice(13, 19),
      sex: b[20], dateOfExpiry: b.slice(21, 27), optionalData1: clean(b.slice(28, 35)),
      checks: { documentNumber: check(b.slice(0, 9), b[9]), dateOfBirth: check(b.slice(13, 19), b[19]), dateOfExpiry: check(b.slice(21, 27), b[27]),
        composite: check(b.slice(0, 10) + b.slice(13, 20) + b.slice(21, 35), b[35]) } };
  } else {
    throw new Error('Unrecognised MRZ: expected 3x30 (ID card), 2x36 or 2x44 (passport) characters');
  }
  r.lines = L;
  r.valid = Object.values(r.checks).every(Boolean);
  return r;
}

/** YYMMDD → ISO date. Birth dates in the future roll back a century; expiry dates assume 20xx. */
export function mrzDateToISO(yymmdd, kind = 'birth') {
  if (!/^\d{6}$/.test(yymmdd)) return yymmdd;
  const yy = +yymmdd.slice(0, 2), now = new Date().getFullYear() % 100;
  const century = kind === 'birth' ? (yy > now ? 1900 : 2000) : (yy >= 70 ? 1900 : 2000);
  return `${century + yy}-${yymmdd.slice(2, 4)}-${yymmdd.slice(4, 6)}`;
}
