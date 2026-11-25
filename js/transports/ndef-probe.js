// NDEF-only probes. These CANNOT read passport / ID chips (no APDU access) — they exist to show
// what Web NFC and the WebToNative NFC add-on actually return, and to check the phone's NFC works.

export function webNfcSupported() { return 'NDEFReader' in globalThis; }

/** Web NFC (Chrome on Android, HTTPS, top-level page). Resolves with serial number + records. */
export async function probeWebNfc({ signal } = {}) {
  const reader = new globalThis.NDEFReader();
  await reader.scan({ signal });
  return new Promise((resolve, reject) => {
    reader.onreadingerror = () => resolve({ source: 'Web NFC', serialNumber: null, records: [], note: 'Tag detected but it has no NDEF data. This is what a passport or ID chip looks like to Web NFC.' });
    reader.onreading = (e) => {
      const records = [...e.message.records].map((r) => {
        let data = '';
        try { data = r.recordType === 'text' || r.recordType === 'url' ? new TextDecoder(r.encoding || 'utf-8').decode(r.data) : `${r.data?.byteLength ?? 0} bytes`; } catch { /* binary */ }
        return { recordType: r.recordType, mediaType: r.mediaType, data };
      });
      resolve({ source: 'Web NFC', serialNumber: e.serialNumber, records });
    };
    signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
  });
}

export function webToNativeAvailable() { return !!(globalThis.WTN && globalThis.WTN.NFC); }

/** WebToNative NFC add-on (`WTN.NFC.read`). Returns the tag's text payload only. */
export function probeWebToNative() {
  return new Promise((resolve) => {
    globalThis.WTN.NFC.read({
      message: 'Hold the tag near the phone',
      callback: (r) => resolve({ source: 'WebToNative', ...r }),
    });
  });
}
