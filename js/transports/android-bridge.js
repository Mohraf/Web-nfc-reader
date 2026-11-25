// Transport for the thin Android WebView shell in /android.
//
// The shell injects `window.NfcBridgeNative` with androidx.webkit's WebMessageListener, which is
// only exposed to origins on the shell's allow-list (never to arbitrary sites). Messages are JSON:
//   page → native: {id, cmd: 'status' | 'start' | 'stop' | 'transceive' | 'settings', apdu?: hex}
//   native → page: {id, ok: true, result} | {id, ok: false, error}
//                  {event: 'tag', info: {...}} | {event: 'tagLost'} | {event: 'error', message}
import { hex, fromHex } from '../util/bytes.js';

const pending = new Map();
let tagWaiter = null;
let seq = 0;
let installed = false;

function native() { return globalThis.NfcBridgeNative; }

function install() {
  if (installed || !native()) return;
  installed = true;
  native().onmessage = (ev) => {
    let m;
    try { m = JSON.parse(ev.data); } catch { return; }
    if (m.event === 'tag') { tagWaiter?.resolve(m.info); tagWaiter = null; return; }
    if (m.event === 'tagLost') {
      for (const [, p] of pending) p.reject(new Error('Connection to the chip was lost. Keep the document still against the phone and try again.'));
      pending.clear();
      return;
    }
    if (m.event === 'error') { tagWaiter?.reject(new Error(m.message)); tagWaiter = null; return; }
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    m.ok ? p.resolve(m.result) : p.reject(new Error(m.error || 'native error'));
  };
}

function call(cmd, extra = {}) {
  install();
  const id = String(++seq);
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    native().postMessage(JSON.stringify({ id, cmd, ...extra }));
  });
}

export class AndroidBridgeTransport {
  constructor() { this.name = 'Phone NFC (Android shell)'; install(); }

  static present() { return !!native(); }

  /** 'ready' | 'disabled' | 'unsupported' | 'absent' */
  static async status() {
    if (!native()) return 'absent';
    try { return await call('status'); } catch { return 'unsupported'; }
  }

  static openSettings() { if (native()) call('settings').catch(() => {}); }

  connect({ timeoutMs = 90000 } = {}) {
    return new Promise((resolve, reject) => {
      tagWaiter = { resolve, reject };
      call('start').catch(reject);
      setTimeout(() => {
        if (tagWaiter) { tagWaiter = null; call('stop').catch(() => {}); reject(new Error('No document detected. Hold it flat against the back of the phone, near the camera, and try again.')); }
      }, timeoutMs);
    });
  }

  async transceive(apdu) { return fromHex(await call('transceive', { apdu: hex(apdu) })); }

  async disconnect() { try { await call('stop'); } catch { /* ignore */ } }
}
