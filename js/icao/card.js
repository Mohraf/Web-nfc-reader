// Card session: raw transceive + optional secure messaging + file reading helpers.
import { hex } from '../util/bytes.js';
import { readTLVHeader, tlv, readTLV } from '../util/tlv.js';
import { encodeAPDU, CardError } from './apdu.js';

export const AID_EMRTD = Uint8Array.of(0xa0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01);
export const FID = { CardAccess: 0x011c, COM: 0x011e, SOD: 0x011d, DG: (n) => 0x0100 + n };
const MAX_READ = 0xdf; // 223 bytes: safe chunk size under secure messaging with short APDUs

export class Card {
  constructor(transport, { onApdu } = {}) {
    this.transport = transport;
    this.sm = null;
    this.onApdu = onApdu || (() => {});
    this.chunk = MAX_READ;
  }

  /** Send a plain (or SM-protected, if a session is active) command. */
  async transmit(cmd) {
    const plain = encodeAPDU(cmd);
    if (!this.sm) {
      const resp = await this.transport.transceive(plain);
      const r = { data: resp.subarray(0, resp.length - 2), sw: (resp[resp.length - 2] << 8) | resp[resp.length - 1] };
      this.onApdu({ dir: 'C', bytes: plain }); this.onApdu({ dir: 'R', bytes: resp });
      return r;
    }
    const wire = this.sm.wrapCommand(cmd);
    this.onApdu({ dir: 'C', bytes: plain, wire });
    const resp = await this.transport.transceive(wire);
    const r = this.sm.unwrapResponse(resp);
    this.onApdu({ dir: 'R', bytes: Uint8Array.from([...r.data, r.sw >> 8, r.sw & 0xff]), wire: resp });
    return r;
  }

  async selectApplication() {
    const r = await this.transmit({ cla: 0, ins: 0xa4, p1: 0x04, p2: 0x0c, data: AID_EMRTD });
    if (r.sw !== 0x9000) throw new CardError(r.sw, 'SELECT eMRTD application');
  }

  async selectFile(fid) {
    const r = await this.transmit({ cla: 0, ins: 0xa4, p1: 0x02, p2: 0x0c, data: Uint8Array.of(fid >> 8, fid & 0xff) });
    if (r.sw !== 0x9000) throw new CardError(r.sw, `SELECT file ${fid.toString(16).toUpperCase().padStart(4, '0')}`);
  }

  async readBinary(offset, le) {
    if (offset > 0x7fff) {
      // READ BINARY with odd INS (B1) and offset data object for large files
      const off = offset > 0xffff ? [offset >> 16, (offset >> 8) & 0xff, offset & 0xff] : [offset >> 8, offset & 0xff];
      const r = await this.transmit({ cla: 0, ins: 0xb1, p1: 0, p2: 0, data: tlv(0x54, off), le: le + 4 });
      if (r.sw !== 0x9000 && r.sw !== 0x6282) throw new CardError(r.sw, 'READ BINARY (B1)');
      return readTLV(r.data, 0).value;
    }
    const r = await this.transmit({ cla: 0, ins: 0xb0, p1: offset >> 8, p2: offset & 0xff, le });
    if (r.sw !== 0x9000 && r.sw !== 0x6282) throw new CardError(r.sw, `READ BINARY @${offset}`);
    return r.data;
  }

  /** Read a whole TLV-structured EF. Optionally use a short file identifier for the first read. */
  async readFile(fid, { sfi, onProgress } = {}) {
    let head;
    if (sfi !== undefined) {
      const r = await this.transmit({ cla: 0, ins: 0xb0, p1: 0x80 | sfi, p2: 0, le: 8 });
      if (r.sw !== 0x9000 && r.sw !== 0x6282) throw new CardError(r.sw, `READ BINARY SFI ${sfi.toString(16)}`);
      head = r.data;
    } else {
      await this.selectFile(fid);
      head = await this.readBinary(0, 8);
    }
    if (head.length < 2) throw new Error('file too short');
    const h = readTLVHeader(head);
    const total = h.headerLength + h.length;
    const out = new Uint8Array(total);
    out.set(head.subarray(0, Math.min(head.length, total)));
    let off = Math.min(head.length, total);
    while (off < total) {
      const n = Math.min(this.chunk, total - off);
      const part = await this.readBinary(off, n);
      if (!part.length) throw new Error(`chip returned no data at offset ${off}`);
      out.set(part.subarray(0, Math.min(part.length, total - off)), off);
      off += part.length;
      onProgress?.(off / total);
    }
    onProgress?.(1);
    return out;
  }
}

export const hexApdu = (b) => hex(b).replace(/(..)/g, '$1 ').trim();
