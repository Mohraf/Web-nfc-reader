// ISO 7816-4 command APDU encoding and status word descriptions.
import { concat, hex } from '../util/bytes.js';

/**
 * Build a command APDU. `le` is the expected response length (1..65536, 256 → short 0x00,
 * undefined → no Le). Extended length is used automatically when needed.
 */
export function encodeAPDU({ cla, ins, p1, p2, data, le }) {
  const hdr = Uint8Array.of(cla, ins, p1, p2);
  const lc = data ? data.length : 0;
  const ext = lc > 255 || (le !== undefined && le > 256);
  if (!ext) {
    return concat(hdr, lc ? concat([lc], data) : [], le !== undefined ? [le === 256 ? 0 : le] : []);
  }
  const leBytes = le === undefined ? [] : (le === 65536 ? [0, 0] : [le >> 8, le & 0xff]);
  return concat(hdr, [0], lc ? concat([lc >> 8, lc & 0xff], data) : [], lc ? leBytes : concat([0], leBytes));
}

export const swOf = (resp) => (resp[resp.length - 2] << 8) | resp[resp.length - 1];

const SW = {
  0x9000: 'OK',
  0x6282: 'End of file reached before Le bytes',
  0x6300: 'Authentication failed — check the document number, dates or CAN',
  0x6700: 'Wrong length',
  0x6881: 'Logical channel not supported',
  0x6882: 'Secure messaging not supported',
  0x6982: 'Security status not satisfied (access denied)',
  0x6983: 'Authentication method blocked',
  0x6984: 'Reference data not usable',
  0x6985: 'Conditions of use not satisfied',
  0x6986: 'Command not allowed',
  0x6987: 'Secure messaging data objects missing',
  0x6988: 'Secure messaging data objects incorrect',
  0x6A80: 'Incorrect data field',
  0x6A82: 'File or application not found',
  0x6A86: 'Incorrect P1/P2',
  0x6A88: 'Referenced data not found',
  0x6B00: 'Wrong parameters (offset outside file)',
  0x6D00: 'Instruction not supported',
  0x6E00: 'Class not supported',
};

export function describeSW(sw) {
  if ((sw & 0xfff0) === 0x63c0) return `Authentication failed, ${sw & 0xf} tries left`;
  return SW[sw] || 'Unknown status';
}

export class CardError extends Error {
  constructor(sw, context) {
    super(`${context}: ${describeSW(sw)} (SW ${hex(Uint8Array.of(sw >> 8, sw & 0xff))})`);
    this.sw = sw;
  }
}
