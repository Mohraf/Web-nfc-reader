// Transport backed by the in-memory VirtualChip — lets you exercise the full protocol anywhere.
import { chipFromSimDoc } from '../sim/virtual-chip.js';

const b64decode = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class SimulatorTransport {
  constructor(simDoc, { tapDelay = 900, latency = 12 } = {}) {
    this.simDoc = simDoc;
    this.tapDelay = tapDelay;
    this.latency = latency;
    this.name = 'Simulator';
  }
  static async isAvailable() { return true; }
  async connect() {
    this.chip = chipFromSimDoc(this.simDoc, b64decode);
    await sleep(this.tapDelay);
    return { technology: 'IsoDep (simulated)', uid: 'random (08…)', maxTransceiveLength: 261, extendedLength: false };
  }
  async transceive(apdu) {
    if (!this.chip) throw new Error('not connected');
    if (this.latency) await sleep(this.latency);
    return this.chip.process(apdu);
  }
  async disconnect() { this.chip = null; }
}

export { b64decode };
