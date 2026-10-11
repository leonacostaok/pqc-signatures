// fast-shake.mjs: SHAKE128/SHAKE256 and the XOF128/XOF256 readers on top of the generated
// unrolled Keccak-f[1600] (fast-keccak.mjs), with the same call interface as @noble/hashes'
// shake objects and @noble/post-quantum's XOF readers (so fast-ml-dsa.mjs can use either).
import { keccakP } from './fast-keccak.mjs';
import { u32, swap32IfBE } from '@noble/hashes/utils.js';

class FastShake {
  constructor(rate, outputLen) {
    this.blockLen = rate;
    this.outputLen = outputLen;
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
    this.pos = 0;
    this.posOut = 0;
    this.finished = false;
    this.destroyed = false;
  }
  permute() {
    swap32IfBE(this.state32);
    keccakP(this.state32);
    swap32IfBE(this.state32);
  }
  update(data) {
    const { state, blockLen } = this;
    let pos = this.pos;
    for (let i = 0; i < data.length; i++) {
      state[pos++] ^= data[i];
      if (pos === blockLen) {
        this.permute();
        pos = 0;
      }
    }
    this.pos = pos;
    return this;
  }
  finish() {
    if (this.finished) return;
    this.finished = true;
    this.state[this.pos] ^= 0x1f;
    this.state[this.blockLen - 1] ^= 0x80;
    this.permute();
    this.posOut = 0;
  }
  xofInto(out) {
    this.finish();
    const { state, blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen) {
        this.permute();
        this.posOut = 0;
      }
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(state.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xof(n) {
    return this.xofInto(new Uint8Array(n));
  }
  digestInto(out) {
    return this.xofInto(out);
  }
  digest() {
    return this.xofInto(new Uint8Array(this.outputLen));
  }
  _cloneInto(to) {
    if (!to) to = new FastShake(this.blockLen, this.outputLen);
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.outputLen = this.outputLen;
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
  }
}
const makeShake = (rate, outputLen) => {
  const fn = (data, opts = {}) => new FastShake(rate, opts.dkLen !== undefined ? opts.dkLen : outputLen).update(data).digest();
  fn.create = (opts = {}) => new FastShake(rate, opts.dkLen !== undefined ? opts.dkLen : outputLen);
  fn.blockLen = rate;
  fn.outputLen = outputLen;
  return fn;
};
export const shake128 = makeShake(168, 16);
export const shake256 = makeShake(136, 32);

// XOF readers, same interface as @noble/post-quantum/_crystals.js XOF128/XOF256.
const createXof = (rate) => (seed, blockLen) => {
  if (!blockLen) blockLen = rate;
  const _seed = new Uint8Array(seed.length + 2);
  _seed.set(seed);
  const seedLen = seed.length;
  const buf = new Uint8Array(blockLen);
  const h = new FastShake(rate, blockLen);
  return {
    get: (x, y) => {
      _seed[seedLen] = x;
      _seed[seedLen + 1] = y;
      h.state.fill(0);
      h.pos = 0;
      h.posOut = 0;
      h.finished = false;
      h.update(_seed);
      return () => h.xofInto(buf);
    },
    clean: () => {},
  };
};
export const XOF128 = createXof(168);
export const XOF256 = createXof(136);
