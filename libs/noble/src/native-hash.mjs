// node:crypto-backed drop-in replacements for the @noble/hashes objects used by
// @noble/post-quantum (shake128/shake256/sha256/sha512/hmac + the XOF128/XOF256 readers).
//
// node:crypto has no incremental "squeeze" for SHAKE, so XOF output is produced with a
// fixed outputLength and extended on demand by recomputing with a larger outputLength:
// SHAKE output of length L2 > L1 has the length-L1 output as a prefix, so this is exact.
// Absorbed input is buffered in JS and hashed in one native call (all inputs here are small).
import { createHash, createHmac, hash as oneShotHash } from 'node:crypto';

function grow(h, need) {
  if (h.len + need <= h.buf.length) return;
  let n = h.buf.length * 2;
  while (n < h.len + need) n *= 2;
  const nb = new Uint8Array(n);
  nb.set(h.buf.subarray(0, h.len));
  h.buf = nb;
}

class NativeHash {
  constructor(alg, blockLen, outputLen, isXof) {
    this.alg = alg;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.isXof = isXof;
    this.buf = new Uint8Array(256);
    this.len = 0;
    this.out = null; // squeezed output stream (XOF)
    this.pos = 0; // read position in `out`
    this.finished = false;
    this.destroyed = false;
  }
  update(data) {
    grow(this, data.length);
    this.buf.set(data, this.len);
    this.len += data.length;
    return this;
  }
  _compute(outLen) {
    if (outLen === this.outputLen && !this.isXof) return oneShotHash(this.alg, this.buf.subarray(0, this.len), 'buffer');
    return createHash(this.alg, this.isXof ? { outputLength: outLen } : undefined)
      .update(this.buf.subarray(0, this.len))
      .digest();
  }
  _ensure(n) {
    const need = this.pos + n;
    if (this.out !== null && need <= this.out.length) return;
    let L = this.out === null ? Math.max(need, 2 * this.blockLen) : this.out.length * 2;
    while (L < need) L *= 2;
    this.out = this._compute(L);
    this.finished = true;
  }
  xofInto(out) {
    this._ensure(out.length);
    out.set(this.out.subarray(this.pos, this.pos + out.length));
    this.pos += out.length;
    return out;
  }
  xof(n) {
    return this.xofInto(new Uint8Array(n));
  }
  digestInto(out) {
    const d = this._compute(this.outputLen);
    out.set(d.subarray(0, Math.min(out.length, d.length)));
    this.finished = true;
    return out;
  }
  digest() {
    const d = this._compute(this.outputLen);
    return new Uint8Array(d.buffer, d.byteOffset, d.length);
  }
  _cloneInto(to) {
    if (!to) to = new NativeHash(this.alg, this.blockLen, this.outputLen, this.isXof);
    if (to.buf.length < this.len) to.buf = new Uint8Array(this.buf.length);
    to.buf.set(this.buf.subarray(0, this.len));
    to.len = this.len;
    to.out = null;
    to.pos = 0;
    to.finished = false;
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

function makeHasher(alg, blockLen, outputLen, isXof) {
  const fn = (data, opts = {}) => {
    const dk = opts.dkLen !== undefined ? opts.dkLen : outputLen;
    return new NativeHash(alg, blockLen, dk, isXof).update(data).digest();
  };
  fn.create = (opts = {}) => new NativeHash(alg, blockLen, opts.dkLen !== undefined ? opts.dkLen : outputLen, isXof);
  fn.blockLen = blockLen;
  fn.outputLen = outputLen;
  fn.nativeName = alg;
  return fn;
}

export const shake128 = makeHasher('shake128', 168, 16, true);
export const shake256 = makeHasher('shake256', 136, 32, true);
export const sha256 = makeHasher('sha256', 64, 32, false);
export const sha512 = makeHasher('sha512', 128, 64, false);

class NativeHmac {
  constructor(h, key) {
    this.h = createHmac(h.nativeName, key);
    this.outputLen = h.outputLen;
    this.blockLen = h.blockLen;
  }
  update(d) {
    this.h.update(d);
    return this;
  }
  digest() {
    const d = this.h.digest();
    return new Uint8Array(d.buffer, d.byteOffset, d.length);
  }
  digestInto(out) {
    out.set(this.h.digest().subarray(0, out.length));
    return out;
  }
  destroy() {}
}
export const hmac = (h, key, msg) => new NativeHmac(h, key).update(msg).digest();
hmac.create = (h, key) => new NativeHmac(h, key);

// XOF readers with the same interface as @noble/post-quantum/_crystals.js XOF128/XOF256:
// get(x, y) rebinds to seed||x||y and returns a reader () => next block (a view, like noble).
const createXofNative = (alg, defaultBlockLen) => (seed, blockLen) => {
  if (!blockLen) blockLen = defaultBlockLen;
  const _seed = new Uint8Array(seed.length + 2);
  _seed.set(seed);
  const seedLen = seed.length;
  // Initial squeeze guess: RejNTTPoly needs >= 768 B (5 SHAKE128 blocks), RejBoundedPoly ~2-3
  // SHAKE256 blocks; ExpandMask reads exactly one (large) block.
  const guess = blockLen >= 500 ? 1 : alg === 'shake128' ? 5 : 3;
  let out = null;
  let pos = 0;
  let calls = 0;
  let xofs = 0;
  const squeeze = (L) => createHash(alg, { outputLength: L }).update(_seed).digest();
  return {
    stats: () => ({ calls, xofs }),
    get: (x, y) => {
      _seed[seedLen] = x;
      _seed[seedLen + 1] = y;
      calls++;
      out = squeeze(guess * blockLen);
      pos = 0;
      return () => {
        xofs++;
        if (pos + blockLen > out.length) out = squeeze(out.length * 2);
        const b = out.subarray(pos, pos + blockLen);
        pos += blockLen;
        return b;
      };
    },
    clean: () => {},
  };
};
export const XOF128 = createXofNative('shake128', 168);
export const XOF256 = createXofNative('shake256', 136);
