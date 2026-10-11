// fast-slh-dsa.mjs: a pure-JS rewrite of the hot paths of @noble/post-quantum's SLH-DSA
// (FIPS 205), used by the "fastjs" / "allin" variants. Byte-compatible with noble (checked
// against common/reference.json at every run). What changed versus noble's slh-dsa.js:
//   - Tweakable hashes F / H / PRF are computed by calling the compression function directly
//     on a pre-padded block: for SHA2 the block `ADRSc || M || pad` is filled into a fixed buffer
//     and `_SHA256.process()` / `_SHA512.process()` is run from the cached `PK.seed || 0..`
//     midstate (no update()/digestInto()/clone(), no length bookkeeping); for SHAKE the 200-byte
//     sponge state is reset from the cached `PK.seed` state and `keccakP()` is invoked once.
//     Everything else (T_l over WOTS public keys, FORS roots, Hmsg, PRFmsg) uses the generic path.
//   - ADRS words are written through small offset helpers instead of noble's setAddr({...})
//     (which allocates an options object and does 8 Object.hasOwn checks per call).
//   - Tree walks hash in place from/into fixed buffers (no per-node subarray views, no
//     per-call output copies).
// A "native" lane (NOBLE_PQ_HASH=native) replaces the compression-function calls with one-shot
// node:crypto hashes of the full input, for the "allin" variant.
import { _SHA256, _SHA512, sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2.js';
import { keccakP, shake256 as nobleShake256 } from '@noble/hashes/sha3.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { u32, swap32IfBE } from '@noble/hashes/utils.js';
import { createHash, createHmac, hash as oneShot } from 'node:crypto';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { getMessage, splitCoder, vecCoder, equalBytes, getMask } from '@noble/post-quantum/utils.js';
import { PARAMS } from '@noble/post-quantum/slh-dsa.js';
import { HASH_BACKEND } from './hashlayer.mjs';

const NATIVE = HASH_BACKEND === 'native';
const AddressType = { WOTS: 0, WOTSPK: 1, HASHTREE: 2, FORSTREE: 3, FORSPK: 4, WOTSPRF: 5, FORSPRF: 6 };

const base2b = (outLen, b) => {
  const mask = getMask(b);
  return (bytes) => {
    const baseB = new Uint32Array(outLen);
    for (let out = 0, pos = 0, bits = 0, total = 0; out < outLen; out++) {
      while (bits < b) {
        total = (total << 8) | bytes[pos++];
        bits += 8;
      }
      bits -= b;
      baseB[out] = (total >>> bits) & mask;
    }
    return baseB;
  };
};
const _1n = BigInt(1);
const getMaskBig = (bits) => (_1n << BigInt(bits)) - _1n;

// ---------------------------------------------------------------------------------------------
// Hash lanes. Each lane returns, for a given (pkSeed, skSeed?), an object with:
//   F(addr, inp, inOff, out, outOff)   out[outOff..+N] = F(PK.seed, ADRS, inp[inOff..+N])
//   H(addr, inp, inOff, out, outOff)   same with a 2N-byte input
//   T(addr, inp, len, out, outOff)     generic T_l over `len` bytes
//   PRF(addr, out, outOff)             out[outOff..+N] = PRF(PK.seed, SK.seed, ADRS)
//   PRFmsg(skPRF, optRand, msg) -> Uint8Array(N);  Hmsg(R, pk, msg, outLen) -> Uint8Array
// ---------------------------------------------------------------------------------------------
function wordsOut256(h, out, outOff, N) {
  const w = [h.A, h.B, h.C, h.D, h.E, h.F, h.G, h.H];
  for (let i = 0, o = outOff; i < N; i += 4, o += 4) {
    const v = w[i >> 2];
    out[o] = v >>> 24;
    out[o + 1] = (v >>> 16) & 0xff;
    out[o + 2] = (v >>> 8) & 0xff;
    out[o + 3] = v & 0xff;
  }
}
function wordsOut512(h, out, outOff, N) {
  const w = [h.Ah, h.Al, h.Bh, h.Bl, h.Ch, h.Cl, h.Dh, h.Dl];
  for (let i = 0, o = outOff; i < N; i += 4, o += 4) {
    const v = w[i >> 2];
    out[o] = v >>> 24;
    out[o + 1] = (v >>> 16) & 0xff;
    out[o + 2] = (v >>> 8) & 0xff;
    out[o + 3] = v & 0xff;
  }
}
// One pre-padded single-block SHA-2 "slot": fixed buffer, padding written once.
function padSlot(blockLen, prefixLen, msgLen) {
  const blk = new Uint8Array(blockLen);
  blk[msgLen] = 0x80;
  const bits = (prefixLen + msgLen) * 8; // < 2^32 here
  const view = new DataView(blk.buffer);
  view.setUint32(blockLen - 4, bits >>> 0, false);
  return { blk, view };
}

// SHA2 lane (FIPS 205 §11.2): h0 = SHA-256 for F/PRF (and H/T for n=16), h1 = SHA-256 or SHA-512.
const genSha2Lane = (useSha512) => (opts) => (pubSeed, skSeed) => {
  const { N } = opts;
  const ADDR = 22;
  // --- SHA-256 lane (F, PRF; also H and T_l for the 128-bit sets)
  const h256 = new _SHA256();
  const mid256 = (() => {
    const t = new _SHA256();
    t.update(pubSeed).update(new Uint8Array(64 - N));
    return [t.A, t.B, t.C, t.D, t.E, t.F, t.G, t.H];
  })();
  const slotF = padSlot(64, 64, ADDR + N); // F and PRF inputs: ADRSc || N bytes
  const slotH256 = padSlot(64, 64, ADDR + 2 * N); // H for n=16 (22+32 = 54 <= 55)
  const noble256mid = nobleSha256.create().update(pubSeed).update(new Uint8Array(64 - N));
  const noble256tmp = noble256mid.clone();
  const tmp32 = new Uint8Array(32);
  const run256 = (slot, out, outOff) => {
    const m = mid256;
    h256.set(m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]);
    h256.process(slot.view, 0);
    wordsOut256(h256, out, outOff, N);
  };
  // --- SHA-512 lane (H and T_l for the 192/256-bit sets)
  let run512 = null;
  let slotH512 = null;
  let noble512mid = null;
  let noble512tmp = null;
  const tmp64 = new Uint8Array(64);
  if (useSha512) {
    const h512 = new _SHA512();
    const t = new _SHA512();
    t.update(pubSeed).update(new Uint8Array(128 - N));
    const m = [t.Ah, t.Al, t.Bh, t.Bl, t.Ch, t.Cl, t.Dh, t.Dl, t.Eh, t.El, t.Fh, t.Fl, t.Gh, t.Gl, t.Hh, t.Hl];
    slotH512 = padSlot(128, 128, ADDR + 2 * N);
    noble512mid = nobleSha512.create().update(pubSeed).update(new Uint8Array(128 - N));
    noble512tmp = noble512mid.clone();
    run512 = (slot, out, outOff) => {
      h512.set(m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15]);
      h512.process(slot.view, 0);
      wordsOut512(h512, out, outOff, N);
    };
  }
  const hBig = useSha512 ? nobleSha512 : nobleSha256;
  const counterB = new Uint8Array(4);
  const counterV = new DataView(counterB.buffer);
  function mgf1(seed, length, hash) {
    const out = new Uint8Array(Math.ceil(length / hash.outputLen) * hash.outputLen);
    for (let counter = 0, o = out; o.length; counter++) {
      counterV.setUint32(0, counter, false);
      hash.create().update(seed).update(counterB).digestInto(o);
      o = o.subarray(hash.outputLen);
    }
    return out.subarray(0, length);
  }
  const lane = {
    F: (addr, inp, inOff, out, outOff) => {
      const b = slotF.blk;
      b.set(addr);
      for (let i = 0; i < N; i++) b[ADDR + i] = inp[inOff + i];
      run256(slotF, out, outOff);
    },
    PRF: (addr, out, outOff) => {
      const b = slotF.blk;
      b.set(addr);
      b.set(skSeed, ADDR);
      run256(slotF, out, outOff);
    },
    H: useSha512
      ? (addr, inp, inOff, out, outOff) => {
          const b = slotH512.blk;
          b.set(addr);
          for (let i = 0; i < 2 * N; i++) b[ADDR + i] = inp[inOff + i];
          run512(slotH512, out, outOff);
        }
      : (addr, inp, inOff, out, outOff) => {
          const b = slotH256.blk;
          b.set(addr);
          for (let i = 0; i < 2 * N; i++) b[ADDR + i] = inp[inOff + i];
          run256(slotH256, out, outOff);
        },
    T: useSha512
      ? (addr, inp, len, out, outOff) => {
          noble512mid._cloneInto(noble512tmp).update(addr).update(inp.subarray(0, len)).digestInto(tmp64);
          for (let i = 0; i < N; i++) out[outOff + i] = tmp64[i];
        }
      : (addr, inp, len, out, outOff) => {
          noble256mid._cloneInto(noble256tmp).update(addr).update(inp.subarray(0, len)).digestInto(tmp32);
          for (let i = 0; i < N; i++) out[outOff + i] = tmp32[i];
        },
    PRFmsg: (skPRF, random, msg) => nobleHmac.create(hBig, skPRF).update(random).update(msg).digest().subarray(0, N),
    Hmsg: (R, pk, m, outLen) => {
      const inner = hBig.create().update(R.subarray(0, N)).update(pk).update(m).digest();
      const seed = new Uint8Array(2 * N + inner.length);
      seed.set(R.subarray(0, N));
      seed.set(pk.subarray(0, N), N);
      seed.set(inner, 2 * N);
      return mgf1(seed, outLen, hBig);
    },
  };
  if (NATIVE) {
    // one-shot OpenSSL hashes over the full (prefix || ADRSc || M) input
    const alg1 = useSha512 ? 'sha512' : 'sha256';
    const pre256 = new Uint8Array(64 + ADDR + 2 * N);
    pre256.set(pubSeed);
    const preBig = new Uint8Array(128 + ADDR + 2 * N);
    preBig.set(pubSeed);
    const one = (alg, buf, len, out, outOff) => {
      const d = oneShot(alg, buf.subarray(0, len), 'buffer');
      for (let i = 0; i < N; i++) out[outOff + i] = d[i];
    };
    lane.F = (addr, inp, inOff, out, outOff) => {
      pre256.set(addr, 64);
      for (let i = 0; i < N; i++) pre256[64 + ADDR + i] = inp[inOff + i];
      one('sha256', pre256, 64 + ADDR + N, out, outOff);
    };
    lane.PRF = (addr, out, outOff) => {
      pre256.set(addr, 64);
      pre256.set(skSeed, 64 + ADDR);
      one('sha256', pre256, 64 + ADDR + N, out, outOff);
    };
    lane.H = useSha512
      ? (addr, inp, inOff, out, outOff) => {
          preBig.set(addr, 128);
          for (let i = 0; i < 2 * N; i++) preBig[128 + ADDR + i] = inp[inOff + i];
          one('sha512', preBig, 128 + ADDR + 2 * N, out, outOff);
        }
      : (addr, inp, inOff, out, outOff) => {
          pre256.set(addr, 64);
          for (let i = 0; i < 2 * N; i++) pre256[64 + ADDR + i] = inp[inOff + i];
          one('sha256', pre256, 64 + ADDR + 2 * N, out, outOff);
        };
    lane.T = (addr, inp, len, out, outOff) => {
      const d = createHash(alg1)
        .update(pubSeed)
        .update(new Uint8Array((useSha512 ? 128 : 64) - N))
        .update(addr)
        .update(inp.subarray(0, len))
        .digest();
      for (let i = 0; i < N; i++) out[outOff + i] = d[i];
    };
    lane.PRFmsg = (skPRF, random, msg) => new Uint8Array(createHmac(alg1, skPRF).update(random).update(msg).digest().subarray(0, N));
    lane.Hmsg = (R, pk, m, outLen) => {
      const inner = createHash(alg1).update(R.subarray(0, N)).update(pk).update(m).digest();
      const seed = new Uint8Array(2 * N + inner.length);
      seed.set(R.subarray(0, N));
      seed.set(pk.subarray(0, N), N);
      seed.set(inner, 2 * N);
      const hLen = useSha512 ? 64 : 32;
      const out = new Uint8Array(Math.ceil(outLen / hLen) * hLen);
      for (let counter = 0, o = 0; o < out.length; counter++, o += hLen) {
        counterV.setUint32(0, counter, false);
        out.set(createHash(alg1).update(seed).update(counterB).digest(), o);
      }
      return out.subarray(0, outLen);
    };
  }
  return lane;
};

// SHAKE lane (FIPS 205 §11.1): everything is SHAKE256(PK.seed || ADRS || M).
const genShakeLane = () => (opts) => (pubSeed, skSeed) => {
  const { N } = opts;
  const ADDR = 32;
  const RATE = 136;
  const state = new Uint8Array(200);
  const state32 = u32(state);
  const mid = new Uint8Array(200);
  mid.set(pubSeed);
  const permute = () => {
    swap32IfBE(state32);
    keccakP(state32, 24);
    swap32IfBE(state32);
  };
  // single-block absorb of PK.seed || ADRS || M (N + 32 + len <= 135), one permutation
  const single = (addr, inp, inOff, len, out, outOff) => {
    state.set(mid);
    state.set(addr, N);
    const base = N + ADDR;
    for (let i = 0; i < len; i++) state[base + i] = inp[inOff + i];
    state[base + len] ^= 0x1f;
    state[RATE - 1] ^= 0x80;
    permute();
    for (let i = 0; i < N; i++) out[outOff + i] = state[i];
  };
  // generic sponge for longer inputs / outputs
  const sponge = (parts, out, outOff, outLen) => {
    state.fill(0);
    let pos = 0;
    for (const part of parts) {
      for (let i = 0; i < part.length; i++) {
        state[pos++] ^= part[i];
        if (pos === RATE) {
          permute();
          pos = 0;
        }
      }
    }
    state[pos] ^= 0x1f;
    state[RATE - 1] ^= 0x80;
    permute();
    for (let o = 0; o < outLen; ) {
      const take = Math.min(RATE, outLen - o);
      for (let i = 0; i < take; i++) out[outOff + o + i] = state[i];
      o += take;
      if (o < outLen) permute();
    }
  };
  const lane = {
    F: (addr, inp, inOff, out, outOff) => single(addr, inp, inOff, N, out, outOff),
    H: (addr, inp, inOff, out, outOff) => single(addr, inp, inOff, 2 * N, out, outOff),
    PRF: (addr, out, outOff) => single(addr, skSeed, 0, N, out, outOff),
    T: (addr, inp, len, out, outOff) => sponge([pubSeed, addr, inp.subarray(0, len)], out, outOff, N),
    PRFmsg: (skPRF, random, msg) => {
      const out = new Uint8Array(N);
      sponge([skPRF, random, msg], out, 0, N);
      return out;
    },
    Hmsg: (R, pk, m, outLen) => {
      const out = new Uint8Array(outLen);
      sponge([R.subarray(0, N), pk, m], out, 0, outLen);
      return out;
    },
  };
  if (NATIVE) {
    const pre = new Uint8Array(N + ADDR + 2 * N);
    pre.set(pubSeed);
    const one = (len, out, outOff) => {
      const d = oneShot('shake256', pre.subarray(0, len), 'buffer'); // 32-byte default output, N <= 32
      for (let i = 0; i < N; i++) out[outOff + i] = d[i];
    };
    lane.F = (addr, inp, inOff, out, outOff) => {
      pre.set(addr, N);
      for (let i = 0; i < N; i++) pre[N + ADDR + i] = inp[inOff + i];
      one(2 * N + ADDR, out, outOff);
    };
    lane.H = (addr, inp, inOff, out, outOff) => {
      pre.set(addr, N);
      for (let i = 0; i < 2 * N; i++) pre[N + ADDR + i] = inp[inOff + i];
      one(3 * N + ADDR, out, outOff);
    };
    lane.PRF = (addr, out, outOff) => {
      pre.set(addr, N);
      pre.set(skSeed, N + ADDR);
      one(2 * N + ADDR, out, outOff);
    };
    lane.T = (addr, inp, len, out, outOff) => {
      const d = createHash('shake256', { outputLength: N }).update(pubSeed).update(addr).update(inp.subarray(0, len)).digest();
      for (let i = 0; i < N; i++) out[outOff + i] = d[i];
    };
    lane.PRFmsg = (skPRF, random, msg) => new Uint8Array(createHash('shake256', { outputLength: N }).update(skPRF).update(random).update(msg).digest());
    lane.Hmsg = (R, pk, m, outLen) => new Uint8Array(createHash('shake256', { outputLength: outLen }).update(R.subarray(0, N)).update(pk).update(m).digest());
  }
  return lane;
};

// ---------------------------------------------------------------------------------------------
export function createFastSlhDsa(paramName, hashName) {
  const opts = PARAMS[paramName];
  const { N, W, H, D, K, A } = opts;
  const isShake = hashName === 'shake';
  const getLane = isShake ? genShakeLane()(opts) : genSha2Lane(N !== 16)(opts);
  const WOTS_LOGW = 4;
  const WOTS_LEN1 = Math.floor((8 * N) / WOTS_LOGW);
  const WOTS_LEN2 = N <= 8 ? 2 : N <= 136 ? 3 : 4;
  const TREE_HEIGHT = Math.floor(H / D);
  const WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;
  // ADRS layout (compressed 22-byte ADRSc for SHA2, full 32-byte ADRS for SHAKE); same as noble.
  const ADDR_BYTES = isShake ? 32 : 22;
  const sh = isShake ? 10 : 0;
  const O_LAYER = 0 + (isShake ? 3 : 0);
  const O_TREE = 1 + (isShake ? 7 : 0);
  const O_TYPE = 9 + sh;
  const O_KP2 = 12 + sh;
  const O_KP1 = 13 + sh;
  const O_CHAIN = 17 + sh;
  const O_INDEX = 18 + sh;
  const O_HASH = 21 + sh;
  const SUBTREE_LEN = O_TREE + 8;
  const newAddr = () => new Uint8Array(ADDR_BYTES);
  const setType = (a, t) => {
    a[O_TYPE] = t;
  };
  const setLayer = (a, l) => {
    a[O_LAYER] = l;
  };
  const setTree = (a, tree) => {
    let t = tree;
    for (let i = 7; i >= 0; i--, t >>= BigInt(8)) a[O_TREE + i] = Number(t & BigInt(0xff));
  };
  const setKeypair = TREE_HEIGHT > 8
    ? (a, kp) => {
        a[O_KP1] = kp;
        a[O_KP2] = kp >>> 8;
      }
    : (a, kp) => {
        a[O_KP1] = kp;
      };
  const setChain = (a, c) => {
    a[O_CHAIN] = c;
  };
  const setHeight = setChain;
  const setHash = (a, h) => {
    a[O_HASH] = h;
  };
  const setIndex = (a, i) => {
    a[O_INDEX] = i >>> 24;
    a[O_INDEX + 1] = i >>> 16;
    a[O_INDEX + 2] = i >>> 8;
    a[O_INDEX + 3] = i;
  };
  const copySubtree = (dst, src) => {
    for (let i = 0; i < SUBTREE_LEN; i++) dst[i] = src[i];
  };
  const copyKeypairAddr = (dst, src) => {
    copySubtree(dst, src);
    dst[O_KP1] = src[O_KP1];
    if (TREE_HEIGHT > 8) dst[O_KP2] = src[O_KP2];
  };

  const chainCoder = base2b(WOTS_LEN2, WOTS_LOGW);
  const msgCoder = base2b(WOTS_LEN1, WOTS_LOGW);
  const chainLengths = (msg) => {
    const W1 = msgCoder(msg);
    let csum = 0;
    for (let i = 0; i < W1.length; i++) csum += W - 1 - W1[i];
    csum <<= (8 - ((WOTS_LEN2 * WOTS_LOGW) % 8)) % 8;
    const W2 = chainCoder(numberToBytesBE(csum, Math.ceil((WOTS_LEN2 * WOTS_LOGW) / 8)));
    const lengths = new Uint32Array(WOTS_LEN);
    lengths.set(W1);
    lengths.set(W2, W1.length);
    return lengths;
  };
  const messageToIndices = base2b(K, A);
  const TREE_BITS = TREE_HEIGHT * (D - 1);
  const LEAF_BITS = TREE_HEIGHT;
  const hashMsgCoder = splitCoder('hashedMessage', Math.ceil((A * K) / 8), Math.ceil(TREE_BITS / 8), Math.ceil(TREE_HEIGHT / 8));
  const hashMessage = (R, pk, msg, lane) => {
    const digest = lane.Hmsg(R, pk, msg, hashMsgCoder.bytesLen);
    const [md, tmpIdxTree, tmpIdxLeaf] = hashMsgCoder.decode(digest);
    const tree = bytesToNumberBE(tmpIdxTree) & getMaskBig(TREE_BITS);
    const leafIdx = Number(bytesToNumberBE(tmpIdxLeaf)) & getMask(LEAF_BITS);
    return { tree, leafIdx, md };
  };

  // WOTS+ leaf: computes the WOTS public key (hashed with T_l) for keypair `kp` under the
  // subtree address in `wotsAddr`; if `sigOut` is given and kp === sigLeaf, also captures the
  // WOTS signature for the chain lengths `steps`.
  const wotsPk = new Uint8Array(WOTS_LEN * N);
  const leafAddr = newAddr();
  const pkAddr = newAddr();
  const wotsLeaf = (lane, wotsAddr, kp, out, outOff, steps, sigLeaf, sigOut) => {
    copySubtree(leafAddr, wotsAddr);
    copySubtree(pkAddr, wotsAddr);
    setType(pkAddr, AddressType.WOTSPK);
    setKeypair(leafAddr, kp);
    setKeypair(pkAddr, kp);
    const capture = kp === sigLeaf;
    for (let i = 0; i < WOTS_LEN; i++) {
      const o = i * N;
      setChain(leafAddr, i);
      setHash(leafAddr, 0);
      setType(leafAddr, AddressType.WOTSPRF);
      lane.PRF(leafAddr, wotsPk, o);
      setType(leafAddr, AddressType.WOTS);
      const wotsK = capture ? steps[i] : -1;
      for (let k = 0; ; k++) {
        if (k === wotsK) for (let b = 0; b < N; b++) sigOut[o + b] = wotsPk[o + b];
        if (k === W - 1) break;
        setHash(leafAddr, k);
        lane.F(leafAddr, wotsPk, o, wotsPk, o);
      }
    }
    lane.T(pkAddr, wotsPk, WOTS_LEN * N, out, outOff);
  };
  // Iterative treehash (xmss_node / fors_node) with auth-path capture, as in noble.
  const treehash = (lane, height, leafFn, leafIdx, idxOffset, treeAddr, authPath) => {
    const maxIdx = (1 << height) - 1;
    const stack = new Uint8Array(height * N);
    const current = new Uint8Array(2 * N);
    const root = new Uint8Array(N);
    for (let idx = 0; ; idx++) {
      leafFn(idx + idxOffset, current, N); // cur1 = leaf
      let h = 0;
      for (let i = idx, o = idxOffset, l = leafIdx; ; h++, i >>>= 1, l >>>= 1, o >>>= 1) {
        if (h === height) {
          for (let b = 0; b < N; b++) root[b] = current[N + b];
          return root;
        }
        if ((i ^ l) === 1) for (let b = 0; b < N; b++) authPath[h * N + b] = current[N + b];
        if ((i & 1) === 0 && idx < maxIdx) break;
        setHeight(treeAddr, h + 1);
        setIndex(treeAddr, (i >> 1) + (o >> 1));
        for (let b = 0; b < N; b++) current[b] = stack[h * N + b];
        lane.H(treeAddr, current, 0, current, N);
      }
      for (let b = 0; b < N; b++) stack[h * N + b] = current[N + b];
    }
  };
  const forsLeafAddr = newAddr();
  const merkleSign = (lane, wotsAddr, treeAddr, leafIdx, prevRoot) => {
    setType(treeAddr, AddressType.HASHTREE);
    const steps = chainLengths(prevRoot);
    const sigWots = new Uint8Array(WOTS_LEN * N);
    const sigAuth = new Uint8Array(TREE_HEIGHT * N);
    const root = treehash(
      lane,
      TREE_HEIGHT,
      (kp, out, outOff) => wotsLeaf(lane, wotsAddr, kp, out, outOff, steps, leafIdx, sigWots),
      leafIdx,
      0,
      treeAddr,
      sigAuth
    );
    return { root, sigWots, sigAuth };
  };
  const computeRoot = (lane, leaf, leafIdx, idxOffset, authPath, treeHeight, addr) => {
    const buffer = new Uint8Array(2 * N);
    if ((leafIdx & 1) !== 0) {
      buffer.set(leaf.subarray(0, N), N);
      buffer.set(authPath.subarray(0, N), 0);
    } else {
      buffer.set(leaf.subarray(0, N), 0);
      buffer.set(authPath.subarray(0, N), N);
    }
    leafIdx >>>= 1;
    idxOffset >>>= 1;
    const out = new Uint8Array(N);
    for (let i = 0; i < treeHeight - 1; i++, leafIdx >>= 1, idxOffset >>= 1) {
      setHeight(addr, i + 1);
      setIndex(addr, leafIdx + idxOffset);
      lane.H(addr, buffer, 0, out, 0);
      const aOff = (i + 1) * N;
      if ((leafIdx & 1) !== 0) {
        buffer.set(out, N);
        for (let b = 0; b < N; b++) buffer[b] = authPath[aOff + b];
      } else {
        buffer.set(out, 0);
        for (let b = 0; b < N; b++) buffer[N + b] = authPath[aOff + b];
      }
    }
    setHeight(addr, treeHeight);
    setIndex(addr, leafIdx + idxOffset);
    lane.H(addr, buffer, 0, out, 0);
    return out;
  };
  const seedCoder = splitCoder('seed', N, N, N);
  const publicCoder = splitCoder('publicKey', N, N);
  const secretCoder = splitCoder('secretKey', N, N, publicCoder.bytesLen);
  const forsCoder = vecCoder(splitCoder('fors', N, N * A), K);
  const wotsCoder = vecCoder(splitCoder('wots', WOTS_LEN * N, TREE_HEIGHT * N), D);
  const sigCoder = splitCoder('signature', N, forsCoder, wotsCoder);

  const keygen = (seed) => {
    if (!(seed instanceof Uint8Array) || seed.length !== 3 * N) throw new Error(`seed: expected ${3 * N} bytes`);
    const [secretSeed, secretPRF, publicSeed] = seedCoder.decode(seed);
    const lane = getLane(publicSeed, secretSeed);
    const treeAddr = newAddr();
    setLayer(treeAddr, D - 1);
    const wotsAddr = newAddr();
    setLayer(wotsAddr, D - 1);
    const { root } = merkleSign(lane, wotsAddr, treeAddr, ~0 >>> 0, new Uint8Array(N));
    const publicKey = publicCoder.encode([publicSeed, root]);
    const secretKey = secretCoder.encode([secretSeed, secretPRF, publicKey]);
    return { publicKey, secretKey };
  };
  const signCore = (M, sk, optRandOpt) => {
    const [skSeed, skPRF, pk] = secretCoder.decode(sk);
    const [pkSeed] = publicCoder.decode(pk);
    const random = optRandOpt === false ? pkSeed : optRandOpt;
    const lane = getLane(pkSeed, skSeed);
    const R = lane.PRFmsg(skPRF, random, M);
    let { tree, leafIdx, md } = hashMessage(R, pk, M, lane);
    const wotsAddr = newAddr();
    setType(wotsAddr, AddressType.WOTS);
    setTree(wotsAddr, tree);
    setKeypair(wotsAddr, leafIdx);
    const forsTreeAddr = newAddr();
    copyKeypairAddr(forsTreeAddr, wotsAddr);
    copyKeypairAddr(forsLeafAddr, wotsAddr);
    const indices = messageToIndices(md);
    const roots = new Uint8Array(K * N);
    const fors = [];
    const forsLeafFn = (addrOffset, out, outOff) => {
      setType(forsLeafAddr, AddressType.FORSPRF);
      setIndex(forsLeafAddr, addrOffset);
      lane.PRF(forsLeafAddr, out, outOff);
      setType(forsLeafAddr, AddressType.FORSTREE);
      lane.F(forsLeafAddr, out, outOff, out, outOff);
    };
    for (let i = 0; i < K; i++) {
      const idxOffset = i << A;
      setType(forsTreeAddr, AddressType.FORSPRF);
      setHeight(forsTreeAddr, 0);
      setIndex(forsTreeAddr, indices[i] + idxOffset);
      const prf = new Uint8Array(N);
      lane.PRF(forsTreeAddr, prf, 0);
      setType(forsTreeAddr, AddressType.FORSTREE);
      const authPath = new Uint8Array(A * N);
      const root = treehash(lane, A, forsLeafFn, indices[i], idxOffset, forsTreeAddr, authPath);
      roots.set(root, i * N);
      fors.push([prf, authPath]);
    }
    const forsPkAddr = newAddr();
    copyKeypairAddr(forsPkAddr, wotsAddr);
    setType(forsPkAddr, AddressType.FORSPK);
    const root = new Uint8Array(N);
    lane.T(forsPkAddr, roots, K * N, root, 0);
    const treeAddr = newAddr();
    setType(treeAddr, AddressType.HASHTREE);
    const wots = [];
    for (let i = 0; i < D; i++, tree >>= BigInt(TREE_HEIGHT)) {
      setTree(treeAddr, tree);
      setLayer(treeAddr, i);
      copySubtree(wotsAddr, treeAddr);
      setKeypair(wotsAddr, leafIdx);
      const { sigWots, sigAuth, root: r } = merkleSign(lane, wotsAddr, treeAddr, leafIdx, root);
      root.set(r);
      wots.push([sigWots, sigAuth]);
      leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
    }
    return sigCoder.encode([R, fors, wots]);
  };
  const verifyCore = (sig, M, publicKey) => {
    const [pkSeed, pubRoot] = publicCoder.decode(publicKey);
    if (sig.length !== sigCoder.bytesLen) return false;
    const [random, forsVec, wotsVec] = sigCoder.decode(sig);
    const lane = getLane(pkSeed);
    let { tree, leafIdx, md } = hashMessage(random, publicKey, M, lane);
    const wotsAddr = newAddr();
    setType(wotsAddr, AddressType.WOTS);
    setTree(wotsAddr, tree);
    setKeypair(wotsAddr, leafIdx);
    const forsTreeAddr = newAddr();
    copyKeypairAddr(forsTreeAddr, wotsAddr);
    setType(forsTreeAddr, AddressType.FORSTREE);
    const indices = messageToIndices(md);
    const roots = new Uint8Array(K * N);
    const leaf = new Uint8Array(N);
    for (let i = 0; i < forsVec.length; i++) {
      const [prf, authPath] = forsVec[i];
      const idxOffset = i << A;
      setHeight(forsTreeAddr, 0);
      setIndex(forsTreeAddr, indices[i] + idxOffset);
      lane.F(forsTreeAddr, prf, 0, leaf, 0);
      roots.set(computeRoot(lane, leaf, indices[i], idxOffset, authPath, A, forsTreeAddr), i * N);
    }
    const forsPkAddr = newAddr();
    copyKeypairAddr(forsPkAddr, wotsAddr);
    setType(forsPkAddr, AddressType.FORSPK);
    let root = new Uint8Array(N);
    lane.T(forsPkAddr, roots, K * N, root, 0);
    const treeAddr = newAddr();
    setType(treeAddr, AddressType.HASHTREE);
    const wotsPkAddr = newAddr();
    setType(wotsPkAddr, AddressType.WOTSPK);
    const wotsPkBuf = new Uint8Array(WOTS_LEN * N);
    for (let i = 0; i < wotsVec.length; i++, tree >>= BigInt(TREE_HEIGHT)) {
      const [wots, sigAuth] = wotsVec[i];
      setTree(treeAddr, tree);
      setLayer(treeAddr, i);
      copySubtree(wotsAddr, treeAddr);
      setKeypair(wotsAddr, leafIdx);
      copyKeypairAddr(wotsPkAddr, wotsAddr);
      const lengths = chainLengths(root);
      for (let c = 0; c < WOTS_LEN; c++) {
        setChain(wotsAddr, c);
        const start = lengths[c];
        const o = c * N;
        for (let b = 0; b < N; b++) wotsPkBuf[o + b] = wots[o + b];
        for (let j = start; j < W - 1; j++) {
          setHash(wotsAddr, j);
          lane.F(wotsAddr, wotsPkBuf, o, wotsPkBuf, o);
        }
      }
      lane.T(wotsPkAddr, wotsPkBuf, WOTS_LEN * N, leaf, 0);
      root = computeRoot(lane, leaf, leafIdx, 0, sigAuth, TREE_HEIGHT, treeAddr);
      leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
    }
    return equalBytes(root, pubRoot);
  };
  return {
    info: { type: 'slh-dsa-fastjs' },
    lengths: { publicKey: publicCoder.bytesLen, secretKey: secretCoder.bytesLen, signature: sigCoder.bytesLen, seed: seedCoder.bytesLen },
    keygen,
    sign: (msg, sk, opts = {}) => {
      if (opts.extraEntropy !== false) throw new Error('fast-slh-dsa: only deterministic signing (extraEntropy: false) is supported');
      return signCore(getMessage(msg, opts.context), sk, false);
    },
    verify: (sig, msg, pk, opts = {}) => verifyCore(sig, getMessage(msg, opts.context), pk),
  };
}

export const slh = {};
for (const h of ['sha2', 'shake'])
  for (const p of ['128s', '128f', '192s', '192f', '256s', '256f']) slh[`slh_dsa_${h}_${p}`] = createFastSlhDsa(p, h);
