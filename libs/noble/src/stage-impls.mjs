// Verify-stage variants (CONTRACT.md Phase 2 §B). Every variant is {stage, id, name, desc, impl,
// hash, runtime} where impl selects the code that runs the stage:
//   'vendor'  noble's own code (build/vendor, stage entry points added by patches/)  -> v0 (and "bun"
//             variants, which run exactly this code under Bun, and "native" variants, which run it with
//             NOBLE_PQ_HASH=native)
//   'fast'    the fast-*.mjs rewrites' stage functions
//   'alt:*'   stand-alone alternatives implemented in this file (unpackers, cached inputs, other NTT
//             reduction, worker-parallel ExpandA)
// A variant's state is built by prepare(ctx) from canonical inputs (outside the timed region);
// run(state) returns the stage result, which the runner canonicalises and hashes.
import { familyOf } from './algs.mjs';
import { PARAMS } from '@noble/post-quantum/ml-dsa.js';

const N = 256;
const Q = 8380417;
const D = 13;
const LEVEL = { 'ML-DSA-44': 2, 'ML-DSA-65': 3, 'ML-DSA-87': 5 };
export const mlParams = (param) => {
  const lvl = LEVEL[param];
  const p = PARAMS[lvl];
  return { ...p, lvl, C_TILDE_BYTES: { 2: 32, 3: 48, 5: 64 }[lvl], ZBITS: p.GAMMA1 === 1 << 17 ? 18 : 20 };
};

// ---------------------------------------------------------------- alt: word-level unpackers (decode)
export function fastUnpackDecode(param) {
  const { K, L, GAMMA1, OMEGA, C_TILDE_BYTES, ZBITS } = mlParams(param);
  const SIG_LEN = C_TILDE_BYTES + L * 32 * ZBITS + OMEGA + K;
  const unpack10 = (buf, off) => {
    const r = new Int32Array(N);
    for (let i = 0, o = off; i < N; i += 4, o += 5) {
      const b0 = buf[o], b1 = buf[o + 1], b2 = buf[o + 2], b3 = buf[o + 3], b4 = buf[o + 4];
      r[i] = b0 | ((b1 & 3) << 8);
      r[i + 1] = (b1 >> 2) | ((b2 & 15) << 6);
      r[i + 2] = (b2 >> 4) | ((b3 & 63) << 4);
      r[i + 3] = (b3 >> 6) | (b4 << 2);
    }
    return r;
  };
  const unpackZ18 = (buf, off) => {
    const r = new Int32Array(N);
    for (let i = 0, o = off; i < N; i += 4, o += 9) {
      const b0 = buf[o], b1 = buf[o + 1], b2 = buf[o + 2], b3 = buf[o + 3], b4 = buf[o + 4], b5 = buf[o + 5], b6 = buf[o + 6], b7 = buf[o + 7], b8 = buf[o + 8];
      r[i] = GAMMA1 - (b0 | (b1 << 8) | ((b2 & 3) << 16));
      r[i + 1] = GAMMA1 - ((b2 >> 2) | (b3 << 6) | ((b4 & 15) << 14));
      r[i + 2] = GAMMA1 - ((b4 >> 4) | (b5 << 4) | ((b6 & 63) << 12));
      r[i + 3] = GAMMA1 - ((b6 >> 6) | (b7 << 2) | (b8 << 10));
    }
    return r;
  };
  const unpackZ20 = (buf, off) => {
    const r = new Int32Array(N);
    for (let i = 0, o = off; i < N; i += 2, o += 5) {
      const b0 = buf[o], b1 = buf[o + 1], b2 = buf[o + 2], b3 = buf[o + 3], b4 = buf[o + 4];
      r[i] = GAMMA1 - (b0 | (b1 << 8) | ((b2 & 15) << 16));
      r[i + 1] = GAMMA1 - ((b2 >> 4) | (b3 << 4) | (b4 << 12));
    }
    return r;
  };
  const unpackZ = ZBITS === 18 ? unpackZ18 : unpackZ20;
  return (pk, sig) => {
    if (pk.length !== 32 + K * 320) throw new Error('bad pk length');
    const rho = pk.subarray(0, 32);
    const t1 = [];
    for (let i = 0; i < K; i++) t1.push(unpack10(pk, 32 + i * 320));
    if (sig.length !== SIG_LEN) return false;
    const cTilde = sig.subarray(0, C_TILDE_BYTES);
    const z = [];
    for (let i = 0; i < L; i++) z.push(unpackZ(sig, C_TILDE_BYTES + i * 32 * ZBITS));
    const hb = C_TILDE_BYTES + L * 32 * ZBITS;
    const h = [];
    let k = 0;
    for (let i = 0; i < K; i++) {
      const hi = new Int32Array(N);
      const end = sig[hb + OMEGA + i];
      if (end < k || end > OMEGA) return false;
      for (let j = k; j < end; j++) {
        if (j > k && sig[hb + j] <= sig[hb + j - 1]) return false;
        hi[sig[hb + j]] = 1;
      }
      k = end;
      h.push(hi);
    }
    for (let j = k; j < OMEGA; j++) if (sig[hb + j] !== 0) return false;
    return { rho, t1, cTilde, z, h };
  };
}

// ---------------------------------------------------------------- alt: fully-reduced int32 NTT with `%`
// (the "other reduction" alternative for w_approx: Int32Array polys, every butterfly output reduced with
// the JS modulo operator — the arithmetic style of noble's generic field code, but inlined)
const ZETAS = (() => {
  const out = new Int32Array(N);
  for (let k = 0; k < N; k++) {
    let b = 0;
    for (let i = 0; i < 8; i++) b |= ((k >> i) & 1) << (7 - i);
    let r = 1;
    for (let i = 0; i < b; i++) r = (r * 1753) % Q;
    out[k] = r;
  }
  return out;
})();
const F = 8347681;
function nttMod(p) {
  for (let i = 0; i < N; i++) {
    const v = p[i] % Q;
    p[i] = v < 0 ? v + Q : v;
  }
  let k = 0;
  for (let len = 128; len >= 1; len >>= 1)
    for (let start = 0; start < N; start += len << 1) {
      const z = ZETAS[++k];
      for (let j = start; j < start + len; j++) {
        const t = (z * p[j + len]) % Q;
        const a = p[j];
        p[j] = (a + t) % Q;
        p[j + len] = (a - t + Q) % Q;
      }
    }
  return p;
}
function inttMod(p) {
  let k = N;
  for (let len = 1; len < N; len <<= 1)
    for (let start = 0; start < N; start += len << 1) {
      const z = Q - ZETAS[--k];
      for (let j = start; j < start + len; j++) {
        const t = p[j];
        const b = p[j + len];
        p[j] = (t + b) % Q;
        p[j + len] = (z * ((t - b + Q) % Q)) % Q;
      }
    }
  for (let i = 0; i < N; i++) p[i] = (F * p[i]) % Q;
  return p;
}
export function wApproxIntMod(param, sampleInBallNtt) {
  const { K, L } = mlParams(param);
  return (A, t1, cTilde, z) => {
    const c = nttMod(sampleInBallNtt(cTilde)); // SampleInBall from noble (ordinary domain), our NTT
    const zNtt = z.map((p) => nttMod(Int32Array.from(p)));
    const w = [];
    for (let i = 0; i < K; i++) {
      const t1h = Int32Array.from(t1[i], (v) => v << D);
      nttMod(t1h);
      const acc = new Int32Array(N);
      for (let j = 0; j < L; j++) {
        const a = A[i][j];
        const zz = zNtt[j];
        for (let n = 0; n < N; n++) acc[n] = (acc[n] + ((a[n] * zz[n]) % Q)) % Q;
      }
      for (let n = 0; n < N; n++) acc[n] = (acc[n] - ((t1h[n] * c[n]) % Q) + Q) % Q;
      w.push(inttMod(acc));
    }
    return w;
  };
}

// ---------------------------------------------------------------- variant table
const V = (stage, n, name, desc, o = {}) => ({ stage, id: `${stage}.v${n}`, name, desc, impl: 'vendor', hash: 'noble', runtime: 'node', ...o });
const bunDesc = "noble's own stage code executed by the Bun runtime (JavaScriptCore) instead of Node/V8.";
const nativeDesc = "noble's own stage code with its @noble/hashes SHAKE/SHA-2 calls served by node:crypto (OpenSSL) through the drop-in shim.";
export const STAGE_VARIANTS = [
  // ---- ML-DSA
  V('decode', 0, 'noble', "noble's pkDecode/sigDecode: generic bit-coders (bitsCoder/splitCoder) with per-coefficient decode closures and the hint validity checks."),
  V('decode', 1, 'word-unpack', 'Hand-written unpackers: t1 (10-bit, 5 bytes -> 4 coeffs), z (18/20-bit, 9/5 bytes -> 4/2 coeffs) and the hint table decoded with straight-line byte arithmetic into Int32Arrays; no generic bit buffer, no per-coefficient calls.', { impl: 'alt:unpack' }),
  V('decode', 2, 'bun', bunDesc, { runtime: 'bun' }),
  V('mu', 0, 'noble', "tr = SHAKE256(pk, 64), mu = SHAKE256(tr || M', 64) with @noble/hashes."),
  V('mu', 1, 'native-shake', nativeDesc, { hash: 'native' }),
  V('mu', 2, 'fast-keccak', 'Same two SHAKE256 calls on the generated, fully unrolled Keccak-f[1600] (fast-shake.mjs).', { impl: 'fast' }),
  V('mu', 3, 'tr-cache', 'tr = H(pk) is a pure function of the public key, so it is cached per pk; the stage only absorbs tr || M\' (halves the permutations for short messages).', { impl: 'alt:trcache' }),
  V('mu', 4, 'bun', bunDesc, { runtime: 'bun' }),
  V('expandA', 0, 'noble', 'ExpandA with noble XOF128 reader + RejNTTPoly (k*l SHAKE128 rejection samplings, ~5 permutations each).'),
  V('expandA', 1, 'native-shake', nativeDesc + ' Each matrix entry is one OpenSSL SHAKE128 call squeezing 5 blocks (extended on demand).', { hash: 'native' }),
  V('expandA', 2, 'fast-keccak', 'XOF128 reader on the unrolled Keccak-f[1600] + the same rejection sampler.', { impl: 'fast' }),
  V('expandA', 3, 'A-cache', 'A^ depends only on rho, i.e. on the public key: it is computed once per pk and the stage just hands out the cached rows (what a verifier serving many signatures under one key does).', { impl: 'alt:acache' }),
  V('expandA', 4, 'workers-x4', 'The k rows of A^ are expanded in parallel by 4 worker_threads (noble code in each), results transferred back as Int32Array buffers; one op = one matrix (latency, threads=4).', { impl: 'alt:aworkers', threads: 4 }),
  V('expandA', 5, 'bun', bunDesc, { runtime: 'bun' }),
  V('w_approx', 0, 'noble', "noble: SampleInBall, NTT(z), NTT(t1*2^d) via the generic FFTCore (field closures, `%` reduction), MultiplyNTTs + polyAdd per product, NTT^-1."),
  V('w_approx', 1, 'lazy-ntt', 'fast-ml-dsa: branch-free lazily-reduced NTT/INTT on Float64Array (reciprocal quotient estimate, coefficients reduced once at the end), fused multiply-accumulate over the l products, unrolled-Keccak SampleInBall.', { impl: 'fast' }),
  V('w_approx', 2, 't1hat-cache', "NTT(t1 * 2^d) depends only on the public key and is precomputed once per pk (noble's own NTT); the stage computes SampleInBall, NTT(z), the products and NTT^-1.", { impl: 'alt:t1hat' }),
  V('w_approx', 3, 'int32-mod-ntt', 'Fully reduced Int32Array NTT with the JS `%` operator after every butterfly and product (same reduction style as noble, but inlined loops without field-method closures); isolates "inlining" from "lazy reduction".', { impl: 'alt:intmod' }),
  V('w_approx', 4, 'bun', bunDesc, { runtime: 'bun' }),
  V('hint_check', 0, 'noble', "noble: z norm check, UseHint per coefficient (decompose objects), w1Encode via bitsCoder, SHAKE256(mu || w1) and compare."),
  V('hint_check', 1, 'fastjs', 'fast-ml-dsa: inlined UseHint loop without per-coefficient objects, unrolled-Keccak SHAKE256; same bit packer.', { impl: 'fast' }),
  V('hint_check', 2, 'native-shake', nativeDesc, { hash: 'native' }),
  V('hint_check', 3, 'bun', bunDesc, { runtime: 'bun' }),
  // ---- SLH-DSA
  V('hmsg', 0, 'noble', "noble: sig parse, Hmsg (SHA2: SHA-256/512 + MGF1; SHAKE: SHAKE256) with @noble/hashes, md / idx_tree / idx_leaf split."),
  V('hmsg', 1, 'native-hash', nativeDesc, { hash: 'native' }),
  V('hmsg', 2, 'fast-keccak', 'SHAKE sets only: Hmsg as one absorb/squeeze on the unrolled Keccak-f[1600] sponge (SHA2 sets would run the identical noble code, so they are skipped here).', { impl: 'fast', shakeOnly: true }),
  V('hmsg', 3, 'bun', bunDesc, { runtime: 'bun' }),
  V('fors', 0, 'noble', 'noble fors_pkFromSig: k x (F + a x H) with cloned-midstate hashers and setAddr({...}) address objects, T_k over the roots.'),
  V('fors', 1, 'fastjs', 'fast-slh-dsa: F/H via direct SHA-2 compression-function calls on a pre-padded block from the PK.seed midstate (SHAKE: cached-seed sponge + unrolled Keccak), fixed-offset ADRS writes, in-place auth-path hashing.', { impl: 'fast' }),
  V('fors', 2, 'native-hash', nativeDesc, { hash: 'native' }),
  V('fors', 3, 'bun', bunDesc, { runtime: 'bun' }),
  V('ht_wots', 0, 'noble', 'noble wots_pkFromSig for all d layers (up to len x 15 F each + T_len), each layer given its correct input message.'),
  V('ht_wots', 1, 'fastjs', 'fast-slh-dsa WOTS+ chains: direct compression-function F from the PK.seed midstate, chain state kept in one buffer, no per-step views.', { impl: 'fast' }),
  V('ht_wots', 2, 'native-hash', nativeDesc, { hash: 'native' }),
  V('ht_wots', 3, 'bun', bunDesc, { runtime: 'bun' }),
  V('ht_auth', 0, 'noble', "noble computeRoot for all d layers (h' x H each) + final compare with PK.root."),
  V('ht_auth', 1, 'fastjs', 'fast-slh-dsa auth paths: H via direct compression-function calls, sibling placement by offset into one 2n buffer.', { impl: 'fast' }),
  V('ht_auth', 2, 'native-hash', nativeDesc, { hash: 'native' }),
  V('ht_auth', 3, 'bun', bunDesc, { runtime: 'bun' }),
  // ---- end-to-end
  V('total', 0, 'noble-stages', "End-to-end verify assembled from the v0 (noble) stages: decode -> mu -> expandA -> w_approx -> hint_check (ML-DSA) / hmsg -> fors -> ht_wots -> ht_auth (SLH-DSA)."),
  V('total_best', 0, 'fast-stages', 'End-to-end verify assembled from the fastest correct cache-free alternatives: word-unpack decode, fast-keccak mu/expandA, lazy-ntt w_approx, fastjs hint_check (ML-DSA); fastjs hmsg/fors/ht_wots/ht_auth (SLH-DSA).', { impl: 'best' }),
];
export const ML_STAGES = ['decode', 'mu', 'expandA', 'w_approx', 'hint_check'];
export const SLH_STAGES = ['hmsg', 'fors', 'ht_wots', 'ht_auth'];
export const stageFamily = (stage) => (ML_STAGES.includes(stage) ? 'ml-dsa' : SLH_STAGES.includes(stage) ? 'slh-dsa' : 'both');
export const stageVariantApplies = (v, param) => {
  const fam = familyOf(param);
  if (fam === 'falcon') return false;
  const sf = stageFamily(v.stage);
  if (sf !== 'both' && sf !== fam) return false;
  if (v.shakeOnly && !param.includes('SHAKE')) return false;
  return true;
};
