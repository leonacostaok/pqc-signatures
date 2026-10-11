// fast-ml-dsa.mjs: a pure-JS rewrite of the hot paths of @noble/post-quantum's ML-DSA
// (FIPS 204), used by the "fastjs" / "allin" variants. Byte-compatible with noble (checked
// against common/reference.json at every run). Differences from noble's ml-dsa.js:
//   - NTT / inverse NTT are written out as the FIPS 204 Alg. 41/42 loops with inlined
//     conditional-subtraction add/sub and a reciprocal-based mulmod (noble goes through the
//     generic FFTCore from @noble/curves with per-butterfly field-method closures and `%`).
//   - Matrix-vector products accumulate L products in a Float64Array and reduce once
//     (7 * (Q-1)^2 < 2^53), instead of allocating + reducing one temporary poly per product.
//   - decompose / HighBits / LowBits / Power2Round / MakeHint / UseHint are inlined loops
//     without per-coefficient {r1, r0} object allocation.
//   - No per-iteration cleanBytes() wiping of rejected buffers.
//   - SHAKE128/256 run on a generated, fully unrolled Keccak-f[1600] (fast-keccak.mjs, ~2.4x
//     noble's keccakP); with NOBLE_PQ_HASH=native the node:crypto shim is used instead ("allin").
// Packing (bit coders) and the SHAKE-based samplers reuse noble's code structure verbatim.
import { HASH_BACKEND } from './hashlayer.mjs';
import * as fastShake from './fast-shake.mjs';
import * as nativeHash from './native-hash.mjs';
import { genCrystals } from '@noble/post-quantum/_crystals.js';
import { equalBytes, getMessage, splitCoder, vecCoder } from '@noble/post-quantum/utils.js';
import { PARAMS } from '@noble/post-quantum/ml-dsa.js';

// SHAKE: generated unrolled keccak (fast-shake.mjs) or node:crypto (NOBLE_PQ_HASH=native)
const { shake256, XOF128, XOF256 } = HASH_BACKEND === 'native' ? nativeHash : fastShake;

const N = 256;
const Q = 8380417;
const QINV = 1 / Q;
const F = 8347681; // 256^-1 mod q
const D = 13;
const ROOT_OF_UNITY = 1753;
const GAMMA2_1 = Math.floor((Q - 1) / 88) | 0;

// zetas[k] = zeta^BitRev8(k) mod q (FIPS 204 Appendix B)
const ZETAS = (() => {
  const out = new Int32Array(N);
  for (let k = 0; k < N; k++) {
    let b = 0;
    for (let i = 0; i < 8; i++) b |= ((k >> i) & 1) << (7 - i);
    let r = 1;
    for (let i = 0; i < b; i++) r = (r * ROOT_OF_UNITY) % Q;
    out[k] = r;
  }
  return out;
})();

// Polynomials are Float64Arrays: every intermediate value stays an exactly representable
// integer below 2^53, and V8 then never has to convert between int32 and double.
//
// Branch-free "almost mod": for |a*b| < 2^52 returns a*b - q*round-estimate, a value in (-q, 2q)
// (the reciprocal quotient estimate is off by at most one). Nothing is corrected here; instead
// the NTT butterflies are lazily reduced: coefficients grow by at most 2q per stage, so after the
// 8 stages |c| <= 17q < 2^28 and every product z*c < 2^51 is still exact. One canonicalizing
// pass at the end brings everything back to [0, q). This removed every data-dependent branch
// from the butterflies and measured ~3x faster than the fully reduced loop.
function mulq(a, b) {
  const t = a * b;
  return t - Math.floor(t * QINV) * Q;
}
function canon(p) {
  for (let i = 0; i < N; i++) {
    const v = p[i] % Q;
    p[i] = v < 0 ? v + Q : v;
  }
  return p;
}
const ZETASF = Float64Array.from(ZETAS);
const NZETASF = Float64Array.from(ZETAS, (z) => Q - z);

// FIPS 204 Algorithm 41 (in place; input in (-q, q), output canonical in [0, q)).
function ntt(p) {
  let k = 0;
  for (let len = 128; len >= 1; len >>= 1) {
    for (let start = 0; start < N; start += len << 1) {
      const z = ZETASF[++k];
      const end = start + len;
      for (let j = start; j < end; j++) {
        const t = mulq(z, p[j + len]);
        const a = p[j];
        p[j] = a + t;
        p[j + len] = a - t;
      }
    }
  }
  return canon(p);
}
// FIPS 204 Algorithm 42 (in place; input canonical, output canonical).
function intt(p) {
  let k = N;
  for (let len = 1; len < N; len <<= 1) {
    for (let start = 0; start < N; start += len << 1) {
      const z = NZETASF[--k];
      const end = start + len;
      for (let j = start; j < end; j++) {
        const t = p[j];
        const b = p[j + len];
        // the sum lane is also reduced (branch-free) here: unlike the forward transform both
        // butterfly inputs can be sums, so it would otherwise double every stage.
        const u = t + b;
        p[j] = u - Math.floor(u * QINV) * Q;
        p[j + len] = mulq(z, t - b);
      }
    }
  }
  for (let i = 0; i < N; i++) p[i] = mulq(F, p[i]);
  return canon(p);
}
const newPoly = () => new Float64Array(N);
const toF64 = (p) => Float64Array.from(p);
// c = a o b (both NTT form, canonical)
function pointwise(a, b) {
  const c = newPoly();
  for (let i = 0; i < N; i++) c[i] = mulq(a[i], b[i]);
  return canon(c);
}
// acc += a o b (no reduction)
function mulAcc(acc, a, b) {
  for (let i = 0; i < N; i++) acc[i] += a[i] * b[i];
}
function reduceAcc(acc, out) {
  for (let i = 0; i < N; i++) out[i] = acc[i] % Q; // acc >= 0 and < 2^53
  return out;
}
// canonical(sum of a canonical/centered pair)
function polyAddMod(a, b) {
  for (let i = 0; i < N; i++) {
    let v = a[i] + b[i];
    if (v >= Q) v -= Q;
    else if (v < 0) v += Q;
    a[i] = v;
  }
  return a;
}
function polyChknorm(p, B) {
  for (let i = 0; i < N; i++) {
    let v = p[i] % Q;
    if (v < 0) v += Q;
    if (v > (Q - 1) >> 1) v -= Q; // centered representative (q odd)
    if (v < 0) v = -v;
    if (v >= B) return true;
  }
  return false;
}
// Used by the vendored-noble compatible XOF reader: NTT-form uniform poly (FIPS 204 Alg 30).
function RejNTTPoly(xof) {
  const r = newPoly();
  for (let j = 0; j < N; ) {
    const b = xof();
    const len = b.length - 2;
    for (let i = 0; j < N && i < len; i += 3) {
      const t = (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)) & 0x7fffff;
      if (t < Q) r[j++] = t;
    }
  }
  return r;
}

// Shared bit packers from noble (same encode/decode semantics, including ETA range checks).
const crystals = genCrystals({ N, Q, F, ROOT_OF_UNITY, newPoly: (n) => new Int32Array(n), isKyber: false, brvBits: 8 });
const id = (n) => n;
const polyCoder = (d, compress = id, verify = id) =>
  crystals.bitsCoder(d, { encode: (i) => compress(verify(i)), decode: (i) => verify(compress(i)) });

export function createFastMlDsa(level) {
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = PARAMS[level];
  const C_TILDE_BYTES = { 2: 32, 3: 48, 5: 64 }[level];
  const CRH_BYTES = 64;
  const TR_BYTES = 64;
  const BETA = TAU * ETA;
  const ALPHA = 2 * GAMMA2;
  const HALF_ALPHA = GAMMA2;
  const HINT_M = Math.floor((Q - 1) / ALPHA);
  const ETACoder = polyCoder(ETA === 2 ? 3 : 4, (i) => ETA - i, (i) => {
    if (!(-ETA <= i && i <= ETA)) throw new Error(`malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`);
    return i;
  });
  const T0Coder = polyCoder(13, (i) => (1 << (D - 1)) - i);
  const T1Coder = polyCoder(10);
  const ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i) => crystals.smod(GAMMA1 - i));
  const W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K);
  const hintCoder = {
    bytesLen: OMEGA + K,
    encode: (h) => {
      const res = new Uint8Array(OMEGA + K);
      for (let i = 0, k = 0; i < K; i++) {
        const hi = h[i];
        for (let j = 0; j < N; j++) if (hi[j] !== 0) res[k++] = j;
        res[OMEGA + i] = k;
      }
      return res;
    },
    decode: (buf) => {
      const h = [];
      let k = 0;
      for (let i = 0; i < K; i++) {
        const hi = newPoly();
        if (buf[OMEGA + i] < k || buf[OMEGA + i] > OMEGA) return false;
        for (let j = k; j < buf[OMEGA + i]; j++) {
          if (j > k && buf[j] <= buf[j - 1]) return false;
          hi[buf[j]] = 1;
        }
        k = buf[OMEGA + i];
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++) if (buf[j] !== 0) return false;
      return h;
    },
  };
  const publicCoder = splitCoder('publicKey', 32, vecCoder(T1Coder, K));
  const secretCoder = splitCoder('secretKey', 32, 32, TR_BYTES, vecCoder(ETACoder, L), vecCoder(ETACoder, K), vecCoder(T0Coder, K));
  const sigCoder = splitCoder('signature', C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
  const seedCoder = splitCoder('seed', 32, 64, 32);

  // FIPS 204 Alg 31 (ordinary form, coefficients in [-eta, eta])
  function RejBoundedPoly(xof) {
    const r = newPoly();
    if (ETA === 2) {
      for (let j = 0; j < N; ) {
        const b = xof();
        for (let i = 0; j < N && i < b.length; i++) {
          const n1 = b[i] & 0x0f;
          const n2 = b[i] >> 4;
          if (n1 < 15) r[j++] = 2 - (n1 % 5);
          if (j < N && n2 < 15) r[j++] = 2 - (n2 % 5);
        }
      }
    } else {
      for (let j = 0; j < N; ) {
        const b = xof();
        for (let i = 0; j < N && i < b.length; i++) {
          const n1 = b[i] & 0x0f;
          const n2 = b[i] >> 4;
          if (n1 < 9) r[j++] = 4 - n1;
          if (j < N && n2 < 9) r[j++] = 4 - n2;
        }
      }
    }
    return r;
  }
  // FIPS 204 Alg 29 (same structure as noble)
  const SampleInBall = (seed) => {
    const pre = newPoly();
    const s = shake256.create({}).update(seed);
    const buf = new Uint8Array(shake256.blockLen);
    s.xofInto(buf);
    const masks = buf.slice(0, 8);
    for (let i = N - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N; i++) {
      let b = i + 1;
      for (; b > i; ) {
        b = buf[pos++];
        if (pos < shake256.blockLen) continue;
        s.xofInto(buf);
        pos = 0;
      }
      pre[i] = pre[b];
      pre[b] = 1 - (((masks[maskPos] >> maskBit++) & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };
  const expandA = (rho) => {
    const A = [];
    const xof = XOF128(rho);
    for (let i = 0; i < K; i++) {
      const row = [];
      for (let j = 0; j < L; j++) row.push(RejNTTPoly(xof.get(j, i)));
      A.push(row);
    }
    xof.clean();
    return A;
  };
  // w1 = HighBits(w) (w canonical)
  const highBits = (w, out) => {
    for (let i = 0; i < N; i++) {
      const r = w[i];
      let r0 = r % ALPHA;
      if (r0 > HALF_ALPHA) r0 -= ALPHA;
      out[i] = r - r0 === Q - 1 ? 0 : (r - r0) / ALPHA;
    }
    return out;
  };
  // r0 = LowBits(w - v) in place into w (w, v canonical)
  const subLowBits = (w, v) => {
    for (let i = 0; i < N; i++) {
      let r = w[i] - v[i];
      if (r < 0) r += Q;
      let r0 = r % ALPHA;
      if (r0 > HALF_ALPHA) r0 -= ALPHA;
      if (r - r0 === Q - 1) r0 -= 1;
      w[i] = r0;
    }
    return w;
  };
  // hint bit as in noble / dilithium ref (inputs: z canonical, r = w1 value)
  const makeHint = (z, w1, out) => {
    let cnt = 0;
    for (let i = 0; i < N; i++) {
      const zi = z[i];
      const h = zi <= GAMMA2 || zi > Q - GAMMA2 || (zi === Q - GAMMA2 && w1[i] === 0) ? 0 : 1;
      out[i] = h;
      cnt += h;
    }
    return cnt;
  };
  const useHint = (u, h) => {
    for (let i = 0; i < N; i++) {
      const r = u[i];
      let r0 = r % ALPHA;
      if (r0 > HALF_ALPHA) r0 -= ALPHA;
      let r1;
      if (r - r0 === Q - 1) {
        r1 = 0;
        r0 -= 1;
      } else r1 = (r - r0) / ALPHA;
      if (h[i] === 1) {
        if (r0 > 0) r1 = (r1 + 1) % HINT_M;
        else {
          r1 = (r1 - 1) % HINT_M;
          if (r1 < 0) r1 += HINT_M;
        }
      }
      u[i] = r1;
    }
    return u;
  };
  const hashMu = (tr, msg) => shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest();

  const keygen = (seed) => {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('seed: expected 32 bytes');
    const seedDst = new Uint8Array(34);
    seedDst.set(seed);
    seedDst[32] = K;
    seedDst[33] = L;
    const [rho, rhoPrime, K_] = seedCoder.decode(shake256(seedDst, { dkLen: seedCoder.bytesLen }));
    const xofPrime = XOF256(rhoPrime);
    const s1 = [];
    for (let i = 0; i < L; i++) s1.push(RejBoundedPoly(xofPrime.get(i & 0xff, (i >> 8) & 0xff)));
    const s2 = [];
    for (let i = L; i < L + K; i++) s2.push(RejBoundedPoly(xofPrime.get(i & 0xff, (i >> 8) & 0xff)));
    const s1Hat = s1.map((p) => ntt(toF64(p)));
    const t0 = [];
    const t1 = [];
    const xof = XOF128(rho);
    const acc = new Float64Array(N);
    for (let i = 0; i < K; i++) {
      acc.fill(0);
      for (let j = 0; j < L; j++) mulAcc(acc, RejNTTPoly(xof.get(j, i)), s1Hat[j]);
      const t = intt(reduceAcc(acc, newPoly()));
      polyAddMod(t, s2[i]);
      const r0 = newPoly();
      const r1 = newPoly();
      for (let k = 0; k < N; k++) {
        const r = t[k];
        let lo = r & 8191;
        if (lo > 4096) lo -= 8192;
        r0[k] = lo;
        r1[k] = (r - lo) >> D;
      }
      t0.push(r0);
      t1.push(r1);
    }
    const publicKey = publicCoder.encode([rho, t1]);
    const tr = shake256(publicKey, { dkLen: TR_BYTES });
    const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]);
    return { publicKey, secretKey };
  };
  const expandSk = (secretKey) => {
    const [rho, K_, tr, s1, s2, t0] = secretCoder.decode(secretKey);
    const A = expandA(rho);
    return { rho, K: K_, tr, s1: s1.map((p) => ntt(toF64(p))), s2: s2.map((p) => ntt(toF64(p))), t0: t0.map((p) => ntt(toF64(p))), A };
  };
  const signExpanded = (M, exp, rnd) => {
    const { K: K_, tr, s1, s2, t0, A } = exp;
    const mu = hashMu(tr, M);
    const rhoprime = shake256.create({ dkLen: CRH_BYTES }).update(K_).update(rnd).update(mu).digest();
    const x256 = XOF256(rhoprime, ZCoder.bytesLen);
    const acc = new Float64Array(N);
    const y = new Array(L);
    const z = new Array(L);
    const w = new Array(K);
    const w1 = new Array(K);
    for (let i = 0; i < K; i++) {
      w[i] = newPoly();
      w1[i] = newPoly();
    }
    const h = new Array(K);
    for (let i = 0; i < K; i++) h[i] = new Int32Array(N);
    for (let kappa = 0; ; ) {
      for (let i = 0; i < L; i++, kappa++) {
        y[i] = ZCoder.decode(x256.get(kappa & 0xff, kappa >> 8)());
        z[i] = ntt(toF64(y[i]));
      }
      for (let i = 0; i < K; i++) {
        acc.fill(0);
        const Ai = A[i];
        for (let j = 0; j < L; j++) mulAcc(acc, Ai[j], z[j]);
        intt(reduceAcc(acc, w[i]));
        highBits(w[i], w1[i]);
      }
      const cTilde = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(w1)).digest();
      const cHat = ntt(SampleInBall(cTilde));
      let reject = false;
      const zz = new Array(L);
      for (let i = 0; i < L; i++) {
        const cs1 = intt(pointwise(s1[i], cHat));
        polyAddMod(cs1, y[i]); // z = y + cs1
        if (polyChknorm(cs1, GAMMA1 - BETA)) {
          reject = true;
          break;
        }
        zz[i] = cs1;
      }
      if (reject) continue;
      let cnt = 0;
      for (let i = 0; i < K; i++) {
        const cs2 = intt(pointwise(s2[i], cHat));
        subLowBits(w[i], cs2); // w[i] := LowBits(w - cs2)
        if (polyChknorm(w[i], GAMMA2 - BETA)) {
          reject = true;
          break;
        }
        const ct0 = intt(pointwise(t0[i], cHat));
        if (polyChknorm(ct0, GAMMA2)) {
          reject = true;
          break;
        }
        polyAddMod(w[i], ct0);
        cnt += makeHint(w[i], w1[i], h[i]);
      }
      if (reject || cnt > OMEGA) continue;
      x256.clean();
      return sigCoder.encode([cTilde, zz, h]);
    }
  };
  const expandPk = (publicKey) => {
    const [rho, t1] = publicCoder.decode(publicKey);
    const tr = shake256(publicKey, { dkLen: TR_BYTES });
    const A = expandA(rho);
    const t1Hat = t1.map((p) => {
      const q = toF64(p);
      for (let i = 0; i < N; i++) q[i] *= 1 << D;
      return ntt(q);
    });
    return { rho, tr, A, t1Hat };
  };
  const verifyExpanded = (sig, M, exp) => {
    const { rho, t1, tr, A, t1Hat } = exp;
    if (sig.length !== sigCoder.bytesLen) return false;
    const [cTilde, z, h] = sigCoder.decode(sig);
    if (h === false) return false;
    for (let i = 0; i < L; i++) if (polyChknorm(z[i], GAMMA1 - BETA)) return false;
    const mu = hashMu(tr, M);
    const c = ntt(SampleInBall(cTilde));
    const zNtt = z.map((p) => ntt(toF64(p)));
    const wTick1 = [];
    const xof = A === null ? XOF128(rho) : null;
    const acc = new Float64Array(N);
    for (let i = 0; i < K; i++) {
      let t1h;
      if (A === null) {
        t1h = toF64(t1[i]);
        for (let k = 0; k < N; k++) t1h[k] *= 1 << D;
        ntt(t1h);
      } else t1h = t1Hat[i];
      const ct12d = pointwise(t1h, c);
      acc.fill(0);
      for (let j = 0; j < L; j++) mulAcc(acc, A === null ? RejNTTPoly(xof.get(j, i)) : A[i][j], zNtt[j]);
      const Az = reduceAcc(acc, newPoly());
      for (let k = 0; k < N; k++) {
        const v = Az[k] - ct12d[k];
        Az[k] = v < 0 ? v + Q : v;
      }
      wTick1.push(useHint(intt(Az), h[i]));
    }
    if (xof) xof.clean();
    const c2 = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(wTick1)).digest();
    for (const t of h) {
      let sum = 0;
      for (let i = 0; i < N; i++) sum += t[i];
      if (!(sum <= OMEGA)) return false;
    }
    for (const t of z) if (polyChknorm(t, GAMMA1 - BETA)) return false;
    return equalBytes(cTilde, c2);
  };
  const rndFromOpts = (opts) => {
    if (opts.extraEntropy === false) return new Uint8Array(32);
    throw new Error('fast-ml-dsa: only deterministic signing (extraEntropy: false) is supported');
  };
  // Phase 2 verify stages (same contract as the vendored noble `stages`, Float64Array polys)
  const stages = {
    decode: (publicKey, sig) => {
      const [rho, t1] = publicCoder.decode(publicKey);
      if (sig.length !== sigCoder.bytesLen) return false;
      const [cTilde, z, h] = sigCoder.decode(sig);
      if (h === false) return false;
      return { rho, t1, cTilde, z, h };
    },
    mu: (publicKey, M) => hashMu(shake256(publicKey, { dkLen: TR_BYTES }), M),
    expandA,
    t1Hat: (t1) =>
      t1.map((p) => {
        const q = toF64(p);
        for (let i = 0; i < N; i++) q[i] *= 1 << D;
        return ntt(q);
      }),
    wApprox: (A, t1, cTilde, z, t1Hat = null) => {
      const c = ntt(SampleInBall(cTilde));
      const zNtt = z.map((p) => ntt(toF64(p)));
      const acc = new Float64Array(N);
      const w = [];
      for (let i = 0; i < K; i++) {
        let t1h;
        if (t1Hat) t1h = t1Hat[i];
        else {
          t1h = toF64(t1[i]);
          for (let k = 0; k < N; k++) t1h[k] *= 1 << D;
          ntt(t1h);
        }
        const ct12d = pointwise(t1h, c);
        acc.fill(0);
        for (let j = 0; j < L; j++) mulAcc(acc, A[i][j], zNtt[j]);
        const Az = reduceAcc(acc, newPoly());
        for (let k = 0; k < N; k++) {
          const v = Az[k] - ct12d[k];
          Az[k] = v < 0 ? v + Q : v;
        }
        w.push(intt(Az));
      }
      return w;
    },
    hintCheck: (mu, w, h, z, cTilde) => {
      for (let i = 0; i < L; i++) if (polyChknorm(z[i], GAMMA1 - BETA)) return { ok: false, w1enc: null };
      const w1 = w.map((p, i) => useHint(toF64(p), h[i]));
      const w1enc = W1Vec.encode(w1);
      const c2 = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(w1enc).digest();
      for (const t of h) {
        let sum = 0;
        for (let i = 0; i < N; i++) sum += t[i];
        if (!(sum <= OMEGA)) return { ok: false, w1enc };
      }
      return { ok: equalBytes(cTilde, c2), w1enc };
    },
  };
  return {
    info: { type: 'ml-dsa-fastjs' },
    stages,
    lengths: { secretKey: secretCoder.bytesLen, publicKey: publicCoder.bytesLen, seed: 32, signature: sigCoder.bytesLen },
    keygen,
    sign: (msg, sk, opts = {}) => signExpanded(getMessage(msg, opts.context), expandSk(sk), rndFromOpts(opts)),
    verify: (sig, msg, pk, opts = {}) => {
      const [rho, t1] = publicCoder.decode(pk);
      const tr = shake256(pk, { dkLen: TR_BYTES });
      return verifyExpanded(sig, getMessage(msg, opts.context), { rho, t1, tr, A: null, t1Hat: null });
    },
    expandSk,
    signPrecomputed: (msg, exp, opts = {}) => signExpanded(getMessage(msg, opts.context), exp, rndFromOpts(opts)),
    expandPk,
    verifyPrecomputed: (sig, msg, exp, opts = {}) => verifyExpanded(sig, getMessage(msg, opts.context), exp),
  };
}

export const ml_dsa44 = createFastMlDsa(2);
export const ml_dsa65 = createFastMlDsa(3);
export const ml_dsa87 = createFastMlDsa(5);
