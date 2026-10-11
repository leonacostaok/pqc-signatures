// Stage pipelines + per-variant stage implementations (shared by stages-one.mjs, validate and memory).
import { bytesToHex } from '@noble/hashes/utils.js';
import { getMessage } from '@noble/post-quantum/utils.js';
import { familyOf, loadAlg } from './algs.mjs';
import { digest, sameBytes } from './refcheck.mjs';
import { fastUnpackDecode, wApproxIntMod } from './stage-impls.mjs';

export const formatM = (msg, ctx) => getMessage(msg, ctx && ctx.length ? ctx : undefined);
export const u32le = (polys) => {
  const flat = polys.flat();
  const out = new Uint8Array(flat.length * N * 4);
  const dv = new DataView(out.buffer);
  let o = 0;
  for (const p of flat) for (let i = 0; i < N; i++, o += 4) dv.setUint32(o, p[i], true);
  return out;
};
const N = 256;
const concat = (arrs) => {
  const out = new Uint8Array(arrs.reduce((a, b) => a + b.length, 0));
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
};

// ---- end-to-end pipelines over a stage-function set S (vendor, fast, or mixed)
export function mlPipeline(S, pk, M, sig) {
  const dec = S.decode(pk, sig);
  if (!dec) return false;
  const mu = S.mu(pk, M);
  const A = S.expandA(dec.rho);
  const w = S.wApprox(A, dec.t1, dec.cTilde, dec.z);
  return S.hintCheck(mu, w, dec.h, dec.z, dec.cTilde).ok === true;
}
export function slhPipeline(S, pk, M, sig) {
  const h = S.hmsg(pk, M, sig);
  if (!h) return false;
  let msg = S.fors(h.context, h.forsVec, h.md, h.tree, h.leafIdx);
  const layers = S.layers(h.tree, h.leafIdx);
  for (let i = 0; i < layers.length; i++) {
    const [wots, auth] = h.wotsVec[i];
    const leaf = S.wotsPkFromSig(h.context, wots, msg, i, layers[i].tree, layers[i].leafIdx);
    msg = S.xmssRoot(h.context, leaf, auth, i, layers[i].tree, layers[i].leafIdx);
  }
  return sameBytes(msg, h.pubRoot);
}
// stage-function sets
export async function stageSets(param) {
  const fam = familyOf(param);
  const vendor = (await loadAlg('vendor', param)).stages;
  const fast = (await loadAlg('fast', param)).stages;
  let best;
  if (fam === 'ml-dsa') best = { ...fast, decode: fastUnpackDecode(param) };
  else best = fast;
  return { fam, vendor, fast, best };
}
export const pipelineFor = (fam) => (fam === 'ml-dsa' ? mlPipeline : slhPipeline);
// verify with context through a pipeline (validation + total/total_best)
export const pipelineVerify = (fam, S, sig, msg, pk, ctx) => {
  try {
    return pipelineFor(fam)(S, pk, formatM(msg, ctx), sig) === true;
  } catch {
    return false;
  }
};

// ---- canonical intermediate values for a (pk, M, sig), computed with noble's own code
export function canonicalContext(fam, vendor, pk, M, sig) {
  const ctx = { pk, M, sig };
  if (fam === 'ml-dsa') {
    ctx.dec = vendor.decode(pk, sig);
    ctx.mu = vendor.mu(pk, M);
    ctx.A = vendor.expandA(ctx.dec.rho);
    ctx.w = vendor.wApprox(ctx.A, ctx.dec.t1, ctx.dec.cTilde, ctx.dec.z);
    const hc = vendor.hintCheck(ctx.mu, ctx.w, ctx.dec.h, ctx.dec.z, ctx.dec.cTilde);
    if (!hc.ok) throw new Error('canonical pipeline rejected the reference signature');
    ctx.outputs = { decode: digest(ctx.dec.cTilde), mu: digest(ctx.mu), expandA: digest(u32le(ctx.A)), w_approx: digest(u32le(ctx.w)), hint_check: digest(hc.w1enc) };
  } else {
    const h = vendor.hmsg(pk, M, sig);
    ctx.h = h;
    ctx.forsPk = vendor.fors(h.context, h.forsVec, h.md, h.tree, h.leafIdx);
    ctx.layers = vendor.layers(h.tree, h.leafIdx);
    ctx.layerMsgs = [];
    ctx.wotsPks = [];
    ctx.roots = [];
    let msg = ctx.forsPk;
    for (let i = 0; i < ctx.layers.length; i++) {
      ctx.layerMsgs.push(msg);
      const [wots, auth] = h.wotsVec[i];
      const leaf = vendor.wotsPkFromSig(h.context, wots, msg, i, ctx.layers[i].tree, ctx.layers[i].leafIdx);
      ctx.wotsPks.push(leaf);
      msg = vendor.xmssRoot(h.context, leaf, auth, i, ctx.layers[i].tree, ctx.layers[i].leafIdx);
      ctx.roots.push(msg);
    }
    if (!sameBytes(msg, h.pubRoot)) throw new Error('canonical pipeline rejected the reference signature');
    ctx.outputs = { hmsg: digest(h.digest), fors: digest(ctx.forsPk), ht_wots: digest(concat(ctx.wotsPks)), ht_auth: digest(concat(ctx.roots)) };
  }
  return ctx;
}

// ---- per-variant stage implementation: { prepare(ctx) -> state, run(state) -> result, encode(result) -> bytes, async? }
export async function stageImpl(v, param, sets, workersFactory) {
  const { fam, vendor, fast, best } = sets;
  const S = v.impl === 'fast' ? fast : v.impl === 'best' ? best : vendor;
  const { pk, M, sig } = { pk: null, M: null, sig: null };
  switch (v.stage) {
    case 'decode':
      if (v.impl === 'alt:unpack') {
        const f = fastUnpackDecode(param);
        return { prepare: (c) => c, run: (c) => f(c.pk, c.sig), encode: (r) => r.cTilde };
      }
      return { prepare: (c) => c, run: (c) => S.decode(c.pk, c.sig), encode: (r) => r.cTilde };
    case 'mu':
      if (v.impl === 'alt:trcache') return { prepare: (c) => ({ tr: vendor.tr(c.pk), M: c.M }), run: (s) => vendor.muFromTr(s.tr, s.M), encode: (r) => r };
      return { prepare: (c) => c, run: (c) => S.mu(c.pk, c.M), encode: (r) => r };
    case 'expandA':
      if (v.impl === 'alt:acache') {
        return {
          prepare: (c) => {
            const key = bytesToHex(c.dec.rho);
            const cache = new Map([[key, vendor.expandA(c.dec.rho)]]);
            return { cache, key };
          },
          run: (s) => s.cache.get(s.key),
          encode: u32le,
        };
      }
      if (v.impl === 'alt:aworkers') {
        const pool = await workersFactory(param);
        return {
          prepare: (c) => ({ rho: c.dec.rho, K: c.A.length, pool }),
          run: (s) => s.pool.expand(s.rho, s.K),
          encode: u32le,
          async: true,
          close: () => pool.close(),
        };
      }
      return { prepare: (c) => c, run: (c) => S.expandA(c.dec.rho), encode: u32le };
    case 'w_approx':
      if (v.impl === 'alt:t1hat') return { prepare: (c) => ({ ...c, t1Hat: vendor.t1Hat(c.dec.t1) }), run: (c) => vendor.wApprox(c.A, c.dec.t1, c.dec.cTilde, c.dec.z, c.t1Hat), encode: u32le };
      if (v.impl === 'alt:intmod') {
        const f = wApproxIntMod(param, vendor.sampleInBall);
        return { prepare: (c) => c, run: (c) => f(c.A, c.dec.t1, c.dec.cTilde, c.dec.z), encode: u32le };
      }
      return { prepare: (c) => c, run: (c) => S.wApprox(c.A, c.dec.t1, c.dec.cTilde, c.dec.z), encode: u32le };
    case 'hint_check':
      return {
        prepare: (c) => c,
        run: (c) => {
          const r = S.hintCheck(c.mu, c.w, c.dec.h, c.dec.z, c.dec.cTilde);
          if (!r.ok) throw new Error('hint_check rejected the reference signature');
          return r.w1enc;
        },
        encode: (r) => r,
      };
    case 'hmsg':
      return { prepare: (c) => c, run: (c) => S.hmsg(c.pk, c.M, c.sig).digest, encode: (r) => r };
    case 'fors':
      return { prepare: (c) => ({ h: S.hmsg(c.pk, c.M, c.sig) }), run: (s) => S.fors(s.h.context, s.h.forsVec, s.h.md, s.h.tree, s.h.leafIdx), encode: (r) => r };
    case 'ht_wots':
      return {
        prepare: (c) => ({ h: S.hmsg(c.pk, c.M, c.sig), layers: c.layers, msgs: c.layerMsgs }),
        run: (s) => s.layers.map((ly, i) => S.wotsPkFromSig(s.h.context, s.h.wotsVec[i][0], s.msgs[i], i, ly.tree, ly.leafIdx)),
        encode: concat,
      };
    case 'ht_auth':
      return {
        prepare: (c) => ({ h: S.hmsg(c.pk, c.M, c.sig), layers: c.layers, leaves: c.wotsPks }),
        run: (s) => {
          const roots = s.layers.map((ly, i) => S.xmssRoot(s.h.context, s.leaves[i], s.h.wotsVec[i][1], i, ly.tree, ly.leafIdx));
          if (!sameBytes(roots[roots.length - 1], s.h.pubRoot)) throw new Error('ht_auth: root mismatch');
          return roots;
        },
        encode: concat,
      };
    case 'total':
    case 'total_best': {
      const P = pipelineFor(fam);
      return { prepare: (c) => c, run: (c) => P(S, c.pk, c.M, c.sig), encode: (r) => r, tamper: (c, tsig) => P(S, c.pk, c.M, tsig) };
    }
    default:
      throw new Error(`unknown stage ${v.stage}`);
  }
}

// worker pool for expandA.v4
export async function makeExpandWorkers(param, threads = 4) {
  const { Worker } = await import('node:worker_threads');
  const workers = [];
  for (let i = 0; i < threads; i++) {
    const w = new Worker(new URL('./stage-worker.mjs', import.meta.url), { workerData: { param } });
    await new Promise((res, rej) => {
      w.once('message', res);
      w.once('error', rej);
    });
    workers.push(w);
  }
  return {
    expand: (rho, K) =>
      Promise.all(
        workers.map((w, t) => {
          const rows = [];
          for (let i = t; i < K; i += threads) rows.push(i);
          if (!rows.length) return Promise.resolve({ rows, polys: [] });
          return new Promise((res, rej) => {
            w.once('message', res);
            w.once('error', rej);
            w.postMessage({ rho, rows });
          });
        })
      ).then((parts) => {
        const A = new Array(K);
        for (const p of parts) p.rows.forEach((i, k) => (A[i] = p.polys[k]));
        return A;
      }),
    close: () => Promise.all(workers.map((w) => w.terminate())),
  };
}
