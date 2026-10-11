// The 18 variants (6 per process). Fields:
//   backend: 'pkg' | 'vendor' | 'fast'      (see algs.mjs)
//   hash:    'noble' | 'native'              (hash layer for vendor/fast, env NOBLE_PQ_HASH)
//   runtime: 'node' | 'bun'
//   mode:    'single' | 'precomputed' | 'workers'
import { familyOf } from './algs.mjs';

const desc = {
  baseline: 'Plain @noble/post-quantum 0.7.1 API under Node (keygen(seed) / sign(msg, sk, {extraEntropy:false}) / verify).',
  native:
    'Vendored noble with its @noble/hashes SHAKE128/SHAKE256/SHA-2 calls routed to node:crypto (OpenSSL) via a drop-in shim; XOF output is squeezed in one native call and extended by the SHAKE prefix property.',
  fastjs:
    'Pure-JS rewrite of the hot paths: branch-free lazily-reduced NTT on Float64Array polys with fused multiply-accumulate (ML-DSA); direct SHA-2 compression-function / keccakP calls on pre-padded blocks and allocation-free ADRS handling (SLH-DSA).',
  allin: 'fastjs rewrite combined with the node:crypto hash layer (the fastest single-threaded combination).',
  bun: 'Unmodified @noble/post-quantum executed by the Bun runtime (JavaScriptCore JIT) instead of Node/V8.',
  workers: 'Throughput variant: 4 worker_threads each run the unmodified baseline on their own copy of the inputs; ops/sec is measured over the whole batch.',
  keycache:
    'Per-secret-key precomputation cached across signatures: ML-DSA caches skDecode + ExpandA + NTT(s1,s2,t0); SLH-DSA caches the hash context and all nodes of the (key-only) top-layer XMSS tree; Falcon caches the secret basis (G completion + FFT of [[g,-f],[G,-F]]).',
  pkcache:
    'Per-public-key precomputation cached across verifications: ML-DSA caches pkDecode + tr + ExpandA + NTT(t1*2^d); Falcon caches NTT(h); SLH-DSA caches the decoded pk and the PK.seed hash midstates (little to cache).',
};

const V = (id, name, d, o) => ({ id, name, desc: d, backend: 'pkg', hash: 'noble', runtime: 'node', mode: 'single', ...o });

export const VARIANTS = [];
for (const op of ['keygen', 'sign', 'verify']) {
  VARIANTS.push(V(`${op}.v0`, 'baseline', desc.baseline, { op }));
  VARIANTS.push(V(`${op}.v1`, 'native-hash', desc.native, { op, backend: 'vendor', hash: 'native' }));
  VARIANTS.push(V(`${op}.v2`, 'fastjs', desc.fastjs, { op, backend: 'fast' }));
  if (op === 'keygen') VARIANTS.push(V(`${op}.v3`, 'fastjs+native', desc.allin, { op, backend: 'fast', hash: 'native' }));
  if (op === 'sign') VARIANTS.push(V(`${op}.v3`, 'keycache', desc.keycache, { op, backend: 'vendor', mode: 'precomputed' }));
  if (op === 'verify') VARIANTS.push(V(`${op}.v3`, 'pkcache', desc.pkcache, { op, backend: 'vendor', mode: 'precomputed' }));
  VARIANTS.push(V(`${op}.v4`, 'bun', desc.bun, { op, runtime: 'bun' }));
  VARIANTS.push(V(`${op}.v5`, 'workers-x4', desc.workers, { op, mode: 'workers', threads: 4 }));
}

export const variantById = (id) => VARIANTS.find((v) => v.id === id);
// Variants whose mechanism does not exist for a param are skipped (the 'fast' rewrite has no Falcon).
export const variantApplies = (v, param) => !(v.backend === 'fast' && familyOf(param) === 'falcon');
