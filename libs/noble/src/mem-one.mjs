// Stack / heap measurement of one op in this process (node or bun).
//   --calibrate                 print the max recursion depth of the probe (used with two known stack
//                               sizes to derive bytes per probe frame)
//   --variant <id> --param <p>  measure one variant (bench variant id, or a stage variant id with --stage)
//   --frame-bytes <n>           bytes per probe frame (from calibration)
//   --in-worker                 run the measurement inside a worker_thread (per-worker stack)
//   --heap                      also measure heap (node only: needs --expose-gc; sampling profiler)
// Method: a recursive probe function fills the stack to a chosen depth and then calls the op; the
// largest depth at which the op still completes (binary search, after JIT warm-up of probe and op)
// is compared with the largest depth at which an empty call completes; the difference times the
// calibrated frame size is the op's peak stack usage.
import { LIB, MESSAGE, loadAlg, familyOf } from './algs.mjs';
import { variantById } from './variants.mjs';
import { referenceInputs, digest, flipBit } from './refcheck.mjs';
import { STAGE_VARIANTS } from './stage-impls.mjs';
import { canonicalContext, formatM, stageImpl, stageSets } from './stage-lib.mjs';

const args = Object.fromEntries(process.argv.slice(2).map((a, i, arr) => (a.startsWith('--') ? [a.slice(2), arr[i + 1] && !arr[i + 1].startsWith('--') ? arr[i + 1] : true] : [])).filter((x) => x.length));

// ---- probe: a frame with a few live locals; depth-first recursion then the payload call
let sink = 0;
function probe(depth, fn) {
  const a = depth + 1;
  const b = a * 2;
  if (depth <= 0) return fn();
  const r = probe(depth - 1, fn);
  sink += (a ^ b) & 1;
  return r;
}
const isOverflow = (e) => e instanceof RangeError && /stack/i.test(String(e.message));
function ok(depth, fn) {
  try {
    probe(depth, fn);
    return true;
  } catch (e) {
    if (isOverflow(e)) return false;
    throw e;
  }
}
// largest depth in [0, hi] for which ok(); assumes monotone
function maxDepth(fn, hi, step) {
  let lo = 0;
  if (!ok(0, fn)) throw new Error('op fails even with an empty stack');
  if (ok(hi, fn)) return hi;
  while (hi - lo > step) {
    const mid = (lo + hi) >> 1;
    if (ok(mid, fn)) lo = mid;
    else hi = mid;
  }
  return lo;
}
const noop = () => 0;
function warm(fn) {
  for (let i = 0; i < 300; i++) {
    ok(3000, noop);
    ok(6, fn);
  }
  for (let i = 0; i < 5; i++) ok(4_000_000, noop); // overflow a few times so that path is also warm
}
// The probe's frame size depends on its JIT tier, so (dNoop, dOp) are re-measured until two
// consecutive rounds agree within one step; the op itself is warmed up first (JIT state as in bench).
async function measure(fn, frameBytes) {
  for (let i = 0; i < 25; i++) fn();
  warm(fn);
  const step = 4;
  let prev = null;
  let res = null;
  for (let round = 0; round < 12; round++) {
    const dNoop = maxDepth(noop, 4_000_000, 1);
    const dOp = maxDepth(fn, dNoop, step);
    const dNoop2 = maxDepth(noop, 4_000_000, 1);
    res = { dNoop: Math.min(dNoop, dNoop2), dOp };
    if (Math.abs(dNoop - dNoop2) <= step && prev && Math.abs(prev.dNoop - res.dNoop) <= step && Math.abs(prev.dOp - res.dOp) <= step) break;
    prev = res;
  }
  return { stack_bytes: (res.dNoop - res.dOp) * frameBytes, stack_resolution_bytes: step * frameBytes, probe_depth_noop: res.dNoop, probe_depth_op: res.dOp };
}
async function heap(fn) {
  if (typeof globalThis.gc !== 'function' || typeof Bun !== 'undefined') return { heap_alloc_bytes_per_op: null, heap_peak_bytes: null, heap_method: null };
  const out = {};
  // retained + garbage at op end, before any GC (upper bound for the live peak if no GC ran mid-op)
  globalThis.gc();
  const h0 = process.memoryUsage().heapUsed;
  fn();
  const h1 = process.memoryUsage().heapUsed;
  out.heap_peak_bytes = Math.max(0, h1 - h0);
  // allocation volume per op: V8 sampling heap profiler over 10 ops
  try {
    const inspector = await import('node:inspector');
    const s = new inspector.Session();
    s.connect();
    const post = (m, p) => new Promise((res, rej) => s.post(m, p, (e, r) => (e ? rej(e) : res(r))));
    await post('HeapProfiler.enable');
    await post('HeapProfiler.startSampling', { samplingInterval: 256, includeObjectsCollectedByMajorGC: true, includeObjectsCollectedByMinorGC: true });
    const ITER = 10;
    for (let i = 0; i < ITER; i++) fn();
    const { profile } = await post('HeapProfiler.stopSampling');
    let total = 0;
    for (const smp of profile.samples) total += smp.size;
    s.disconnect();
    out.heap_alloc_bytes_per_op = Math.round(total / ITER);
    out.heap_method = 'V8 sampling heap profiler (interval 256 B, 10 ops) for allocation volume; peak = heapUsed delta of one op before GC (--expose-gc)';
  } catch (e) {
    out.heap_alloc_bytes_per_op = null;
    out.heap_method = 'peak only: heapUsed delta of one op before GC';
  }
  return out;
}

if (args['in-worker']) {
  // per-worker stack: run this same measurement inside a worker_thread (its stdout is forwarded)
  const { Worker } = await import('node:worker_threads');
  const argv = process.argv.slice(2).filter((a) => a !== '--in-worker');
  const w = new Worker(new URL(import.meta.url), { argv, execArgv: process.execArgv.filter((a) => a !== '--expose-gc') });
  await new Promise((res, rej) => {
    w.on('exit', res);
    w.on('error', rej);
  });
  process.exit(0);
}
if (args.calibrate) {
  warm(noop);
  console.log(JSON.stringify({ depth: maxDepth(noop, 4_000_000, 1) }));
  process.exit(0);
}

const frameBytes = Number(args['frame-bytes']);
const param = args.param;
const fam = familyOf(param);
let fn;
let matched = true;
let op;
let extra = {};
if (args.stage) {
  const v = STAGE_VARIANTS.find((x) => x.id === args.variant);
  const ref = await referenceInputs(param);
  const sets = await stageSets(param);
  const M = formatM(MESSAGE, new Uint8Array(0));
  const ctx = canonicalContext(fam, sets.vendor, ref.pk, M, ref.sig);
  const impl = await stageImpl(v, param, sets, null);
  const state = impl.prepare(ctx);
  op = 'verify-stage';
  extra.stage = v.stage;
  fn = () => impl.run(state);
  const r = fn();
  if (v.stage === 'total' || v.stage === 'total_best') matched = r === true && impl.tamper(state, flipBit(ref.sig)) === false;
  else matched = digest(impl.encode(r)) === ctx.outputs[v.stage];
} else {
  const v = variantById(args.variant);
  const ref = await referenceInputs(param);
  const alg = await loadAlg(v.backend, param);
  op = v.op;
  if (op === 'keygen') {
    fn = () => alg.keygen(ref.seed);
    const r = fn();
    matched = digest(r.publicKey) === ref.pk_sha256 && digest(r.secretKey) === ref.sk_sha256;
  } else if (op === 'sign') {
    if (v.mode === 'precomputed') {
      const exp = alg.expandSk(ref.sk);
      fn = () => alg.signPrecomputed(MESSAGE, exp);
    } else fn = () => alg.sign(MESSAGE, ref.sk);
    matched = digest(fn()) === ref.sig_sha256;
  } else {
    if (v.mode === 'precomputed') {
      const exp = alg.expandPk(ref.pk);
      fn = () => alg.verifyPrecomputed(ref.sig, MESSAGE, exp);
      matched = fn() === true && alg.verifyPrecomputed(flipBit(ref.sig), MESSAGE, exp) === false;
    } else {
      fn = () => alg.verify(ref.sig, MESSAGE, ref.pk);
      matched = fn() === true && alg.verify(flipBit(ref.sig), MESSAGE, ref.pk) === false;
    }
  }
}
const stack = await measure(fn, frameBytes);
const h = args.heap ? await heap(fn) : { heap_alloc_bytes_per_op: null, heap_peak_bytes: null, heap_method: null };
console.log(JSON.stringify({ lib: LIB, variant: args.variant, op, param, ...extra, ...stack, ...h, match: matched }));
