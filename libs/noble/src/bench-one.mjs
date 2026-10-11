// Measures one variant for one or more params in this process and prints one JSON line per param.
// Usage: node bench-one.mjs --variant sign.v2 --params ML-DSA-44,ML-DSA-65 --budget-ms 1000
// The hash layer is selected by env NOBLE_PQ_HASH (set by bench.mjs); the runtime (node/bun) is
// whatever executes this file.
import { LIB, LIB_VERSION, MESSAGE, loadAlg } from './algs.mjs';
import { variantById, variantApplies } from './variants.mjs';
import { referenceInputs, digest, flipBit, sameBytes } from './refcheck.mjs';
import { measureSingle, finish, cpuNs } from './timing.mjs';

const args = Object.fromEntries(process.argv.slice(2).map((a, i, arr) => (a.startsWith('--') ? [a.slice(2), arr[i + 1]] : [])).filter((x) => x.length));
const v = variantById(args.variant);
if (!v) throw new Error(`unknown variant ${args.variant}`);
const params = args.params.split(',');
const budgetMs = Number(args['budget-ms'] || 1000);
const runtimeName = typeof Bun !== 'undefined' ? `bun ${Bun.version}` : `node ${process.versions.node}`;
const hrNow = () => process.hrtime.bigint();

const line = (param, stats, output_sha256, match, extra = {}) => {
  const rec = {
    lib: LIB,
    lib_version: LIB_VERSION,
    lang: 'js',
    runtime: runtimeName,
    variant: v.id,
    variant_name: v.name,
    variant_desc: v.desc,
    op: v.op,
    param,
    ...stats,
    output_sha256,
    match,
    ...extra,
  };
  process.stdout.write(JSON.stringify(rec) + '\n');
};

async function runSingle(param) {
  const ref = await referenceInputs(param);
  const alg = await loadAlg(v.backend, param);
  const { op } = v;
  let fn;
  let check;
  let output_sha256;
  let matched = true;
  const extra = {};
  if (op === 'keygen') {
    let first = null;
    fn = () => alg.keygen(ref.seed);
    check = (r) => {
      if (first === null) {
        first = r;
        const pkd = digest(r.publicKey);
        const skd = digest(r.secretKey);
        output_sha256 = pkd;
        extra.pk_sha256 = pkd;
        extra.sk_sha256 = skd;
        if (pkd !== ref.pk_sha256 || skd !== ref.sk_sha256) matched = false;
      } else if (!sameBytes(r.publicKey, first.publicKey) || !sameBytes(r.secretKey, first.secretKey)) matched = false;
    };
  } else if (op === 'sign') {
    let first = null;
    if (v.mode === 'precomputed') {
      if (!alg.expandSk) throw new Error(`${v.id}: backend has no expandSk for ${param}`);
      const exp = alg.expandSk(ref.sk);
      fn = () => alg.signPrecomputed(MESSAGE, exp);
    } else fn = () => alg.sign(MESSAGE, ref.sk);
    check = (s) => {
      if (first === null) {
        first = s;
        output_sha256 = digest(s);
        if (output_sha256 !== ref.sig_sha256) matched = false;
      } else if (!sameBytes(s, first)) matched = false;
    };
  } else {
    let verifyFn;
    if (v.mode === 'precomputed') {
      if (!alg.expandPk) throw new Error(`${v.id}: backend has no expandPk for ${param}`);
      const exp = alg.expandPk(ref.pk);
      verifyFn = (sig) => alg.verifyPrecomputed(sig, MESSAGE, exp);
    } else verifyFn = (sig) => alg.verify(sig, MESSAGE, ref.pk);
    fn = () => verifyFn(ref.sig);
    check = (r) => {
      if (r !== true) matched = false;
    };
  }
  const stats = measureSingle(fn, check, budgetMs);
  if (op === 'verify') {
    let tamper = false;
    try {
      tamper = fn.call(null) === true && (v.mode === 'precomputed' ? alg.verifyPrecomputed(flipBit(ref.sig), MESSAGE, alg.expandPk(ref.pk)) : alg.verify(flipBit(ref.sig), MESSAGE, ref.pk)) === false;
    } catch {
      tamper = false;
    }
    extra.tamper_rejected = tamper;
    matched = matched && tamper;
    output_sha256 = matched ? 'true' : 'false';
  }
  extra.reference = ref.reference;
  line(param, stats, output_sha256, matched, extra);
}

async function runWorkers(param) {
  const { Worker } = await import('node:worker_threads');
  const ref = await referenceInputs(param);
  const threads = v.threads;
  const workers = [];
  const inputs = { type: 'inputs', seed: ref.seed, sk: ref.sk, pk: ref.pk, sig: ref.sig };
  for (let i = 0; i < threads; i++) {
    const w = new Worker(new URL('./worker.mjs', import.meta.url), { workerData: { param, op: v.op, backend: v.backend } });
    await new Promise((res, rej) => {
      w.once('message', res);
      w.once('error', rej);
    });
    w.postMessage(inputs);
    await new Promise((res) => w.once('message', res));
    workers.push(w);
  }
  const batch = (count) =>
    Promise.all(
      workers.map(
        (w) =>
          new Promise((res, rej) => {
            w.once('message', res);
            w.once('error', rej);
            w.postMessage({ type: 'run', count });
          })
      )
    );
  let matched = true;
  const extra = {};
  let output_sha256;
  const checkResults = (rs) => {
    for (const r of rs) {
      if (!r.ok) matched = false;
      if (v.op === 'keygen') {
        output_sha256 = r.pk_sha256;
        extra.pk_sha256 = r.pk_sha256;
        extra.sk_sha256 = r.sk_sha256;
        if (r.pk_sha256 !== ref.pk_sha256 || r.sk_sha256 !== ref.sk_sha256) matched = false;
      } else if (v.op === 'sign') {
        output_sha256 = r.sig_sha256;
        if (r.sig_sha256 !== ref.sig_sha256) matched = false;
      } else {
        if (!r.tamper_rejected) matched = false;
        extra.tamper_rejected = r.tamper_rejected;
      }
    }
  };
  // warm-up: one op per worker first (also gives the per-op estimate), then more if fast
  let t0 = hrNow();
  checkResults(await batch(1));
  const est = Number(hrNow() - t0); // ns per op per thread
  let k = Math.max(1, Math.min(1000, Math.ceil(20e6 / est))); // ops per worker per batch (>= ~20 ms batches)
  if (est < 1e9) {
    const warmStart = hrNow();
    let n = threads;
    while ((n < 20 || Number(hrNow() - warmStart) < 200e6) && Number(hrNow() - warmStart) < 3000e6) {
      checkResults(await batch(k));
      n += k * threads;
    }
  }
  const perOp = [];
  let ops = 0;
  const cpu0 = cpuNs();
  const loopStart = hrNow();
  let minBatches = 3;
  for (let b = 0; ; b++) {
    const s = hrNow();
    const rs = await batch(k);
    const dt = Number(hrNow() - s);
    checkResults(rs);
    const n = k * threads;
    for (let i = 0; i < n; i++) perOp.push(dt / n);
    ops += n;
    if (b === 0 && dt > 5e9) minBatches = 2;
    const elapsedMs = Number(hrNow() - loopStart) / 1e6;
    if ((elapsedMs >= budgetMs && b + 1 >= minBatches) || ops >= 100000) break;
  }
  const loopWall = Number(hrNow() - loopStart);
  const cpu = cpuNs() - cpu0;
  const stats = finish(perOp, loopWall, cpu, ops, threads);
  stats.batch_size = k * threads;
  if (v.op === 'verify') output_sha256 = matched ? 'true' : 'false';
  extra.reference = ref.reference;
  line(param, stats, output_sha256, matched, extra);
  for (const w of workers) await w.terminate();
}

for (const param of params) {
  if (!variantApplies(v, param)) continue;
  if (v.mode === 'workers') await runWorkers(param);
  else await runSingle(param);
}
