// One fresh-process paired benchmark. Run several forks; checks stay outside timing.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import os from 'node:os';

const numeric = (raw, name, { integer = false, zero = false } = {}) => {
  const value = Number(raw);
  if (String(raw).trim() === '' || !Number.isFinite(value) || (zero ? value < 0 : value <= 0)
      || (integer && !Number.isSafeInteger(value)))
    throw Error(`${name} must be a ${zero ? 'nonnegative' : 'positive'} ${integer ? 'safe integer' : 'finite number'}`);
  return value;
};
const fork = numeric(process.argv[2] ?? '0', 'fork', { integer: true, zero: true });
const rounds = numeric(process.env.ROUNDS ?? '6', 'ROUNDS', { integer: true });
const budgetMs = numeric(process.env.BUDGET_MS ?? '250', 'BUDGET_MS');
if (budgetMs * 1e6 > Number.MAX_SAFE_INTEGER) throw Error('BUDGET_MS exceeds exact nanosecond range');
const startedAt = new Date().toISOString();
const modes = JSON.parse(readFileSync(new URL('../build/multiply-add/mode.json', import.meta.url)));
assert.equal(modes.mode, 'rows', 'final benchmark requires the rows candidate');
assert.equal(modes.version, '0.7.1', 'final benchmark requires noble 0.7.1');
const provenanceFiles = {
  baseline: '../build/multiply-add/baseline/ml-dsa.js',
  candidate: '../build/multiply-add/candidate/ml-dsa.js',
  baseline_crystals: '../build/multiply-add/baseline/_crystals.js',
  candidate_crystals: '../build/multiply-add/candidate/_crystals.js',
  baseline_utils: '../build/multiply-add/baseline/utils.js',
  candidate_utils: '../build/multiply-add/candidate/utils.js',
  patch_ts: '../patches/ml-dsa-rowdot.patch',
  patch_js: '../patches/ml-dsa-rowdot-js.patch',
  validation_suite: '../../../common/validation/validation.json.gz',
  benchmark_script: './multiply-add-bench.mjs',
  prepare_script: './multiply-add-prepare.mjs',
  mode_manifest: '../build/multiply-add/mode.json',
  correctness_script: './multiply-add-check.mjs',
  arithmetic_script: './arithmetic-check.mjs',
  collector_script: './rowdot.mjs',
  lockfile: '../../../package-lock.json',
};
const hashFiles = () => Object.fromEntries(Object.entries(provenanceFiles).map(([name, path]) =>
  [name, { path, sha256: createHash('sha256').update(readFileSync(new URL(path, import.meta.url))).digest('hex') }]));
const provenance = hashFiles();
const baseline = await import('../build/multiply-add/baseline/ml-dsa.js');
const candidate = await import('../build/multiply-add/candidate/ml-dsa.js');
const derive = (label, length) => createHash('shake256', { outputLength: length }).update(`muladd-v1/${label}`).digest();
const rows = [];
const warmupMs = 300;
const warmupOrder = fork % 2 ? ['candidate', 'baseline'] : ['baseline', 'candidate'];
for (const level of [44, 65, 87]) {
  const name = `ml_dsa${level}`;
  const base = baseline[name], next = candidate[name];
  const corpus = Array.from({ length: 12 }, (_, i) => {
    const seed = derive(`${fork}/${level}/${i}/seed`, 32);
    const msg = derive(`${fork}/${level}/${i}/message`, [0, 64, 1024, 4096][i % 4]);
    const ctx = derive(`${fork}/${level}/${i}/context`, [0, 31, 255][i % 3]);
    const keys = base.keygen(seed);
    const opts = { context: ctx, extraEntropy: false };
    const sig = base.sign(msg, keys.secretKey, opts);
    assert.deepEqual(next.keygen(seed), keys);
    assert.deepEqual(base.getPublicKey(keys.secretKey), keys.publicKey);
    assert.deepEqual(next.getPublicKey(keys.secretKey), keys.publicKey);
    assert.deepEqual(next.sign(msg, keys.secretKey, opts), sig);
    assert.equal(base.verify(sig, msg, keys.publicKey, { context: ctx }), true);
    assert.equal(next.verify(sig, msg, keys.publicKey, { context: ctx }), true);
    return { seed, msg, ctx, keys, opts, sig };
  });
  for (const op of ['keygen', 'getPublicKey', 'sign', 'verify']) {
    const invoke = (alg, c) => op === 'keygen' ? alg.keygen(c.seed)
      : op === 'getPublicKey' ? alg.getPublicKey(c.keys.secretKey)
      : op === 'sign' ? alg.sign(c.msg, c.keys.secretKey, c.opts)
        : alg.verify(c.sig, c.msg, c.keys.publicKey, { context: c.ctx });
    const measure = (alg, ms) => {
      let iterations = 0, last;
      const cpuStart = process.cpuUsage();
      const start = process.hrtime.bigint();
      let elapsed;
      do {
        // Complete whole corpus cycles so rejection-sampling paths have equal weights.
        for (const c of corpus) {
          last = invoke(alg, c);
          iterations++;
        }
        elapsed = Number(process.hrtime.bigint() - start);
      } while (elapsed < ms * 1e6 || iterations < corpus.length);
      const cpu = process.cpuUsage(cpuStart);
      const c = corpus[(iterations - 1) % corpus.length];
      if (op === 'verify') assert.equal(last, true);
      else assert.deepEqual(last, op === 'sign' ? c.sig : op === 'getPublicKey' ? c.keys.publicKey : c.keys);
      return { iterations, ns_per_op: elapsed / iterations, cpu_ns_per_op: (cpu.user + cpu.system) * 1000 / iterations };
    };
    for (const variant of warmupOrder) measure(variant === 'baseline' ? base : next, warmupMs);
    for (let round = 0; round < rounds; round++) {
      const order = (fork + round) % 2 ? ['candidate', 'baseline'] : ['baseline', 'candidate'];
      const pair = {};
      for (const variant of order) pair[variant] = measure(variant === 'baseline' ? base : next, budgetMs);
      rows.push({ level, op, round, order, ...pair, speedup: pair.baseline.ns_per_op / pair.candidate.ns_per_op });
    }
  }
}
assert.deepEqual(hashFiles(), provenance, 'benchmark inputs changed during the run');
console.log(JSON.stringify({ fork, ...modes, runtime: process.version, arch: process.arch, platform: process.platform,
  cpu: os.cpus()[0].model, os_release: os.release(), exec_path: process.execPath, exec_argv: process.execArgv,
  node_options: process.env.NODE_OPTIONS ?? '', v8: process.versions.v8, started_at: startedAt, finished_at: new Date().toISOString(),
  corpus_cases: 36, corpus_id: 'muladd-v1', rounds, budgetMs, warmupMs, warmupOrder, provenance, rows }));
