// memory --out <file.jsonl> [--params a,b] [--variants id,id] [--no-stages] [--no-heap]
// Stack per op for every bench variant (and every verify stage v0 + total_best), heap where possible.
// Stack method (JS): in-process recursion probe (see mem-one.mjs); bytes per probe frame are calibrated
// per runtime by running the probe at two known stack sizes (node --stack-size, bun via ulimit -s).
import { spawnSync } from 'node:child_process';
import { appendFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PARAM_NAMES, familyOf } from './algs.mjs';
import { VARIANTS, variantApplies } from './variants.mjs';
import { STAGE_VARIANTS, stageVariantApplies } from './stage-impls.mjs';

const argv = process.argv.slice(2);
const args = {};
for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) args[argv[i].slice(2)] = i + 1 < argv.length && !argv[i + 1].startsWith('--') ? argv[++i] : true;
if (!args.out) {
  console.error('usage: memory --out <file.jsonl> [--params a,b] [--variants id,id] [--no-stages] [--no-heap] [--append]');
  process.exit(2);
}
const params = args.params ? args.params.split(',') : PARAM_NAMES;
const bunBin = process.env.BUN_BIN || `${process.env.HOME || '/root'}/.bun/bin/bun`;
const haveBun = existsSync(bunBin);
const one = fileURLToPath(new URL('./mem-one.mjs', import.meta.url));

const run = (cmd, cargs, opts = {}) => spawnSync(cmd, cargs, { encoding: 'utf8', maxBuffer: 64 << 20, env: process.env, ...opts });
const lastJson = (s) => {
  const ls = (s || '').split('\n').filter((l) => l.trim().startsWith('{'));
  return ls.length ? JSON.parse(ls[ls.length - 1]) : null;
};
// ---- calibration: bytes per probe frame
function calibrateNode() {
  const d = (kb) => lastJson(run(process.execPath, [`--stack-size=${kb}`, one, '--calibrate']).stdout).depth;
  const d1 = d(512), d2 = d(1024);
  return Math.round((512 * 1024) / (d2 - d1));
}
function calibrateBun() {
  const d = (kb) => lastJson(run('bash', ['-c', `ulimit -s ${kb}; "${bunBin}" "${one}" --calibrate`]).stdout).depth;
  const d1 = d(1024), d2 = d(2048);
  return Math.round((1024 * 1024) / (d2 - d1));
}
const frameNode = calibrateNode();
const frameBun = haveBun ? calibrateBun() : null;
console.error(`[noble] memory: probe frame = ${frameNode} B (node)${haveBun ? `, ${frameBun} B (bun)` : ''}`);
const method = (rt, threads) =>
  `in-process recursion probe: max probe depth with vs. without the op (binary search, JIT-warmed), times the calibrated frame size (${rt === 'bun' ? frameBun : frameNode} B from two known stack sizes)${threads > 1 ? '; measured inside one worker_thread' : ''}`;

if (!args.append) writeFileSync(args.out, '');
const jobs = [];
for (const v of VARIANTS.filter((v) => !args.variants || args.variants.split(',').includes(v.id)))
  for (const p of params) if (variantApplies(v, p)) jobs.push({ v, p, stage: false });
if (!args['no-stages'])
  for (const v of STAGE_VARIANTS.filter((v) => v.id.endsWith('.v0') && (!args.variants || args.variants.split(',').includes(v.id))))
    for (const p of params) if (stageVariantApplies(v, p)) jobs.push({ v, p, stage: true });

for (const { v, p, stage } of jobs) {
  const t0 = Date.now();
  const rt = v.runtime || 'node';
  const threads = v.threads || 1;
  const base = [one, '--variant', v.id, '--param', p, '--frame-bytes', String(rt === 'bun' ? frameBun : frameNode)];
  if (stage) base.push('--stage', '1');
  let r;
  if (rt === 'bun') {
    if (!haveBun) continue;
    r = run(bunBin, base);
  } else {
    const nodeArgs = ['--expose-gc', ...base];
    if (!args['no-heap']) nodeArgs.push('--heap');
    if (v.mode === 'workers') nodeArgs.push('--in-worker');
    r = run(process.execPath, nodeArgs);
  }
  const j = lastJson(r.stdout);
  if (!j) {
    console.error(`[noble] memory ${v.id} ${p} FAILED: ${(r.stderr || '').slice(-400)}`);
    continue;
  }
  const rec = {
    lib: 'noble',
    variant: v.id,
    op: j.op,
    param: p,
    ...(j.stage ? { stage: j.stage } : {}),
    stack_bytes: j.stack_bytes,
    stack_method: method(rt, threads),
    stack_resolution_bytes: j.stack_resolution_bytes,
    heap_alloc_bytes_per_op: j.heap_alloc_bytes_per_op,
    heap_peak_bytes: j.heap_peak_bytes,
    heap_method: j.heap_method,
    threads,
    runtime: rt,
    match: j.match,
  };
  appendFileSync(args.out, JSON.stringify(rec) + '\n');
  console.error(`[noble] memory ${v.id.padEnd(14)} ${p.padEnd(19)} stack ${String(j.stack_bytes).padStart(7)} B  heap/op ${String(j.heap_alloc_bytes_per_op).padStart(10)} B  peak ${String(j.heap_peak_bytes).padStart(10)} B  match ${j.match}  (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
}
