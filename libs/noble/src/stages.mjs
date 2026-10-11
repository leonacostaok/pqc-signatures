// stages --out <file.jsonl> [--budget-ms N] [--params a,b] [--stages x,y] [--variants id,id] [--append]
// Spawns one child process per (variant, param-set) so every variant starts from a cold JIT and so
// the runtime (node / bun) and hash layer (env NOBLE_PQ_HASH) are fixed per process.
import { spawnSync } from 'node:child_process';
import { appendFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PARAM_NAMES } from './algs.mjs';
import { STAGE_VARIANTS as VARIANTS, stageVariantApplies as variantApplies } from './stage-impls.mjs';

const argv = process.argv.slice(2);
const args = {};
for (let i = 0; i < argv.length; i++) {
  if (argv[i].startsWith('--')) {
    const k = argv[i].slice(2);
    if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) args[k] = argv[++i];
    else args[k] = true;
  }
}
if (!args.out) {
  console.error('usage: stages --out <file.jsonl> [--budget-ms N] [--params a,b] [--stages x,y] [--variants id,id] [--append]');
  process.exit(2);
}
const budgetMs = Number(args['budget-ms'] || 1000);
const params = args.params ? args.params.split(',') : PARAM_NAMES;
for (const p of params) if (!PARAM_NAMES.includes(p)) throw new Error(`unknown param ${p}`);
const stages = args.stages ? args.stages.split(',') : null;
const variants = VARIANTS.filter((v) => (!stages || stages.includes(v.stage)) && (!args.variants || args.variants.split(',').includes(v.id)));
const bunBin = args.bun || process.env.BUN_BIN || `${process.env.HOME || '/root'}/.bun/bin/bun`;
const benchOne = fileURLToPath(new URL('./stages-one.mjs', import.meta.url));

if (!args.append) writeFileSync(args.out, '');
let failures = 0;
for (const v of variants) {
  const ps = params.filter((p) => variantApplies(v, p));
  if (!ps.length) continue;
  let exe = process.execPath;
  if (v.runtime === 'bun') {
    if (!existsSync(bunBin)) {
      console.error(`[noble] ${v.id}: bun not found at ${bunBin}, skipping`);
      continue;
    }
    exe = bunBin;
  }
  // one process per param for slow families (keeps a failure local); batch fast ones per variant
  const groups = ps.map((p) => [p]);
  for (const group of groups) {
    const t0 = Date.now();
    const r = spawnSync(exe, [benchOne, '--variant', v.id, '--params', group.join(','), '--budget-ms', String(budgetMs)], {
      env: { ...process.env, NOBLE_PQ_HASH: v.hash },
      encoding: 'utf8',
      maxBuffer: 64 << 20,
    });
    if (r.status !== 0) {
      failures++;
      console.error(`[noble] ${v.id} ${group.join(',')} FAILED (exit ${r.status}):\n${(r.stderr || '').slice(-2000)}`);
      continue;
    }
    const lines = r.stdout.split('\n').filter((l) => l.trim().startsWith('{'));
    appendFileSync(args.out, lines.map((l) => l + '\n').join(''));
    for (const l of lines) {
      const j = JSON.parse(l);
      console.error(
        `[noble] ${j.variant.padEnd(14)} ${j.param.padEnd(19)} median ${(j.wall_ns_median / 1e6).toFixed(3).padStart(10)} ms  ops/s ${String(j.ops_per_sec).padStart(10)}  iters ${String(j.iterations).padStart(6)}  match ${j.match}  (${((Date.now() - t0) / 1000).toFixed(1)}s)`
      );
    }
  }
}
if (failures) {
  console.error(`[noble] ${failures} bench group(s) failed`);
  process.exit(1);
}
