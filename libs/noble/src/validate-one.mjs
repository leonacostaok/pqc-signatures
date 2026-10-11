// Runs the validation cases of one kind through one variant; prints one JSON line per case.
// Usage: node validate-one.mjs --variant sign.v3 --suite <path.json.gz> [--params a,b] [--ids a,b]
// Variants: keygen.v*, sign.v*, verify.v* (variants.mjs) and stages.total / stages.total_best.
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { PARAM_NAMES, familyOf, loadAlg } from './algs.mjs';
import { variantById } from './variants.mjs';
import { runCase } from './validate-lib.mjs';

const args = Object.fromEntries(process.argv.slice(2).map((a, i, arr) => (a.startsWith('--') ? [a.slice(2), arr[i + 1]] : [])).filter((x) => x.length));
const suite = JSON.parse(gunzipSync(readFileSync(args.suite)));
const vid = args.variant;
const isStage = vid.startsWith('stages.');
const v = isStage ? { id: vid, op: 'verify', mode: vid === 'stages.total' ? 'total' : 'total_best', backend: 'vendor', hash: 'noble' } : variantById(vid);
if (!v) throw new Error(`unknown variant ${vid}`);
const kind = { keygen: 'keygen', sign: 'siggen', verify: 'sigver' }[v.op];
const paramFilter = args.params ? args.params.split(',') : null;
const idFilter = args.ids ? new Set(args.ids.split(',')) : null;
const cases = suite.cases.filter((c) => c.kind === kind && PARAM_NAMES.includes(c.param) && familyOf(c.param) !== 'falcon' && (!paramFilter || paramFilter.includes(c.param)) && (!idFilter || idFilter.has(c.id)));
const emit = (r) => process.stdout.write(JSON.stringify(r) + '\n');

if (v.mode === 'workers') {
  // distribute the cases over 4 worker_threads running the baseline
  const { Worker } = await import('node:worker_threads');
  const threads = v.threads;
  const chunks = Array.from({ length: threads }, () => []);
  cases.forEach((c, i) => chunks[i % threads].push(c));
  await Promise.all(
    chunks.map(
      (chunk, t) =>
        new Promise((res, rej) => {
          if (!chunk.length) return res();
          const w = new Worker(new URL('./validate-worker.mjs', import.meta.url), { workerData: { cases: chunk, variant: v.id } });
          w.on('message', (m) => {
            if (m.type === 'result') emit({ ...m.result, worker: t });
            else if (m.type === 'done') res();
          });
          w.on('error', rej);
        })
    )
  );
} else {
  const algCache = new Map();
  for (const c of cases) {
    const r = await runCase(c, v, algCache);
    emit({ id: c.id, variant: vid, ...r });
  }
}
