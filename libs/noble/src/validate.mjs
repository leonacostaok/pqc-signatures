// validate <suite.json.gz> <out.json> [--params a,b] [--variants id,id] [--skip-slow]
// Runs every case through every variant of the matching process (keygen -> keygen.v0..v5, siggen ->
// sign.v0..v5, sigver -> verify.v0..v5 + the stage pipelines stages.total / stages.total_best), one
// child process per variant (node or bun, hash layer via env), and writes results + summary.
import { spawnSync } from 'node:child_process';
import { writeFileSync, existsSync, readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { LIB, LIB_VERSION, PARAM_NAMES, familyOf } from './algs.mjs';
import { VARIANTS } from './variants.mjs';

const argv = process.argv.slice(2);
const pos = argv.filter((a, i) => !a.startsWith('--') && (i === 0 || !argv[i - 1].startsWith('--')));
const args = {};
for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) args[argv[i].slice(2)] = i + 1 < argv.length && !argv[i + 1].startsWith('--') ? argv[++i] : true;
const [suitePath, outPath] = pos;
if (!suitePath || !outPath) {
  console.error('usage: validate <suite.json.gz> <out.json> [--params a,b] [--variants id,id] [--skip-slow]');
  process.exit(2);
}
const suite = JSON.parse(gunzipSync(readFileSync(suitePath)));
const bunBin = process.env.BUN_BIN || `${process.env.HOME || '/root'}/.bun/bin/bun`;
const one = fileURLToPath(new URL('./validate-one.mjs', import.meta.url));
const SLOW = new Set(PARAM_NAMES.filter((p) => familyOf(p) === 'slh-dsa' && p.endsWith('s')));

const variants = [
  ...VARIANTS.map((v) => ({ id: v.id, op: v.op, runtime: v.runtime, hash: v.hash })),
  { id: 'stages.total', op: 'verify', runtime: 'node', hash: 'noble' },
  { id: 'stages.total_best', op: 'verify', runtime: 'node', hash: 'noble' },
].filter((v) => !args.variants || args.variants.split(',').includes(v.id));
const kindOf = { keygen: 'keygen', sign: 'siggen', verify: 'sigver' };
const results = [];
const summary = {};
const paramFilter = args.params ? args.params.split(',') : null;
for (const v of variants) {
  const kind = kindOf[v.op];
  const mine = suite.cases.filter((c) => c.kind === kind && PARAM_NAMES.includes(c.param) && familyOf(c.param) !== 'falcon');
  const sum = (summary[v.id] = { pass: 0, fail: 0, skipped: 0 });
  const todo = [];
  for (const c of mine) {
    if (paramFilter && !paramFilter.includes(c.param)) {
      results.push({ id: c.id, variant: v.id, pass: null, got: null, error: null, skipped: 'not in --params filter' });
      sum.skipped++;
    } else if (args['skip-slow'] && kind === 'siggen' && SLOW.has(c.param)) {
      results.push({ id: c.id, variant: v.id, pass: null, got: null, error: null, skipped: 'SLH-DSA "s" signing skipped (--skip-slow)' });
      sum.skipped++;
    } else todo.push(c);
  }
  if (!todo.length) continue;
  let exe = process.execPath;
  if (v.runtime === 'bun') {
    if (!existsSync(bunBin)) {
      for (const c of todo) {
        results.push({ id: c.id, variant: v.id, pass: null, got: null, error: null, skipped: 'bun not installed' });
        sum.skipped++;
      }
      continue;
    }
    exe = bunBin;
  }
  const t0 = Date.now();
  const r = spawnSync(exe, [one, '--variant', v.id, '--suite', suitePath, '--ids', todo.map((c) => c.id).join(',')], {
    env: { ...process.env, NOBLE_PQ_HASH: v.hash },
    encoding: 'utf8',
    maxBuffer: 256 << 20,
  });
  const got = new Map();
  for (const l of (r.stdout || '').split('\n')) if (l.trim().startsWith('{')) {
    const j = JSON.parse(l);
    got.set(j.id, j);
  }
  for (const c of todo) {
    const j = got.get(c.id);
    if (!j) {
      results.push({ id: c.id, variant: v.id, pass: false, got: null, error: `no result (child exit ${r.status}): ${(r.stderr || '').slice(-300).trim()}` });
      sum.fail++;
    } else {
      results.push({ id: c.id, variant: v.id, pass: j.pass, got: j.got, error: j.error });
      if (j.pass) sum.pass++;
      else sum.fail++;
    }
  }
  console.error(`[noble] validate ${v.id.padEnd(18)} pass ${String(sum.pass).padStart(4)}  fail ${String(sum.fail).padStart(3)}  skipped ${String(sum.skipped).padStart(3)}  (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
}
writeFileSync(outPath, JSON.stringify({ lib: LIB, lib_version: LIB_VERSION, suite: { version: suite.version, cases: suite.cases.length }, results, summary }, null, 1) + '\n');
const fails = Object.values(summary).reduce((a, s) => a + s.fail, 0);
console.error(`[noble] validate done: ${fails} failure(s)`);
if (fails) process.exit(1);
