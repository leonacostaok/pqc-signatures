// Fail-closed, sequential experiment runner. No timing overlaps correctness checks.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, linkSync, mkdirSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const opts = {};
for (let i = 0; i < args.length; i += 2) {
  assert.ok(['--out', '--forks', '--start'].includes(args[i]), `unknown option ${args[i]}`);
  assert.ok(args[i + 1] && !args[i + 1].startsWith('--'), `missing value for ${args[i]}`);
  assert.ok(!(args[i] in opts), `duplicate option ${args[i]}`);
  opts[args[i]] = args[i + 1];
}
assert.ok(opts['--out'], 'usage: node rowdot.mjs --out results.json [--forks 5] [--start 10]');
const count = Number(opts['--forks'] ?? 5), start = Number(opts['--start'] ?? 10);
assert.ok(Number.isSafeInteger(count) && count >= 3 && count <= 30, 'forks must be 3..30');
assert.ok(Number.isSafeInteger(start) && start >= 0 && start < 1000000, 'invalid start seed');
const out = resolve(opts['--out']);
assert.ok(!existsSync(out), 'choose a new output path; existing evidence will not be overwritten');
const run = (script, extra = []) => execFileSync(process.execPath, [fileURLToPath(new URL(script, import.meta.url)), ...extra], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
const build = new URL('../build/multiply-add/', import.meta.url);
mkdirSync(build, { recursive: true });
const lock = new URL('.rowdot.lock/', build);
try { mkdirSync(lock); } catch { throw Error('rowdot build directory is locked; another experiment may be running'); }
try {
  process.stderr.write('Preparing exact patch and checking correctness...\n');
  run('multiply-add-prepare.mjs');
  const arithmetic = JSON.parse(run('arithmetic-check.mjs'));
  const correctness = JSON.parse(run('multiply-add-check.mjs'));
  const runs = [];
  for (let i = 0; i < count; i++) {
    process.stderr.write(`Paired fork ${i + 1}/${count}, corpus seed ${start + i}\n`);
    const result = JSON.parse(run('multiply-add-bench.mjs', [String(start + i)]));
    assert.equal(result.rows.length, result.rounds * 12, 'incomplete operation matrix');
    if (i) assert.deepEqual(result.provenance, runs[0].provenance, 'sources changed during run');
    for (const row of result.rows) {
      assert.ok(Number.isFinite(row.speedup) && row.speedup > 0);
      for (const variant of ['baseline', 'candidate']) {
        assert.ok(Number.isFinite(row[variant].ns_per_op) && row[variant].ns_per_op > 0);
        assert.ok(row[variant].iterations > 0 && row[variant].iterations % 12 === 0);
      }
    }
    runs.push(result);
  }
  const median = (values) => {
    const v = [...values].sort((a, b) => a - b), m = v.length >> 1;
    return v.length % 2 ? v[m] : (v[m - 1] + v[m]) / 2;
  };
  const summary = [];
  for (const level of [44, 65, 87]) for (const op of ['keygen', 'getPublicKey', 'sign', 'verify']) {
    const forks = runs.map((r) => {
      const rows = r.rows.filter((x) => x.level === level && x.op === op);
      assert.equal(rows.length, r.rounds);
      return { fork: r.fork, speedup: median(rows.map((x) => x.speedup)), baseline_ns: median(rows.map((x) => x.baseline.ns_per_op)), candidate_ns: median(rows.map((x) => x.candidate.ns_per_op)) };
    });
    summary.push({ level, op, speedup: median(forks.map((f) => f.speedup)), fork_min: Math.min(...forks.map((f) => f.speedup)), fork_max: Math.max(...forks.map((f) => f.speedup)), forks });
  }
  const report = { schema: 'noble-rowdot-v1', recorded_at: new Date().toISOString(), statistic: 'median of within-fork median paired baseline/candidate ratios; min/max are descriptive fork ranges, not confidence intervals', arithmetic, correctness, summary, runs };
  mkdirSync(dirname(out), { recursive: true });
  const temp = `${out}.${process.pid}.tmp`;
  writeFileSync(temp, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  try { linkSync(temp, out); } finally { unlinkSync(temp); }
  process.stderr.write(`Saved ${out}\n`);
} finally { rmdirSync(lock); }
