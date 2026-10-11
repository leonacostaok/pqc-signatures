// Prints preliminary markdown result tables (median wall ms, speedup vs v0) from a bench.jsonl.
// Usage: node libs/noble/dev/prelim.mjs results/noble/bench.jsonl [op]
import { readFileSync } from 'node:fs';
const lines = readFileSync(process.argv[2], 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
const ops = process.argv[3] ? [process.argv[3]] : ['keygen', 'sign', 'verify'];
for (const op of ops) {
  const rows = lines.filter((l) => l.op === op);
  const variants = [...new Set(rows.map((r) => r.variant))].sort();
  const params = [...new Set(rows.map((r) => r.param))];
  const names = Object.fromEntries(rows.map((r) => [r.variant, r.variant_name]));
  console.log(`\n### ${op} — median wall per op (ms), speedup vs v0 in parentheses (ops/s ratio), all variants matched the reference\n`);
  console.log(`| param | ${variants.map((v) => `${v} ${names[v]}`).join(' | ')} |`);
  console.log(`|---|${variants.map(() => '---:').join('|')}|`);
  for (const p of params) {
    const base = rows.find((r) => r.variant === `${op}.v0` && r.param === p);
    const cells = variants.map((v) => {
      const r = rows.find((x) => x.variant === v && x.param === p);
      if (!r) return 'n/a';
      const ms = (r.wall_ns_median / 1e6).toFixed(r.wall_ns_median > 1e8 ? 0 : 3);
      const sp = base ? (r.ops_per_sec / base.ops_per_sec).toFixed(2) : '';
      return `${ms}${sp ? ` (${sp}×)` : ''}${r.match ? '' : ' MISMATCH'}`;
    });
    console.log(`| ${p} | ${cells.join(' | ')} |`);
  }
}
