// Preliminary markdown tables for stages.jsonl / memory.jsonl / validation.json
import { readFileSync } from 'node:fs';
const [, , kind, file] = process.argv;
const jl = (f) => readFileSync(f, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
if (kind === 'stages') {
  const L = jl(file);
  for (const stage of [...new Set(L.map((l) => l.stage))]) {
    const rows = L.filter((l) => l.stage === stage);
    const variants = [...new Set(rows.map((r) => r.variant))].sort();
    const names = Object.fromEntries(rows.map((r) => [r.variant, r.variant_name]));
    console.log(`\n**${stage}** — median wall per op (ms), speedup vs v0 in parentheses\n`);
    console.log(`| param | ${variants.map((v) => `${v} ${names[v]}`).join(' | ')} |`);
    console.log(`|---|${variants.map(() => '---:').join('|')}|`);
    for (const p of [...new Set(rows.map((r) => r.param))]) {
      const base = rows.find((r) => r.variant === `${stage}.v0` && r.param === p);
      console.log(`| ${p} | ${variants.map((v) => { const r = rows.find((x) => x.variant === v && x.param === p); if (!r) return 'n/a'; const ms = (r.wall_ns_median / 1e6).toFixed(3); return `${ms}${base && v !== `${stage}.v0` ? ` (${(base.wall_ns_median / r.wall_ns_median).toFixed(2)}×)` : ''}${r.match ? '' : ' MISMATCH'}`; }).join(' | ')} |`);
    }
  }
} else if (kind === 'memory') {
  const L = jl(file);
  console.log('\n| variant | op | param | stack B | heap alloc/op B | heap end-of-op B | threads | match |\n|---|---|---|---:|---:|---:|---:|---|');
  for (const r of L) console.log(`| ${r.variant} | ${r.op}${r.stage ? ' ' + r.stage : ''} | ${r.param} | ${r.stack_bytes} | ${r.heap_alloc_bytes_per_op ?? 'n/a'} | ${r.heap_peak_bytes ?? 'n/a'} | ${r.threads} | ${r.match} |`);
} else {
  const V = JSON.parse(readFileSync(file, 'utf8'));
  console.log('\n| variant | pass | fail | skipped |\n|---|---:|---:|---:|');
  for (const [k, s] of Object.entries(V.summary)) console.log(`| ${k} | ${s.pass} | ${s.fail} | ${s.skipped} |`);
  const fails = V.results.filter((r) => r.pass === false);
  if (fails.length) { console.log('\nFailures:'); for (const f of fails) console.log(`- ${f.variant} ${f.id}: got=${f.got} error=${f.error}`); }
}
