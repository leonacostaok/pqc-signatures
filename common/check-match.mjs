// Byte-match + cross-verification report across all libraries.
// Inputs: common/reference.json, results/<lib>/artifacts.json, results/<lib>/crossverify-<src>.json, results/<lib>/bench.jsonl
// Output: results/match.json and results/MATCH.md. Exit code 1 if any mismatch / failed verification.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
const root = new URL('../', import.meta.url);
const rd = (p) => JSON.parse(readFileSync(new URL(p, root)));
const LIBS = ['noble', 'liboqs', 'openssl', 'circl', 'rustcrypto', 'bouncycastle'];
const ref = rd('common/reference.json');
const V = rd('common/vectors.json');
const params = V.params.map((p) => p.name);
let bad = 0;
const out = { byte_match: {}, crossverify: {}, bench_match: {} };

// 1. baseline artifacts vs reference
for (const l of LIBS) {
  const f = `results/${l}/artifacts.json`;
  if (!existsSync(new URL(f, root))) continue;
  const a = rd(f);
  out.byte_match[l] = {};
  for (const e of a.entries) {
    const r = ref[e.param];
    const st = !r ? (e.self_verify ? 'self-verify' : 'FAIL')
      : e.pk_sha256 === r.pk_sha256 && e.sk_sha256 === r.sk_sha256 && e.sig_sha256 === r.sig_sha256 && e.self_verify ? 'match' : 'MISMATCH';
    if (st === 'MISMATCH' || st === 'FAIL') bad++;
    out.byte_match[l][e.param] = st;
  }
}
// 2. cross verification matrix: verifier x signer
for (const v of LIBS) for (const s of LIBS) {
  const f = `results/${v}/crossverify-${s}.json`;
  if (!existsSync(new URL(f, root))) continue;
  for (const r of rd(f).results) {
    const k = `${v}<-${s}`;
    out.crossverify[k] ??= { ok: 0, fail: 0, tamper_ok: 0, failures: [] };
    if (r.ok) out.crossverify[k].ok++; else { out.crossverify[k].fail++; out.crossverify[k].failures.push(r.param); bad++; }
    if (r.tamper_rejected) out.crossverify[k].tamper_ok++; else bad++;
  }
}
// 3. every benchmark variant must match
for (const l of LIBS) {
  const f = new URL(`results/${l}/bench.jsonl`, root);
  if (!existsSync(f)) continue;
  const rows = readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((x) => JSON.parse(x));
  const m = rows.filter((r) => r.match === true).length;
  const fails = rows.filter((r) => r.match !== true).map((r) => `${r.variant}/${r.param}`);
  out.bench_match[l] = { rows: rows.length, match: m, fails };
  bad += fails.length;
}
writeFileSync(new URL('results/match.json', root), JSON.stringify(out, null, 2) + '\n');

// Markdown
const libs = Object.keys(out.byte_match);
let md = '# Signature match report\n\n';
md += 'Every library derives keys from the same seeds in `common/vectors.json` and signs the same message deterministically. ';
md += '`match` = public key, secret key and signature are byte-identical to `common/reference.json`. Falcon is not byte-matchable across libraries (no standard seed format, randomized salt), so it is checked by self-verify and cross-verification only.\n\n';
md += `| param | ${libs.join(' | ')} |\n|---|${libs.map(() => '---').join('|')}|\n`;
for (const p of params) md += `| ${p} | ${libs.map((l) => out.byte_match[l][p] ?? '—').join(' | ')} |\n`;
md += '\n## Cross-verification (rows verify signatures produced by columns)\n\n';
const vs = [...new Set(Object.keys(out.crossverify).map((k) => k.split('<-')[0]))];
md += `| verifier \\ signer | ${LIBS.join(' | ')} |\n|---|${LIBS.map(() => '---').join('|')}|\n`;
for (const v of vs) md += `| **${v}** | ${LIBS.map((s) => { const c = out.crossverify[`${v}<-${s}`]; return c ? `${c.ok}/${c.ok + c.fail} ok, ${c.tamper_ok} tamper rejected` : '—'; }).join(' | ')} |\n`;
md += '\n## Benchmark variants matching the reference\n\n| lib | rows | matching |\n|---|---|---|\n';
for (const [l, b] of Object.entries(out.bench_match)) md += `| ${l} | ${b.rows} | ${b.match}${b.fails.length ? ' (fails: ' + b.fails.slice(0, 10).join(', ') + ')' : ''} |\n`;
md += `\n**Problems found: ${bad}**\n`;
writeFileSync(new URL('results/MATCH.md', root), md);
console.log(md);
process.exit(bad ? 1 : 0);
