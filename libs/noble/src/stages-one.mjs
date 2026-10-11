// Measures one verify-stage variant for the given params; prints one JSON line per param.
// Usage: node stages-one.mjs --variant expandA.v2 --params ML-DSA-44,ML-DSA-65 --budget-ms 1000
import { LIB, LIB_VERSION, MESSAGE, familyOf } from './algs.mjs';
import { STAGE_VARIANTS, stageVariantApplies } from './stage-impls.mjs';
import { referenceInputs, digest, flipBit } from './refcheck.mjs';
import { measureSingle, measureAsync } from './timing.mjs';
import { canonicalContext, formatM, stageImpl, stageSets, makeExpandWorkers } from './stage-lib.mjs';

const args = Object.fromEntries(process.argv.slice(2).map((a, i, arr) => (a.startsWith('--') ? [a.slice(2), arr[i + 1]] : [])).filter((x) => x.length));
const v = STAGE_VARIANTS.find((x) => x.id === args.variant);
if (!v) throw new Error(`unknown stage variant ${args.variant}`);
const budgetMs = Number(args['budget-ms'] || 1000);
const runtimeName = typeof Bun !== 'undefined' ? `bun ${Bun.version}` : `node ${process.versions.node}`;

for (const param of args.params.split(',')) {
  if (!stageVariantApplies(v, param)) continue;
  const fam = familyOf(param);
  const ref = await referenceInputs(param);
  const sets = await stageSets(param);
  const M = formatM(MESSAGE, new Uint8Array(0));
  const ctx = canonicalContext(fam, sets.vendor, ref.pk, M, ref.sig);
  const impl = await stageImpl(v, param, sets, makeExpandWorkers);
  const state = impl.prepare(ctx);
  let out = null;
  let matched = true;
  const isTotal = v.stage === 'total' || v.stage === 'total_best';
  const check = (r) => {
    if (isTotal) {
      if (r !== true) matched = false;
      return;
    }
    const d = digest(impl.encode(r));
    if (out === null) out = d;
    else if (d !== out) matched = false;
  };
  const fn = () => impl.run(state);
  const stats = impl.async ? await measureAsync(fn, check, budgetMs) : measureSingle(fn, check, budgetMs);
  if (isTotal) {
    let tamper = false;
    try {
      tamper = impl.tamper(state, flipBit(ref.sig)) === false;
    } catch {
      tamper = true;
    }
    matched = matched && tamper;
    out = matched ? 'true' : 'false';
  } else if (out !== ctx.outputs[v.stage]) matched = false;
  if (impl.close) await impl.close();
  stats.threads = v.threads || 1;
  const rec = {
    lib: LIB,
    lib_version: LIB_VERSION,
    lang: 'js',
    runtime: runtimeName,
    family: fam,
    stage: v.stage,
    variant: v.id,
    variant_name: v.name,
    variant_desc: v.desc,
    param,
    ...stats,
    output_sha256: out,
    match: matched,
  };
  process.stdout.write(JSON.stringify(rec) + '\n');
}
