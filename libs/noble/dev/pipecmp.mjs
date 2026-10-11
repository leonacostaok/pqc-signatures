import { loadAlg, MESSAGE } from '../src/algs.mjs';
import { referenceInputs } from '../src/refcheck.mjs';
import { stageSets, pipelineFor, formatM } from '../src/stage-lib.mjs';
for (const param of ['ML-DSA-44','SLH-DSA-SHA2-128f']) {
  const ref = await referenceInputs(param); const sets = await stageSets(param); const fast = await loadAlg('fast', param); const M = formatM(MESSAGE, new Uint8Array(0));
  const P = pipelineFor(sets.fam);
  const b=(nm,f)=>{for(let i=0;i<30;i++)f();const s=performance.now();let c=0;while(performance.now()-s<1500){f();c++;}console.log(param,nm,((performance.now()-s)/c).toFixed(3));};
  b('fast.verify', ()=>fast.verify(ref.sig, MESSAGE, ref.pk)); b('best pipeline', ()=>P(sets.best, ref.pk, M, ref.sig)); b('vendor pipeline', ()=>P(sets.vendor, ref.pk, M, ref.sig));
}
