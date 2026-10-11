import { MESSAGE } from '../src/algs.mjs';
import { referenceInputs } from '../src/refcheck.mjs';
import { stageSets, pipelineFor, formatM } from '../src/stage-lib.mjs';
const param='SLH-DSA-SHA2-128f'; const ref = await referenceInputs(param); const sets = await stageSets(param); const M = formatM(MESSAGE, new Uint8Array(0));
const P = pipelineFor(sets.fam); const s=performance.now(); let n=0; while(performance.now()-s<3000){P(sets.best, ref.pk, M, ref.sig);n++;} console.log((performance.now()-s)/n);
