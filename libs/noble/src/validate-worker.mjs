// worker_threads worker for the validation suite (workers-x4 variants): runs its chunk of cases
// through the unmodified baseline and streams results back.
import { parentPort, workerData } from 'node:worker_threads';
import { variantById } from './variants.mjs';
import { runCase } from './validate-lib.mjs';
const v = variantById(workerData.variant);
const algCache = new Map();
for (const c of workerData.cases) {
  const r = await runCase(c, v, algCache);
  parentPort.postMessage({ type: 'result', result: { id: c.id, variant: v.id, ...r } });
}
parentPort.postMessage({ type: 'done' });
