// worker for expandA.v4: expands the requested rows of A^ with noble's code and transfers them back.
import { parentPort, workerData } from 'node:worker_threads';
import { loadAlg } from './algs.mjs';
const alg = await loadAlg('vendor', workerData.param);
parentPort.on('message', ({ rho, rows }) => {
  const out = alg.raw.stages.expandARows(rho, rows);
  const buffers = out.flat().map((p) => p.buffer);
  parentPort.postMessage({ rows, polys: out }, buffers);
});
parentPort.postMessage('loaded');
