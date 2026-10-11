// worker_threads worker for the "workers-x4" variants: runs `count` ops of one (op, param) on the
// unmodified baseline and reports digests so the parent can check them against the reference.
import { parentPort, workerData } from 'node:worker_threads';
import { loadAlg, MESSAGE } from './algs.mjs';
import { digest, flipBit, sameBytes } from './refcheck.mjs';

const { param, op, backend } = workerData;
const alg = await loadAlg(backend, param);
let inputs = null;

parentPort.on('message', (m) => {
  if (m.type === 'inputs') {
    inputs = m;
    parentPort.postMessage({ type: 'ready' });
    return;
  }
  const { count } = m;
  let first = null;
  let ok = true;
  if (op === 'keygen') {
    for (let i = 0; i < count; i++) {
      const r = alg.keygen(inputs.seed);
      if (first === null) first = r;
      else if (!sameBytes(r.publicKey, first.publicKey) || !sameBytes(r.secretKey, first.secretKey)) ok = false;
    }
    parentPort.postMessage({ type: 'done', ok, pk_sha256: digest(first.publicKey), sk_sha256: digest(first.secretKey) });
  } else if (op === 'sign') {
    for (let i = 0; i < count; i++) {
      const s = alg.sign(MESSAGE, inputs.sk);
      if (first === null) first = s;
      else if (!sameBytes(s, first)) ok = false;
    }
    parentPort.postMessage({ type: 'done', ok, sig_sha256: digest(first) });
  } else {
    for (let i = 0; i < count; i++) if (alg.verify(inputs.sig, MESSAGE, inputs.pk) !== true) ok = false;
    const tamper = alg.verify(flipBit(inputs.sig), MESSAGE, inputs.pk) === false;
    parentPort.postMessage({ type: 'done', ok, tamper_rejected: tamper });
  }
});
parentPort.postMessage({ type: 'loaded' });
