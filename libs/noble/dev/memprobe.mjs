import { loadAlg, MESSAGE, seedOf } from '../src/algs.mjs';
const a = await loadAlg('pkg', 'ML-DSA-44'); const k = a.keygen(seedOf('ML-DSA-44'));
if (process.argv[2] === 'op') { a.sign(MESSAGE, k.secretKey); }
console.log('ok');
