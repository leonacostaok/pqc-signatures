import { keccakP as fast } from '../src/fast-keccak.mjs';
import { keccakP as noble } from '@noble/hashes/sha3.js';
const s = new Uint32Array(50);
for (const [nm, f] of [['noble', (x) => noble(x, 24)], ['fast', fast], ['noble', (x) => noble(x, 24)], ['fast', fast]]) {
  for (let i = 0; i < 20000; i++) f(s);
  const t0 = performance.now(); for (let i = 0; i < 200000; i++) f(s);
  console.log(nm, ((performance.now() - t0) * 1e3 / 200000).toFixed(3), 'us/perm');
}
