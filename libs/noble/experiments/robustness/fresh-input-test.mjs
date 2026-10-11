import assert from 'node:assert/strict';
import { invokeFresh } from './common.mjs';
const c = Object.fromEntries(['seed', 'secretKey', 'publicKey', 'message', 'context', 'signature'].map((k, i) => [k, Uint8Array.of(i + 1, 19)]));
const saved = structuredClone(c);
const seen = new WeakSet();
let calls = 0, arrays = 0, options = 0;
const inspect = (...args) => {
  calls++;
  for (const x of args) {
    assert.equal(seen.has(x), false, 'every call must receive fresh array/options identities');
    seen.add(x);
    if (x instanceof Uint8Array) {
      arrays++;
      assert.ok(!Object.values(c).includes(x), 'never pass retained corpus arrays to the API');
      x.fill(255); // Mutation must not poison another call or the retained corpus.
    } else {
      options++;
      assert.equal(seen.has(x.context), false);
      seen.add(x.context);
      assert.equal(x.context instanceof Uint8Array, true);
      assert.ok(!Object.values(c).includes(x.context));
      x.context.fill(255);
    }
  }
  return true;
};
const alg = Object.fromEntries(['keygen', 'getPublicKey', 'sign', 'verify'].map((op) => [op, inspect]));
for (let round = 0; round < 4; round++) for (const op of Object.keys(alg)) invokeFresh(alg, op, c);
assert.deepEqual(c, saved, 'input copies isolate retained corpus from mutation');
assert.equal(calls, 16);
assert.equal(arrays, 28);
assert.equal(options, 8);
console.log(JSON.stringify({ calls, arrays, options, fresh_identity_and_mutation_isolation: true }));
