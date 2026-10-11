// Exercise the actual private helper against an independent exact-integer oracle.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DotNTTs } from '../build/multiply-add/candidate/ml-dsa.audit.js';

const Q = 8380417;
assert.equal(typeof DotNTTs, 'function');
assert.ok(7n * BigInt(Q - 1) ** 2n < 2n ** 49n);
const random = (seed) => {
  const bytes = createHash('shake256', { outputLength: 1024 }).update(seed).digest();
  return Int32Array.from({ length: 256 }, (_, i) => bytes.readUInt32LE(i * 4) % Q);
};
let dotCases = 0;
for (const length of [4, 5, 7]) {
  for (let sample = 0; sample < 34; sample++) {
    const row = Array.from({ length }, (_, i) => sample < 2 ? new Int32Array(256).fill(sample ? Q - 1 : 0) : random(`row/${length}/${sample}/${i}`));
    const vec = Array.from({ length }, (_, i) => sample < 2 ? new Int32Array(256).fill(sample ? Q - 1 : 0) : random(`vec/${length}/${sample}/${i}`));
    const saved = [...row, ...vec].map((v) => v.slice());
    const expected = Int32Array.from({ length: 256 }, (_, i) => {
      let sum = 0n;
      for (let j = 0; j < length; j++) sum += BigInt(row[j][i]) * BigInt(vec[j][i]);
      return Number(sum % BigInt(Q));
    });
    assert.deepEqual(DotNTTs(row, vec), expected);
    const storage = new Int32Array(258).fill(-1234567);
    const out = storage.subarray(1, 257);
    assert.equal(DotNTTs(row, vec, out), out, 'reuse the supplied destination');
    assert.deepEqual(out, expected, 'overwrite every coefficient, including a nonzero destination');
    assert.equal(storage[0], -1234567);
    assert.equal(storage[257], -1234567);
    [...row, ...vec].forEach((v, i) => assert.deepEqual(v, saved[i], 'read-only operands'));
    dotCases += 2;
  }
}
console.log(JSON.stringify({ dotCases, oracle: 'BigInt', max_sum: String(7n * BigInt(Q - 1) ** 2n) }));
