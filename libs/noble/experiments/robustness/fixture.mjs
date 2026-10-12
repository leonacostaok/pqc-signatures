import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const [modulePath, forkString] = process.argv.slice(2);
const fork = Number(forkString);
assert.ok(Number.isSafeInteger(fork) && fork >= 0);
const module = await import(pathToFileURL(modulePath));
const derive = (label, n) => new Uint8Array(createHash('shake256', { outputLength: n }).update(`rowdot-fresh-v1/${fork}/${label}`).digest());
const cases = [];
for (const group of ['measured', 'warmup']) for (const level of [44, 65, 87]) for (let index = 0; index < 12; index++) {
  const alg = module[`ml_dsa${level}`];
  const seed = derive(`${group}/${level}/${index}/seed`, 32);
  const message = derive(`${group}/${level}/${index}/message`, [0, 64, 1024, 4096][index % 4]);
  const context = derive(`${group}/${level}/${index}/context`, [0, 31, 255][index % 3]);
  const { publicKey, secretKey } = alg.keygen(seed);
  const signature = alg.sign(message, secretKey, { context, extraEntropy: false });
  assert.equal(alg.verify(signature, message, publicKey, { context }), true);
  cases.push(Object.fromEntries(Object.entries({ group, level, index, seed, message, context, publicKey, secretKey, signature })
    .map(([k, v]) => [k, v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v])));
}
console.log(JSON.stringify({ schema: 'rowdot-fresh-corpus-v1', fork, cases }));
