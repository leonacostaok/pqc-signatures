// Differential correctness and allocation regression check for a copied upstream candidate.
// Arguments: baseline ml-dsa.js, candidate ml-dsa.js, baseline hashes/sha2.js.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const NativeInt32Array = globalThis.Int32Array;
let allocations = 0;
let allocatedBytes = 0;
globalThis.Int32Array = class extends NativeInt32Array {
  constructor(...args) {
    super(...args);
    allocations++;
    allocatedBytes += this.byteLength;
  }
};
const baseline = await import(pathToFileURL(process.argv[2]));
const candidate = await import(pathToFileURL(process.argv[3]));
const outcome = (fn) => {
  try { return { value: fn() }; } catch (e) { return { error: e.constructor.name, message: e.message }; }
};
const suite = JSON.parse(gunzipSync(readFileSync(new URL('../../../../common/validation/validation.json.gz', import.meta.url))));
const bytes = (h = '') => Uint8Array.from(Buffer.from(h, 'hex'));
const cases = suite.cases.filter((c) => c.param.startsWith('ML-DSA'));
assert.equal(cases.length, 219, 'do not silently accept a partial validation suite');
let checked = 0;
for (const c of cases) {
  const alg = candidate[`ml_dsa${c.param.split('-')[2]}`];
  if (c.kind === 'keygen') {
    const keys = alg.keygen(bytes(c.seed_hex));
    assert.deepEqual(keys.publicKey, bytes(c.expect_pk_hex), c.id);
    assert.deepEqual(keys.secretKey, bytes(c.expect_sk_hex), c.id);
  } else if (c.kind === 'siggen') {
    assert.deepEqual(alg.sign(bytes(c.msg_hex), bytes(c.sk_hex), { context: bytes(c.ctx_hex), extraEntropy: false }), bytes(c.expect_sig_hex), c.id);
  } else {
    const verify = (a) => outcome(() => a.verify(bytes(c.sig_hex), bytes(c.msg_hex), bytes(c.pk_hex), { context: bytes(c.ctx_hex) }));
    const got = verify(alg);
    assert.deepEqual(got, verify(baseline[`ml_dsa${c.param.split('-')[2]}`]), `${c.id}: rejection parity`);
    assert.equal(got.value ?? false, c.expect, c.id);
  }
  checked++;
}

const measurements = [];
for (const [level, products] of [[44, 16], [65, 30], [87, 56]]) {
  const name = `ml_dsa${level}`;
  const seed = createHash('sha256').update(`multiply-add/allocation/${level}`).digest();
  const keys = baseline[name].keygen(seed);
  const msg = new TextEncoder().encode('allocation regression with a real signature');
  const sig = baseline[name].sign(msg, keys.secretKey, { extraEntropy: false });
  const measure = (alg, op) => {
    allocations = allocatedBytes = 0;
    const result = op === 'verify' ? alg.verify(sig, msg, keys.publicKey)
      : op === 'sign' ? alg.sign(msg, keys.secretKey, { extraEntropy: false })
        : op === 'getPublicKey' ? alg.getPublicKey(keys.secretKey) : alg.keygen(seed);
    const measured = { allocations, allocatedBytes };
    assert.deepEqual(result, op === 'verify' ? true : op === 'sign' ? sig : op === 'getPublicKey' ? keys.publicKey : keys);
    return measured;
  };
  for (const op of ['verify', 'keygen', 'getPublicKey', 'sign']) {
    const before = measure(baseline[name], op);
    const after = measure(candidate[name], op);
    measurements.push({ level, op, before, after });
    const removed = products;
    assert.ok(before.allocations - after.allocations >= removed,
      `ML-DSA-${level} ${op}: remove at least ${products} temporary polynomial allocations; before=${before.allocations}, after=${after.allocations}`);
    assert.ok(before.allocatedBytes - after.allocatedBytes >= removed * 256 * 4);
  }
}
globalThis.Int32Array = NativeInt32Array;
// Exercise options and ownership without the allocation instrument installed.
const { sha512 } = await import(pathToFileURL(process.argv[4]));
let differentialCases = 0;
for (const level of [44, 65, 87]) {
  const base = baseline[`ml_dsa${level}`], next = candidate[`ml_dsa${level}`];
  for (let i = 0; i < 8; i++) {
    const derive = (label, size) => createHash('shake256', { outputLength: size }).update(`rowdot-check/${level}/${i}/${label}`).digest();
    const seed = derive('seed', 32), msg = derive('message', [0, 1, 64, 4096][i % 4]);
    const context = derive('context', i % 2 ? 255 : 0), entropy = derive('entropy', 32);
    const seedSnapshot = Buffer.from(seed);
    const keys = base.keygen(seed);
    assert.deepEqual(next.keygen(seed), keys);
    assert.deepEqual(seed, seedSnapshot, 'key generation preserves seed');
    const secretSnapshot = keys.secretKey.slice();
    assert.deepEqual(next.getPublicKey(keys.secretKey), keys.publicKey);
    assert.deepEqual(keys.secretKey, secretSnapshot, 'public-key derivation preserves secret key');
    for (const surface of ['pure', 'prehash', 'externalMu']) {
      const a = surface === 'prehash' ? base.prehash(sha512) : surface === 'externalMu' ? base.internal : base;
      const b = surface === 'prehash' ? next.prehash(sha512) : surface === 'externalMu' ? next.internal : next;
      const input = surface === 'externalMu' ? derive('mu', 64) : msg;
      const opts = surface === 'externalMu' ? { externalMu: true } : { context };
      const owned = [seed, input, context, entropy, keys.secretKey, keys.publicKey];
      const saved = owned.map((x) => x.constructor.from(x));
      const sig = a.sign(input, keys.secretKey, { ...opts, extraEntropy: entropy });
      assert.deepEqual(b.sign(input, keys.secretKey, { ...opts, extraEntropy: entropy }), sig);
      assert.equal(b.verify(sig, input, keys.publicKey, opts), true);
      const bad = sig.slice(); bad[0] ^= 1;
      assert.deepEqual(outcome(() => b.verify(bad, input, keys.publicKey, opts)), outcome(() => a.verify(bad, input, keys.publicKey, opts)));
      for (const malformed of [sig.subarray(1), new Uint8Array(sig.length + 1)]) {
        assert.deepEqual(outcome(() => b.verify(malformed, input, keys.publicKey, opts)), outcome(() => a.verify(malformed, input, keys.publicKey, opts)));
      }
      owned.forEach((x, j) => assert.deepEqual(x, saved[j], 'caller-owned input preserved'));
      differentialCases++;
    }
    const invalidContext = { context: new Uint8Array(256), extraEntropy: false };
    assert.deepEqual(outcome(() => next.sign(msg, keys.secretKey, invalidContext)), outcome(() => base.sign(msg, keys.secretKey, invalidContext)));
  }
}
console.log(JSON.stringify({ checked, differentialCases, allocation_metric: 'Int32Array constructor calls and requested byteLength; not heap or peak memory', measurements }, null, 2));
