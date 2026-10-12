import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const args = JSON.parse(process.argv[2]);
const corpus = JSON.parse(readFileSync(args.corpus));
const cases = corpus.parameters[String(args.param)];
assert.equal(cases.measured.length, 10);
assert.equal(cases.warmup.length, 4);
assert.equal(new Set([...cases.measured, ...cases.warmup].map(c => c.seed)).size, 14);
assert.ok(Number.isSafeInteger(args.warmupCycles) && args.warmupCycles > 0);
const module = await import(pathToFileURL(args.module));
const alg = module[`ml_dsa${args.param}`];
const hex = (x) => Buffer.from(x).toString('hex');
const decode = (x) => Uint8Array.from(Buffer.from(x, 'hex'));
const copy = (x) => Uint8Array.from(x);
let timedCalls = { keygen: 0, sign: 0, verify: 0 };
function call(op, measured, fn) {
  if (!measured) return { value: fn() };
  timedCalls[op]++;
  const cpu = process.cpuUsage();
  const start = process.hrtime.bigint();
  const value = fn();
  const wall_ns = Number(process.hrtime.bigint() - start);
  const elapsed = process.cpuUsage(cpu);
  return { value, wall_ns, cpu_ns: (elapsed.user + elapsed.system) * 1000 };
}
function one(c, measured) {
  const seed = decode(c.seed), savedSeed = copy(seed);
  const kg = call('keygen', measured, () => alg.keygen(seed));
  assert.deepEqual(seed, savedSeed);
  const pk = copy(kg.value.publicKey), sk = copy(kg.value.secretKey);
  const message = decode(c.message), context = decode(c.context);
  const signSK = copy(sk), signMessage = copy(message), signContext = copy(context);
  const signOptions = { context: signContext, extraEntropy: false };
  const sig = call('sign', measured, () => alg.sign(signMessage, signSK, signOptions));
  assert.deepEqual(signSK, sk); assert.deepEqual(signMessage, message); assert.deepEqual(signContext, context);
  const verifyPK = copy(pk), verifyMessage = copy(message), verifySignature = copy(sig.value), verifyContext = copy(context);
  const verifyOptions = { context: verifyContext };
  const ver = call('verify', measured, () => alg.verify(verifySignature, verifyMessage, verifyPK, verifyOptions));
  assert.equal(ver.value, true);
  assert.deepEqual(verifyPK, pk); assert.deepEqual(verifyMessage, message); assert.deepEqual(verifySignature, sig.value); assert.deepEqual(verifyContext, context);
  const bad = copy(sig.value); bad[Math.floor(bad.length / 2)] ^= 1;
  assert.equal(alg.verify(bad, copy(message), copy(pk), { context: copy(context) }), false);
  return { index: c.index, seed: c.seed, public_key: hex(pk), secret_key: hex(sk), signature: hex(sig.value),
    valid: true, tamper_rejected: true, inputs_preserved: true,
    timing: Object.fromEntries([['keygen', kg], ['sign', sig], ['verify', ver]].map(([op, r]) => [op, { wall_ns: r.wall_ns, cpu_ns: r.cpu_ns }])) };
}
for (let cycle = 0; cycle < args.warmupCycles; cycle++) for (const c of cases.warmup) one(c, false);
const rows = cases.measured.map((c) => one(c, true));
assert.deepEqual(timedCalls, { keygen: 10, sign: 10, verify: 10 });
console.log(JSON.stringify({ schema: 'fresh-ten-keys-worker-v1', param: String(args.param), corpus_id: corpus.id,
  runtime: process.version, v8: process.versions.v8, measured_calls: timedCalls,
  warmup_keys: 4, warmup_cycles: args.warmupCycles, timing_scope: 'public API only; fresh caller copies outside timer; no cross-call cryptographic cache', rows }));
