import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { PerformanceObserver, constants } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
const opts = JSON.parse(process.argv[2]);
const fixture = JSON.parse(readFileSync(opts.fixture));
const bytes = (x) => Uint8Array.from(Buffer.from(x, 'hex'));
let count = 0, requestedBytes = 0;
const native = globalThis.Int32Array;
if (opts.mode === 'constructors') globalThis.Int32Array = class extends native {
  constructor(...args) { super(...args); count++; requestedBytes += this.byteLength; }
};
const api = await import(pathToFileURL(opts.module));
const alg = api[`ml_dsa${opts.parameter}`];
const prepare = (c, operation) => {
  const seed = bytes(c.seed), message = bytes(c.message), context = bytes(c.context);
  const sk = bytes(c.secretKey), pk = bytes(c.publicKey), sig = bytes(c.signature);
  const owned = [seed, message, context, sk, pk, sig];
  const saved = owned.map((x) => x.slice());
  return {
    perform: () => operation === 'keygen' ? alg.keygen(seed)
      : operation === 'getPublicKey' ? alg.getPublicKey(sk)
        : operation === 'sign' ? alg.sign(message, sk, { context, extraEntropy: false })
          : alg.verify(operation === 'invalidLength' ? sig.subarray(1) : sig, message, pk, { context }),
    check: (result) => {
      const encoded = operation === 'keygen' ? Buffer.concat([result.publicKey, result.secretKey])
        : operation === 'verify' || operation === 'invalidLength' ? Uint8Array.of(result ? 1 : 0) : result;
      if (operation === 'keygen') {
        assert.deepEqual(result.publicKey, pk); assert.deepEqual(result.secretKey, sk);
      } else assert.deepEqual(result, operation === 'verify' ? true : operation === 'invalidLength' ? false
        : operation === 'getPublicKey' ? pk : sig);
      owned.forEach((x, i) => assert.deepEqual(x, saved[i]));
      return createHash('sha256').update(encoded).digest('hex');
    }
  };
};
const cases = fixture.rows.filter((x) => x.parameter === opts.parameter && x.group === 'measured');
assert.equal(cases.length, 12);
if (opts.mode === 'constructors') {
  const rows = [];
  for (const operation of ['keygen', 'getPublicKey', 'sign', 'verify', 'invalidLength']) {
    for (const c of cases) {
      const call = prepare(c, operation); count = requestedBytes = 0;
      const result = call.perform();
      const row = { operation, index: c.index, constructors: count, requested_bytes: requestedBytes };
      row.output_sha256 = call.check(result); rows.push(row);
    }
  }
  console.log(JSON.stringify({ mode: opts.mode, parameter: opts.parameter, node: process.version, rows,
    metric: 'Int32Array constructor calls and requested byteLength only; excludes JS arrays/objects and is not heap/peak memory' }));
} else {
  assert.equal(opts.mode, 'retained'); assert.equal(typeof global.gc, 'function');
  const warm = fixture.rows.filter((x) => x.parameter === opts.parameter && x.group === 'warmup');
  for (let i = 0; i < 48; i++) { const c = prepare(warm[i % warm.length], opts.operation); c.check(c.perform()); }
  const gcEvents = { forced: 0, automatic: 0, by_kind: {} };
  const observer = new PerformanceObserver((list) => {
    for (const e of list.getEntries()) {
      const key = String(e.detail.kind);
      gcEvents.by_kind[key] = (gcEvents.by_kind[key] || 0) + 1;
      gcEvents[e.detail.flags & constants.NODE_PERFORMANCE_GC_FLAGS_FORCED ? 'forced' : 'automatic']++;
    }
  });
  observer.observe({ entryTypes: ['gc'] });
  const tick = () => new Promise((resolve) => setImmediate(resolve));
  const snapshot = async () => {
    global.gc(); await tick(); global.gc(); await tick();
    const { heapUsed, heapTotal, external, arrayBuffers } = process.memoryUsage();
    return { heapUsed, heapTotal, external, arrayBuffers };
  };
  const epochs = [{ calls: 0, memory: await snapshot() }];
  let checked = 0;
  for (let epoch = 0; epoch < 3; epoch++) {
    for (let i = 0; i < 96; i++) {
      const call = prepare(cases[i % cases.length], opts.operation); call.check(call.perform()); checked++;
    }
    await tick(); epochs.push({ calls: checked, memory: await snapshot() });
  }
  observer.disconnect();
  console.log(JSON.stringify({ mode: opts.mode, parameter: opts.parameter, operation: opts.operation,
    node: process.version, checked, epochs, gc_events: gcEvents,
    gc_forced_flag: constants.NODE_PERFORMANCE_GC_FLAGS_FORCED,
    metric: 'post-forced-GC process heap/external/arrayBuffers after validated calls; includes harness and JIT; not peak memory or exact allocation volume',
    corpus_policy: '12 measured fixture values with fresh caller buffers each call; disjoint warmup fixture values; no retained result or signer' }));
}
