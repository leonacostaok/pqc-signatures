// Run from worktree root: node --expose-gc docs/audit/evidence/js-go-hash-memory-probes.mjs
const root = process.cwd();
const { shake256: native } = await import(`${root}/libs/noble/src/native-hash.mjs`);
const { shake256: fast } = await import(`${root}/libs/noble/src/fast-shake.mjs`);
const { shake256: official } = await import(`${root}/libs/noble/node_modules/@noble/hashes/sha3.js`);
const seed = new Uint8Array(32).fill(0x42);
const report = {};
for (const [name, alg] of [['native', native], ['fast', fast], ['official', official]]) {
  const h = alg.create().update(seed);
  h.destroy();
  const state = h.buf || h.state;
  report[name] = { destroyed: h.destroyed, nonzeroBytesAfterDestroy: Array.from(state).filter(v => v !== 0).length };
}
globalThis.gc();
const m0 = process.memoryUsage();
const arr = new Uint8Array(8 * 1024 * 1024);
arr.fill(1);
const m1 = process.memoryUsage();
report.eightMiBTypedArray = { heapUsedDelta: m1.heapUsed - m0.heapUsed, arrayBuffersDelta: m1.arrayBuffers - m0.arrayBuffers, externalDelta: m1.external - m0.external };
console.log(JSON.stringify(report, null, 2));
