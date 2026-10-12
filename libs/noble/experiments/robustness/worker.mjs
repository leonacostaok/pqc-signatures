// Each process imports exactly one variant. Single mode invokes its first crypto
// operation once; warm mode uses separate warmup inputs and fresh copies per call.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { decodeCase, expected, invokeFresh } from './common.mjs';
const args = JSON.parse(process.argv[2]);
assert.ok(['warm', 'single', 'check'].includes(args.mode));
const fixture = JSON.parse(readFileSync(args.fixture));
const all = fixture.cases.map(decodeCase);
assert.equal(all.length, 72);
const module = await import(pathToFileURL(args.module));
if (args.mode === 'check') {
  let calls = 0;
  for (const c of all) for (const op of ['keygen', 'getPublicKey', 'sign', 'verify']) {
    const saved = structuredClone(c);
    assert.deepEqual(invokeFresh(module[`ml_dsa${c.level}`], op, c), expected(c, op));
    assert.deepEqual(c, saved);
    calls++;
  }
  console.log(JSON.stringify({ checked: calls, corpus_cases: all.length }));
} else {
  const alg = module[`ml_dsa${args.level}`];
  const measured = all.filter((c) => c.level === args.level && c.group === 'measured');
  const warmup = all.filter((c) => c.level === args.level && c.group === 'warmup');
  assert.equal(measured.length, 12);
  assert.equal(warmup.length, 12);
  let result;
  if (args.mode === 'single') {
    assert.ok(Number.isSafeInteger(args.index) && args.index >= 0 && args.index < 12);
    const c = measured[args.index];
    const cpuStart = process.cpuUsage();
    const start = process.hrtime.bigint();
    const output = invokeFresh(alg, args.op, c);
    const elapsed = Number(process.hrtime.bigint() - start);
    const cpu = process.cpuUsage(cpuStart);
    assert.deepEqual(output, expected(c, args.op));
    result = { iterations: 1, ns_per_op: elapsed, cpu_ns_per_op: (cpu.user + cpu.system) * 1000 };
  } else {
    assert.deepEqual([...args.order].sort((a, b) => a - b), Array.from({ length: 12 }, (_, i) => i));
    const measure = (corpus, budgetMs) => {
      const last = Array(12);
      let count = 0, valid = true, elapsed;
      const cpuStart = process.cpuUsage();
      const start = process.hrtime.bigint();
      do {
        for (const index of args.order) {
          last[index] = invokeFresh(alg, args.op, corpus[index]);
          if (args.op === 'verify') valid = (last[index] === true) && valid;
          count++;
        }
        elapsed = Number(process.hrtime.bigint() - start);
      } while (elapsed < budgetMs * 1e6);
      const cpu = process.cpuUsage(cpuStart);
      assert.equal(valid, true);
      for (let index = 0; index < 12; index++) assert.deepEqual(last[index], expected(corpus[index], args.op));
      return { iterations: count, ns_per_op: elapsed / count, cpu_ns_per_op: (cpu.user + cpu.system) * 1000 / count };
    };
    assert.ok(Number.isFinite(args.budgetMs) && args.budgetMs >= 1);
    assert.ok(Number.isFinite(args.warmupMs) && args.warmupMs >= 1);
    measure(warmup, args.warmupMs);
    result = measure(measured, args.budgetMs);
  }
  console.log(JSON.stringify({ mode: args.mode, level: args.level, op: args.op, fork: fixture.fork, index: args.index,
    runtime: process.version, v8: process.versions.v8, arch: process.arch, ...result }));
}
