// Validate process/timing protocol with a fake API, without cryptographic timings.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const build = fileURLToPath(new URL('../../build/robustness/', import.meta.url));
mkdirSync(build, { recursive: true });
const dir = mkdtempSync(join(build, 'worker-test-'));
try {
  const module = join(dir, 'fake.mjs'), fixture = join(dir, 'fixture.json'), counter = join(dir, 'counts.json');
  writeFileSync(module, `import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
const calls = { keygen: 0, getPublicKey: 0, sign: 0, verify: 0 }, seen = new WeakSet();
const inspect = (op, args) => {
  calls[op]++;
  for (const value of args) {
    assert.equal(seen.has(value), false, 'cross-call argument identity reused');
    seen.add(value);
    if (!(value instanceof Uint8Array)) {
      assert.equal(seen.has(value.context), false, 'cross-call context identity reused');
      seen.add(value.context);
    }
  }
};
const api = {
  keygen(...args) { inspect('keygen', args); return { publicKey: Uint8Array.of(2), secretKey: Uint8Array.of(3) }; },
  getPublicKey(...args) { inspect('getPublicKey', args); return Uint8Array.of(2); },
  sign(...args) { inspect('sign', args); return Uint8Array.of(6); },
  verify(...args) { inspect('verify', args); return true; }
};
export const ml_dsa44 = api, ml_dsa65 = api, ml_dsa87 = api;
process.on('exit', () => writeFileSync(${JSON.stringify(counter)}, JSON.stringify(calls)));
`);
  const cases = [];
  for (const group of ['measured', 'warmup']) for (const level of [44, 65, 87]) for (let index = 0; index < 12; index++)
    cases.push({ group, level, index, seed: '01', publicKey: '02', secretKey: '03', message: '04', context: '05', signature: '06' });
  writeFileSync(fixture, JSON.stringify({ fork: 0, cases }));
  let checked = 0;
  for (const op of ['keygen', 'getPublicKey', 'sign', 'verify']) for (const mode of ['single', 'warm']) {
    const args = { module, fixture, mode, level: 44, op, index: 7, order: Array.from({ length: 12 }, (_, i) => 11 - i), budgetMs: 1, warmupMs: 1 };
    const result = JSON.parse(execFileSync(process.execPath, [fileURLToPath(new URL('worker.mjs', import.meta.url)), JSON.stringify(args)], { encoding: 'utf8' }));
    const counts = JSON.parse(readFileSync(counter));
    for (const other of Object.keys(counts)) if (other !== op) assert.equal(counts[other], 0, 'worker performed an unrelated API operation');
    if (mode === 'single') {
      assert.equal(counts[op], 1, 'single mode must call the cryptographic API exactly once');
      assert.equal(result.iterations, 1);
    } else {
      assert.ok(counts[op] > result.iterations, 'warm mode must warm up separately');
      assert.equal(counts[op] % 12, 0);
      assert.equal(result.iterations % 12, 0);
    }
    checked++;
  }
  console.log(JSON.stringify({ checked, first_operation_exactly_once: true, complete_warm_cycles: true, fresh_identities: true, fake_api_only: true }));
} finally { rmSync(dir, { recursive: true }); }
