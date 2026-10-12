// Run from the audit worktree root after installing the lockfile packages under libs/noble/node_modules and applying the three patches under libs/noble/build/vendor.
// This only performs correctness probes; it does not run timing benchmarks or write results/.
import fs from 'node:fs';
import zlib from 'node:zlib';
const root = process.cwd();
const mlFast = await import(`${root}/libs/noble/src/fast-ml-dsa.mjs`);
const { slh } = await import(`${root}/libs/noble/src/fast-slh-dsa.mjs`);
const mlVendor = await import(`${root}/libs/noble/build/vendor/ml-dsa.js`);
const slhVendor = await import(`${root}/libs/noble/build/vendor/slh-dsa.js`);
const suite = JSON.parse(zlib.gunzipSync(fs.readFileSync('common/validation/validation.json.gz')));
const hx = s => Uint8Array.from(Buffer.from(s || '', 'hex'));
const mlNames = { 'ML-DSA-44': 'ml_dsa44', 'ML-DSA-65': 'ml_dsa65', 'ML-DSA-87': 'ml_dsa87' };
const report = { runtime: process.version, hash: process.env.NOBLE_PQ_HASH || 'noble', fast: { pass: 0, fail: 0 }, vendor: { pass: 0, fail: 0 }, failures: [] };
const cases = suite.cases.filter(c => c.kind === 'sigver' || c.kind === 'siggen' && c.param.startsWith('ML-DSA'));
for (const c of cases) {
  const key = mlNames[c.param] || c.param.toLowerCase().replaceAll('-', '_');
  for (const [name, registry] of [['fast', { ...mlFast, ...slh }], ['vendor', { ...mlVendor, ...slhVendor }]]) {
    let got = false;
    const alg = registry[key];
    if (!alg) throw Error(key);
    try {
      got = c.kind === 'sigver' ? alg.verify(hx(c.sig_hex), hx(c.msg_hex), hx(c.pk_hex), { context: hx(c.ctx_hex) }) === true : Buffer.from(alg.sign(hx(c.msg_hex), hx(c.sk_hex), { context: hx(c.ctx_hex), extraEntropy: false })).toString('hex') === c.expect_sig_hex;
    } catch {}
    const pass = got === (c.kind === 'sigver' ? c.expect : true);
    report[name][pass ? 'pass' : 'fail']++;
    if (!pass) report.failures.push({ name, id: c.id, param: c.param });
  }
}
console.log(JSON.stringify(report, null, 2));
