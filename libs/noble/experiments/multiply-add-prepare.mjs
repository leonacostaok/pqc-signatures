// Apply the reviewable patch to isolated, integrity-checked upstream copies.
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = new URL('../../../', import.meta.url);
const upstream = new URL('node_modules/@noble/post-quantum/', root);
const build = new URL('../build/multiply-add/', import.meta.url);
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const pkg = JSON.parse(readFileSync(new URL('package.json', upstream)));
assert.equal(pkg.version, '0.7.1', 'install the locked noble version with npm ci');
for (const [path, hash] of [
  ['ml-dsa.js', '7c64e733930b115b72bd0585731d8202f1caa819e081cc1e682a19d1fcbcfbda'],
  ['src/ml-dsa.ts', '7c54716e7e2e7983b2132b0d3ebd04c5c3d031efffc7c17d15db75245ead9992'],
]) assert.equal(sha256(readFileSync(new URL(path, upstream))), hash, `unexpected upstream ${path}`);
for (const name of ['baseline', 'candidate']) {
  const dest = new URL(`${name}/`, build);
  mkdirSync(dest, { recursive: true });
  cpSync(upstream, dest, { recursive: true });
}
for (const patch of ['ml-dsa-rowdot-js.patch', 'ml-dsa-rowdot.patch']) {
  execFileSync('git', ['apply', '--check', fileURLToPath(new URL(`../patches/${patch}`, import.meta.url))], { cwd: fileURLToPath(new URL('candidate/', build)) });
  execFileSync('git', ['apply', fileURLToPath(new URL(`../patches/${patch}`, import.meta.url))], { cwd: fileURLToPath(new URL('candidate/', build)) });
}
// Test-only access to the actual private helper; the benchmark imports the normal module.
const code = readFileSync(new URL('candidate/ml-dsa.js', build), 'utf8');
assert.ok(code.includes('const DotNTTs ='), 'patch must have applied');
writeFileSync(new URL('candidate/ml-dsa.audit.js', build), code + '\nexport { DotNTTs };\n');
writeFileSync(new URL('mode.json', build), JSON.stringify({ mode: 'rows', version: pkg.version }) + '\n');
console.log('Prepared row-dot candidate from noble 0.7.1');
