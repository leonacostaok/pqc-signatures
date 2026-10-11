// crossverify <artifacts.json> <out.json>: verifies every entry of another library's artifacts file
// with the noble baseline verify (pk_hex / sig_hex from the file, message from common/vectors.json),
// plus one tampered-signature check (one bit flipped) per param. Unsupported params are skipped.
import { readFileSync, writeFileSync } from 'node:fs';
import { hexToBytes } from '@noble/hashes/utils.js';
import { LIB, MESSAGE, PARAM_NAMES, loadAlg } from './algs.mjs';
import { flipBit } from './refcheck.mjs';

const [inFile, outFile] = process.argv.slice(2);
if (!inFile || !outFile) throw new Error('usage: crossverify <artifacts.json> <out.json>');
const art = JSON.parse(readFileSync(inFile, 'utf8'));
const results = [];
for (const e of art.entries || []) {
  if (!PARAM_NAMES.includes(e.param)) continue;
  const alg = await loadAlg('pkg', e.param);
  let ok = false;
  let error = null;
  let tamper = false;
  try {
    const pk = hexToBytes(e.pk_hex);
    const sig = hexToBytes(e.sig_hex);
    ok = alg.verify(sig, MESSAGE, pk) === true;
    try {
      tamper = alg.verify(flipBit(sig), MESSAGE, pk) === false;
    } catch {
      tamper = true; // an exception on malformed input is a rejection
    }
  } catch (err) {
    error = String(err && err.message ? err.message : err);
  }
  results.push({ param: e.param, ok, error, tamper_rejected: tamper });
  console.error(`[noble] crossverify ${art.lib} ${e.param.padEnd(19)} ok=${ok} tamper_rejected=${tamper}${error ? ' error=' + error : ''}`);
}
writeFileSync(outFile, JSON.stringify({ lib: LIB, source: art.lib, results }, null, 1) + '\n');
