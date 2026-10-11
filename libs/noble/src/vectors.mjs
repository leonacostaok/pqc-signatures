// vectors <out.json>: baseline keygen + deterministic sign + verify for every supported param;
// writes the artifacts file described in CONTRACT.md and checks the byte-matchable params against
// common/reference.json (non-zero exit on any mismatch).
import { writeFileSync } from 'node:fs';
import { bytesToHex } from '@noble/hashes/utils.js';
import { LIB, LIB_VERSION, MESSAGE, PARAM_NAMES, REFERENCE, isByteMatch, loadAlg, seedOf } from './algs.mjs';
import { digest, flipBit } from './refcheck.mjs';

const out = process.argv[2];
if (!out) throw new Error('usage: vectors <out.json>');
const entries = [];
let bad = 0;
for (const param of PARAM_NAMES) {
  const alg = await loadAlg('pkg', param);
  const { publicKey, secretKey } = alg.keygen(seedOf(param));
  const sig = alg.sign(MESSAGE, secretKey);
  const selfVerify = alg.verify(sig, MESSAGE, publicKey) === true;
  const tamper = alg.verify(flipBit(sig), MESSAGE, publicKey) === false;
  const e = {
    param,
    pk_hex: bytesToHex(publicKey),
    sig_hex: bytesToHex(sig),
    sk_sha256: digest(secretKey),
    pk_sha256: digest(publicKey),
    sig_sha256: digest(sig),
    self_verify: selfVerify && tamper,
  };
  if (isByteMatch(param)) {
    const r = REFERENCE[param];
    e.reference_match = r && r.pk_sha256 === e.pk_sha256 && r.sk_sha256 === e.sk_sha256 && r.sig_sha256 === e.sig_sha256;
    if (!e.reference_match) bad++;
  } else e.reference_match = null; // Falcon: not byte-matchable across libraries
  if (!e.self_verify) bad++;
  console.error(`[noble] ${param.padEnd(19)} sig ${String(sig.length).padStart(6)} B  self_verify=${e.self_verify}  reference_match=${e.reference_match}`);
  entries.push(e);
}
writeFileSync(out, JSON.stringify({ lib: LIB, lib_version: LIB_VERSION, entries }, null, 1) + '\n');
if (bad) {
  console.error(`[noble] ${bad} problem(s)`);
  process.exit(1);
}
