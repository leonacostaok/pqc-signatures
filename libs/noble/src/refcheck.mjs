// Reference inputs/digests. For byte-matchable params the expected digests come from
// common/reference.json; for Falcon (no cross-library reference) the expectation is the output of
// the unmodified @noble/post-quantum baseline computed at runtime (noble's seeded Falcon keygen and
// extraEntropy:false signing are deterministic), so Falcon variants are checked for self-consistency.
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { MESSAGE, REFERENCE, isByteMatch, loadAlg, seedOf } from './algs.mjs';

export const digest = (b) => bytesToHex(sha256(b));
export const flipBit = (sig) => {
  const t = sig.slice();
  t[t.length >> 1] ^= 0x01;
  return t;
};
export const sameBytes = (a, b) => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

const cache = new Map();
// Returns { seed, msg, pk, sk, sig, pk_sha256, sk_sha256, sig_sha256, reference: 'common'|'baseline' }
// The pk/sk/sig are produced by the baseline and (for byte-match params) verified against reference.json.
export async function referenceInputs(param) {
  if (cache.has(param)) return cache.get(param);
  const base = await loadAlg('pkg', param);
  const seed = seedOf(param);
  const { publicKey: pk, secretKey: sk } = base.keygen(seed);
  const sig = base.sign(MESSAGE, sk);
  const out = { seed, msg: MESSAGE, pk, sk, sig, pk_sha256: digest(pk), sk_sha256: digest(sk), sig_sha256: digest(sig), reference: 'baseline' };
  if (isByteMatch(param)) {
    const ref = REFERENCE[param];
    if (!ref) throw new Error(`no reference digests for ${param}`);
    for (const k of ['pk_sha256', 'sk_sha256', 'sig_sha256'])
      if (ref[k] !== out[k]) throw new Error(`baseline ${param} ${k} does not match common/reference.json (${out[k]} vs ${ref[k]})`);
    out.reference = 'common/reference.json';
  }
  if (!base.verify(sig, MESSAGE, pk)) throw new Error(`baseline self-verify failed for ${param}`);
  cache.set(param, out);
  return out;
}
