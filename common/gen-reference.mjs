// Computes reference SHA-256 digests (pk, sk, sig) for byte-matchable params using noble baseline.
// Other libraries must reproduce these exactly; check-match.mjs also confirms cross-library consensus.
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import * as slh from '@noble/post-quantum/slh-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync } from 'node:fs';

const V = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url)));
const impl = (name) => {
  if (name.startsWith('ML-DSA')) return { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 }[name];
  const [, , h, s] = name.split('-');
  return slh[`slh_dsa_${h.toLowerCase()}_${s}`];
};
const msg = hexToBytes(V.message_hex);
const ref = {};
for (const p of V.params.filter((p) => p.byte_match_expected)) {
  const alg = impl(p.name);
  const { publicKey, secretKey } = alg.keygen(hexToBytes(p.seed_hex));
  const sig = alg.sign(msg, secretKey, { extraEntropy: false });
  if (!alg.verify(sig, msg, publicKey)) throw new Error(`verify failed ${p.name}`);
  ref[p.name] = {
    pk_len: publicKey.length, sk_len: secretKey.length, sig_len: sig.length,
    pk_sha256: bytesToHex(sha256(publicKey)), sk_sha256: bytesToHex(sha256(secretKey)), sig_sha256: bytesToHex(sha256(sig)),
  };
  console.log(p.name, ref[p.name].sig_len);
}
writeFileSync(new URL('./reference.json', import.meta.url), JSON.stringify(ref, null, 2) + '\n');
