import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import * as slh from '@noble/post-quantum/slh-dsa.js';
import { falcon512, falcon1024 } from '@noble/post-quantum/falcon.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
const V = JSON.parse(readFileSync('common/vectors.json'));
const msg = hexToBytes(V.message_hex);
const t = (f) => { const s = process.hrtime.bigint(); const r = f(); return [Number(process.hrtime.bigint() - s) / 1e6, r]; };
const algs = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87, 'SLH-DSA-SHA2-128f': slh.slh_dsa_sha2_128f, 'SLH-DSA-SHAKE-128f': slh.slh_dsa_shake_128f, 'SLH-DSA-SHA2-128s': slh.slh_dsa_sha2_128s, 'SLH-DSA-SHAKE-256s': slh.slh_dsa_shake_256s, 'Falcon-512': falcon512, 'Falcon-1024': falcon1024 };
for (const [n, a] of Object.entries(algs)) {
  const seed = hexToBytes(V.params.find(p => p.name === n).seed_hex);
  const [tk, { publicKey, secretKey }] = t(() => a.keygen(seed));
  const [ts, sig] = t(() => a.sign(msg, secretKey, { extraEntropy: false }));
  const [tv, ok] = t(() => a.verify(sig, msg, publicKey));
  const [ts2, sig2] = t(() => a.sign(msg, secretKey, { extraEntropy: false }));
  console.log(n, 'keygen', tk.toFixed(2), 'sign', ts.toFixed(2), ts2.toFixed(2), 'verify', tv.toFixed(2), ok, sig.length);
}
// hash micro: 64-byte sha256 x 100k
const b = new Uint8Array(86); let s = process.hrtime.bigint();
for (let i = 0; i < 100000; i++) sha256(b); console.log('noble sha256 86B x100k ms', Number(process.hrtime.bigint() - s) / 1e6);
s = process.hrtime.bigint();
for (let i = 0; i < 100000; i++) createHash('sha256').update(b).digest(); console.log('node sha256 86B x100k ms', Number(process.hrtime.bigint() - s) / 1e6);
s = process.hrtime.bigint();
for (let i = 0; i < 100000; i++) shake256(b, { dkLen: 32 }); console.log('noble shake256 86B x100k ms', Number(process.hrtime.bigint() - s) / 1e6);
s = process.hrtime.bigint();
for (let i = 0; i < 100000; i++) createHash('shake256', { outputLength: 32 }).update(b).digest(); console.log('node shake256 86B x100k ms', Number(process.hrtime.bigint() - s) / 1e6);
const big = new Uint8Array(34); s = process.hrtime.bigint();
for (let i = 0; i < 10000; i++) shake128(big, { dkLen: 840 }); console.log('noble shake128 840B out x10k ms', Number(process.hrtime.bigint() - s) / 1e6);
s = process.hrtime.bigint();
for (let i = 0; i < 10000; i++) createHash('shake128', { outputLength: 840 }).update(big).digest(); console.log('node shake128 840B out x10k ms', Number(process.hrtime.bigint() - s) / 1e6);
import { shake128 } from '@noble/hashes/sha3.js';
