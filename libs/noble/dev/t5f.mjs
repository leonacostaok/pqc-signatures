import { slh as m } from '../src/fast-slh-dsa.mjs';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js'; import { sha256 } from '@noble/hashes/sha2.js'; import { readFileSync } from 'node:fs';
const V=JSON.parse(readFileSync('common/vectors.json')); const R=JSON.parse(readFileSync('common/reference.json'));
const msg=hexToBytes(V.message_hex);
const names = (process.argv[2] || 'SLH-DSA-SHA2-128f,SLH-DSA-SHAKE-128f,SLH-DSA-SHA2-192f,SLH-DSA-SHAKE-256f,SLH-DSA-SHA2-128s').split(',');
for (const n of names) {
 const [, , h, sz] = n.split('-'); const a = m[`slh_dsa_${h.toLowerCase()}_${sz}`];
 const seed=hexToBytes(V.params.find(p=>p.name===n).seed_hex); let t0=performance.now(); const k=a.keygen(seed); const tk=performance.now()-t0;
 t0=performance.now(); const sig=a.sign(msg,k.secretKey,{extraEntropy:false}); const ts=performance.now()-t0;
 const t=sig.slice(); t[100]^=1;
 t0=performance.now(); const ok=a.verify(sig,msg,k.publicKey); const tv=performance.now()-t0;
 console.log(process.env.NOBLE_PQ_HASH||'noble', n, bytesToHex(sha256(k.publicKey))===R[n].pk_sha256, bytesToHex(sha256(k.secretKey))===R[n].sk_sha256, bytesToHex(sha256(sig))===R[n].sig_sha256, ok, a.verify(t,msg,k.publicKey), 'kg',tk.toFixed(1),'sign',ts.toFixed(1),'ver',tv.toFixed(2));
}
