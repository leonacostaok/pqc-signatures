import * as m from '../src/fast-ml-dsa.mjs';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js'; import { sha256 } from '@noble/hashes/sha2.js'; import { readFileSync } from 'node:fs';
const V=JSON.parse(readFileSync('common/vectors.json')); const R=JSON.parse(readFileSync('common/reference.json'));
const msg=hexToBytes(V.message_hex);
for (const [n,a] of [['ML-DSA-44',m.ml_dsa44],['ML-DSA-65',m.ml_dsa65],['ML-DSA-87',m.ml_dsa87]]) {
 const seed=hexToBytes(V.params.find(p=>p.name===n).seed_hex); const k=a.keygen(seed);
 const sig=a.sign(msg,k.secretKey,{extraEntropy:false}); const exp=a.expandSk(k.secretKey); const sig2=a.signPrecomputed(msg,exp,{extraEntropy:false}); const sig3=a.signPrecomputed(msg,exp,{extraEntropy:false});
 const pe=a.expandPk(k.publicKey); const t=sig.slice(); t[100]^=1;
 console.log(process.env.NOBLE_PQ_HASH, n, bytesToHex(sha256(k.publicKey))===R[n].pk_sha256, bytesToHex(sha256(k.secretKey))===R[n].sk_sha256, bytesToHex(sha256(sig))===R[n].sig_sha256, bytesToHex(sha256(sig2))===R[n].sig_sha256, bytesToHex(sha256(sig3))===R[n].sig_sha256, a.verify(sig,msg,k.publicKey), a.verifyPrecomputed(sig,msg,pe), a.verifyPrecomputed(sig,msg,pe), a.verifyPrecomputed(t,msg,pe), a.verify(t,msg,k.publicKey));
 const b=(nm,f)=>{for(let i=0;i<5;i++)f();const s=performance.now();let c=0;while(performance.now()-s<400){f();c++;}console.log(' ',nm,((performance.now()-s)/c).toFixed(3));};
 b('sign',()=>a.sign(msg,k.secretKey,{extraEntropy:false})); b('signPre',()=>a.signPrecomputed(msg,exp,{extraEntropy:false})); b('verify',()=>a.verify(sig,msg,k.publicKey)); b('verifyPre',()=>a.verifyPrecomputed(sig,msg,pe)); b('keygen',()=>a.keygen(seed));
}
