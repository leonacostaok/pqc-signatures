import * as m from '../build/vendor/falcon.js';
import * as orig from '@noble/post-quantum/falcon.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js'; import { sha256 } from '@noble/hashes/sha2.js'; import { readFileSync } from 'node:fs';
const V=JSON.parse(readFileSync('common/vectors.json'));
const msg=hexToBytes(V.message_hex);
for (const [n,a,o] of [['Falcon-512',m.falcon512,orig.falcon512],['Falcon-1024',m.falcon1024,orig.falcon1024]]) {
 const seed=hexToBytes(V.params.find(p=>p.name===n).seed_hex); let t0=performance.now(); const k=a.keygen(seed); const tk=performance.now()-t0;
 const ko=o.keygen(seed); const sigo=o.sign(msg,ko.secretKey,{extraEntropy:false});
 t0=performance.now(); const sig=a.sign(msg,k.secretKey,{extraEntropy:false}); const ts=performance.now()-t0;
 t0=performance.now(); const exp=a.expandSk(k.secretKey); const te=performance.now()-t0;
 t0=performance.now(); const sig2=a.signPrecomputed(msg,exp,{extraEntropy:false}); const ts2=performance.now()-t0; const sig3=a.signPrecomputed(msg,exp,{extraEntropy:false});
 const pe=a.expandPk(k.publicKey); const t=sig.slice(); t[100]^=1;
 t0=performance.now(); const ok=a.verify(sig,msg,k.publicKey); const tv=performance.now()-t0;
 t0=performance.now(); const ok2=a.verifyPrecomputed(sig,msg,pe); const tv2=performance.now()-t0;
 const eq=(x,y)=>bytesToHex(sha256(x))===bytesToHex(sha256(y));
 console.log(process.env.NOBLE_PQ_HASH||'noble', n, 'pk=orig',eq(k.publicKey,ko.publicKey), 'sk=orig',eq(k.secretKey,ko.secretKey),'sig=orig',eq(sig,sigo), eq(sig2,sigo), eq(sig3,sigo), ok, ok2, a.verifyPrecomputed(sig,msg,pe), a.verifyPrecomputed(t,msg,pe), a.verify(t,msg,k.publicKey), 'kg',tk.toFixed(1),'sign',ts.toFixed(1),'exp',te.toFixed(1),'signPre',ts2.toFixed(1),'ver',tv.toFixed(2),'verPre',tv2.toFixed(2));
}
