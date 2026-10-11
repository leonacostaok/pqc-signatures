import * as m from '../src/fast-ml-dsa.mjs';
import { hexToBytes } from '@noble/hashes/utils.js'; import { readFileSync } from 'node:fs';
const V=JSON.parse(readFileSync('common/vectors.json')); const msg=hexToBytes(V.message_hex);
const a=m.ml_dsa65; const seed=hexToBytes(V.params.find(p=>p.name==='ML-DSA-65').seed_hex); const k=a.keygen(seed);
const op=process.argv[2]||'sign'; const sig=a.sign(msg,k.secretKey,{extraEntropy:false});
const f = op==='sign'? ()=>a.sign(msg,k.secretKey,{extraEntropy:false}) : op==='verify' ? ()=>a.verify(sig,msg,k.publicKey) : ()=>a.keygen(seed);
const s=performance.now(); let n=0; while(performance.now()-s<3000){f();n++;} console.log(op, (performance.now()-s)/n);
