import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { algorithm, hex } from './common.mjs';
const [root, parameter, output] = process.argv.slice(2);
const { alg, spec } = await algorithm(root,parameter);
const rows=[];
for (const group of ['warmup','measured']) for (let index=0;index<(group==='warmup'?2:3);index++) {
  const derive=(name,n)=>new Uint8Array(createHash('shake256',{outputLength:n}).update(`resource-followup-v1/${parameter}/${group}/${index}/${name}`).digest());
  const seed=derive('seed',alg.lengths.seed),message=derive('message',[0,64,1024][index%3]);
  const context=derive('context',spec.falcon?0:[0,31,255][index%3]),entropy=derive('entropy',48);
  const {publicKey,secretKey}=alg.keygen(seed);
  const opts=spec.falcon?{extraEntropy:entropy}:{context,extraEntropy:false};
  const signature=alg.sign(message,secretKey,opts);assert(alg.verify(signature,message,publicKey,spec.falcon?{}:{context}));
  const bad=signature.slice();bad[Math.floor(bad.length/2)]^=1;assert(!alg.verify(bad,message,publicKey,spec.falcon?{}:{context}));
  rows.push({group,index,...Object.fromEntries(Object.entries({seed,message,context,entropy,publicKey,secretKey,signature}).map(([k,v])=>[k,hex(v)]))});
}
writeFileSync(output,JSON.stringify({schema:'noble-followup-fixture-v1',parameter,rows})+'\n',{flag:'wx'});
