import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const root = resolve(import.meta.dirname, '../../build/tenkeys'); mkdirSync(root, { recursive: true });
const tmp = mkdtempSync(join(root, 'worker-test-'));
try {
  const module = join(tmp, 'fake.mjs'), corpus = join(tmp, 'corpus.json');
  writeFileSync(module, `import assert from 'node:assert/strict';
const seen=new WeakSet(); const count={keygen:0,sign:0,verify:0};
const fresh=(...values)=>{for(const v of values){assert.ok(!seen.has(v),'reused caller object');seen.add(v);}};
const signature=(m,s,c)=>Uint8Array.from([s[0],m[0]||0,c[0]||0,77]);
export const ml_dsa44={keygen(seed){fresh(seed);count.keygen++;return {publicKey:seed.slice(),secretKey:seed.slice()};},
sign(m,s,o){fresh(m,s,o,o.context);count.sign++;assert.equal(o.extraEntropy,false);return signature(m,s,o.context);},
verify(sig,m,p,o){fresh(sig,m,p,o,o.context);count.verify++;return Buffer.from(sig).equals(Buffer.from(signature(m,p,o.context)));}};
process.on('exit',()=>assert.deepEqual(count,{keygen:18,sign:18,verify:36}));`);
  const item=(i)=>({index:i,seed:(i+1).toString(16).padStart(2,'0'),message:'22',context:'33'});
  writeFileSync(corpus,JSON.stringify({id:'protocol-test',parameters:{44:{warmup:[100,101,102,103].map(item),measured:Array.from({length:10},(_,i)=>item(i))}}}));
  const args={module,corpus,param:'44',warmupCycles:2};
  const r=spawnSync(process.execPath,[join(import.meta.dirname,'worker.mjs'),JSON.stringify(args)],{encoding:'utf8'});
  assert.equal(r.status,0,r.stderr);const result=JSON.parse(r.stdout);
  assert.equal(result.rows.length,10);assert.deepEqual(result.measured_calls,{keygen:10,sign:10,verify:10});
  assert.ok(result.rows.every(r=>r.valid&&r.tamper_rejected&&r.inputs_preserved));
  console.log(JSON.stringify({protocol:'passed',measured_keys:10,warmup_disjoint:true,fresh_caller_objects:true,exact_measured_calls:true}));
} finally { rmSync(tmp,{recursive:true,force:true}); }
