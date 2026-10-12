import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { PerformanceObserver, performance } from 'node:perf_hooks';
import v8 from 'node:v8';
import { algorithm, decode, prepare } from './common.mjs';
const o=JSON.parse(process.argv[2]);const fixture=JSON.parse(readFileSync(o.fixture));
assert(['check','latency','resource'].includes(o.mode));
assert(['default','constrained'].includes(o.settings));
assert(!o.operation||['keygen','getPublicKey','sign','verify'].includes(o.operation));
assert.equal(fixture.parameter,o.parameter);
const {alg,spec}=await algorithm(o.root,o.parameter);
const warm=fixture.rows.filter(x=>x.group==='warmup').map(decode),cases=fixture.rows.filter(x=>x.group==='measured').map(decode);
assert(warm.length===2&&cases.length===3);
assert.equal(fixture.rows.length,5);
assert(o.operation!=='getPublicKey'||spec.affected);
const ops=o.operation?[o.operation]:(spec.affected&&o.mode==='check'?['keygen','getPublicKey','sign','verify']:['keygen','sign','verify']);
const output={schema:'noble-resource-followup-v1',parameter:o.parameter,mode:o.mode,settings:o.settings,node:process.version,v8:process.versions.v8,exec_argv:process.execArgv,heap_limit_bytes:v8.getHeapStatistics().heap_size_limit,rows:[],checks:{inputs_preserved:true,exact_outputs:true}};
for(const op of ops){
  const warmCount=spec.affected?24:2;
  for(let i=0;i<warmCount;i++){const c=prepare(alg,spec,warm[i%2],op);c.check(c.call());}
  const events=[];const observer=new PerformanceObserver(list=>{for(const e of list.getEntries())events.push({start_ms:e.startTime,duration_ms:e.duration,kind:e.detail.kind,flags:e.detail.flags});});
  if(o.mode==='resource')observer.observe({entryTypes:['gc']});
  await new Promise(setImmediate);
  const digest=createHash('sha256'), samples=[];let maxMemory={};
  const sample=(index)=>{const m=process.memoryUsage();for(const [k,v]of Object.entries(m))maxMemory[k]=Math.max(maxMemory[k]||0,v);if(index%16===0||index===-1)samples.push({index,...m});return m;};
  const initial=o.mode==='resource'?sample(-1):null;
  const count=o.mode==='check'?3:o.mode==='resource'?192:3;
  const apiNs=[];const cpu0=process.cpuUsage(), t0=performance.now();
  for(let i=0;i<count;i++){
    const c=prepare(alg,spec,cases[i%3],op),a=process.hrtime.bigint();const result=c.call();const b=process.hrtime.bigint();apiNs.push(Number(b-a));
    if(o.mode==='resource')sample(i);
    for(const part of c.check(result))digest.update(part);
    if(o.mode==='resource'&&i%16===15)await new Promise(setImmediate);
  }
  const t1=performance.now(),cpu=process.cpuUsage(cpu0),end=o.mode==='resource'?sample(count):null;
  let stable=0,last=-1;for(let i=0;i<12&&stable<3;i++){await new Promise(setImmediate);stable=events.length===last?stable+1:0;last=events.length;}observer.disconnect();
  const gc=events.filter(x=>x.start_ms>=t0&&x.start_ms<=t1);
  output.rows.push({operation:op,count,warmup_calls:warmCount,api_ns:apiNs,checked_workload_ms:t1-t0,checked_workload_cpu_us:cpu.user+cpu.system,output_sha256:digest.digest('hex'),memory:{initial,end,sampled_max:maxMemory,samples},gc:{delivery:'observed after bounded stability drain; zero does not prove absence',events:gc,cycles:gc.length,duration_ms:gc.reduce((s,e)=>s+e.duration_ms,0)},process_maxrss_kib:process.resourceUsage().maxRSS,metric:o.mode==='resource'?'instrumented checked workload; sampling after synchronous operations misses internal peaks; GC includes copies/checks/JIT':'ordinary API clocks; copies/checks outside clock; capped disjoint warmup, no steady-state claim'});
}
for(const c of cases){const bad=c.signature.slice();bad[Math.floor(bad.length/2)]^=1;const saved=bad.slice();assert.equal(alg.verify(bad,c.message.slice(),c.publicKey.slice(),spec.falcon?{}:{context:c.context.slice()}),false);assert.deepEqual(bad,saved);}
output.checks.tamper_rejections=cases.length;
console.log(JSON.stringify(output));
