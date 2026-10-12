#!/usr/bin/env python3
"""Recompute summary from every preserved process; no benchmark execution."""
import argparse, hashlib, json, math, statistics, sys
from collections import defaultdict
from pathlib import Path
if sys.flags.optimize: raise RuntimeError('Python optimization disables validation')
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
LIB=HERE.parents[1].name

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def rel(p): return str(Path(p).resolve().relative_to(ROOT))
def delta(a,b): return 100*(b/a-1) if a else None

def read_runs(folder):
    ex=json.loads((folder/'execution.json').read_text())
    manifest=json.loads((folder/'manifest.json').read_text())
    plan=json.loads((folder/'plan.json').read_text())
    assert ex['passed'] is True and ex['python_optimize']==0
    assert ex['manifest_sha256']==sha(folder/'manifest.json')
    assert len(ex['runs'])==len(plan) and len(plan)>0
    result=[]
    for i,(rec,want) in enumerate(zip(ex['runs'],plan)):
        assert rec['index']==i and rec['exit_code']==0
        assert all(rec[k]==v for k,v in want.items())
        p=folder/rec['raw']; assert sha(p)==rec['sha256']
        assert sha(p.with_suffix('.stderr'))==rec['stderr_sha256']
        data=json.loads(p.read_text())
        assert data['checks']=={'exact_outputs':True,'inputs_preserved':True,'tamper_rejections':3}
        assert all(data[k]==rec[k] for k in ('parameter','mode','settings'))
        expected_ops=[rec['operation']] if rec['operation'] else ['keygen','sign','verify']
        assert [r['operation'] for r in data['rows']]==expected_ops
        fp=folder/'fixtures'/(rec['parameter']+'.json')
        assert sha(fp)==manifest['fixtures'][rec['parameter']]['sha256']
        cases=[c for c in json.loads(fp.read_text())['rows'] if c['group']=='measured']
        assert len(cases)==3
        for row in data['rows']:
            assert type(row['count']) is int and row['count']>0
            assert len(row['api_ns'])==row['count'] and all(type(t) is int and t>0 for t in row['api_ns'])
            h=hashlib.sha256()
            for j in range(row['count']):
                c=cases[j%3];op=row['operation']
                names={'keygen':['publicKey','secretKey'],'getPublicKey':['publicKey'],'sign':['signature'],'verify':[]}[op]
                for name in names: h.update(bytes.fromhex(c[name]))
                if op=='verify': h.update(b'\x01')
            assert h.hexdigest()==row['output_sha256']
            result.append((rec,row,rel(p)))
    return result,ex,manifest

def metrics(row):
    n=row['count'];mem=row['memory'];a=mem['initial'];b=mem['end'];mx=mem['sampled_max']
    t=row['checked_workload_ms']*1e6 if LIB=='noble' else row['checked_workload_ns']
    cpu=row['checked_workload_cpu_us']*1000 if LIB=='noble' else row['checked_workload_cpu_ns']
    assert t>0 and cpu>0
    out={'api_instrumented_ns_per_op':(sum(row['api_ns'])/n,'ns/op'),
         'checked_workload_ns_per_op':(t/n,'ns/op'),
         'checked_workload_cpu_ns_per_op':(cpu/n,'ns/op'),
         'checked_throughput':(n*1e9/t,'operations/s'),
         'process_lifetime_highwater_rss':(row['process_maxrss_kib']*1024 if LIB=='noble' else row['process_maxrss_bytes'],'bytes')}
    if LIB=='noble':
        for k in ('heapUsed','heapTotal','external','arrayBuffers','rss'):
            out['sampled_max_'+k]=(mx[k],'bytes');out['ending_'+k]=(b[k],'bytes')
        out['observed_gc_cycles']=(row['gc']['cycles'],'events/workload')
        out['observed_gc_duration']=(row['gc']['duration_ms'],'ms/workload')
        out['observed_gc_duration_share']=(row['gc']['duration_ms']*1e8/t,'percent of workload wall')
    else:
        for k in ('heap_alloc_bytes','heap_inuse_bytes','heap_objects','runtime_reserved_stack_bytes'):
            out['sampled_max_'+k]=(mx[k],'objects' if k=='heap_objects' else 'bytes')
            out['ending_'+k]=(b[k],'objects' if k=='heap_objects' else 'bytes')
        for key,name,unit in [('total_allocated_bytes','allocated_bytes','bytes'),('allocated_objects','allocated_objects','objects'),('gc_cycles','gc_cycles','cycles'),('gc_pause_total_ns','gc_pause','ns'),('gc_cpu_seconds','gc_cpu','seconds')]:
            d=b[key]-a[key];assert d>=0
            out[name+'_per_workload']=(d,unit+'/workload')
            if key in ('total_allocated_bytes','allocated_objects'):out[name+'_per_op']=(d/n,unit+'/op')
        out['allocation_rate']=((b['total_allocated_bytes']-a['total_allocated_bytes'])*1e9/t,'bytes/s')
        out['gc_pause_share']=((b['gc_pause_total_ns']-a['gc_pause_total_ns'])*100/t,'percent of workload wall')
        out['last_gc_live_heap_at_end']=(b['last_gc_live_heap_bytes'],'bytes; potentially from warmup if no measured GC')
    assert all(type(v) in (float,int) and math.isfinite(v) and v>=0 for v,u in out.values())
    return out

def main(base,resource,out):
    bs,bex,bmanifest=read_runs(base);rs,rex,rmanifest=read_runs(resource)
    assert bmanifest==rmanifest
    bgroup=defaultdict(list)
    for rec,row,path in bs:
        assert rec['variant']=='baseline' and row['count']==3
        bgroup[(rec['parameter'],row['operation'])].append((rec,row,path))
    baseline=[]
    for (param,op),rows in sorted(bgroup.items()):
        assert sorted(r['round'] for r,x,p in rows)==[0,1,2]
        times=[t for r,x,p in rows for t in x['api_ns']]
        baseline.append({'library':LIB,'parameter':param,'operation':op,'wall_ns':sum(times)/len(times),'statistic':'sum of nine API wall observations / nine calls; three fresh processes','protocol':'two disjoint warmup calls per operation; capped warmup, not steady-state; fresh buffers; copying/import/checking outside API clock','source':rel(out),'raw_sources':[p for r,x,p in rows],'raw_api_ns':times,'process_highwater_rss_bytes':[x['process_maxrss_kib']*1024 if LIB=='noble' else x['process_maxrss_bytes'] for r,x,p in rows]})
    group=defaultdict(dict)
    for rec,row,path in rs:
        key=(rec['parameter'],row['operation'],rec['settings'])
        slot=(rec['round'],rec['variant']);assert slot not in group[key]
        group[key][slot]=(rec,row,path)
    paired=[]
    for (param,op,setting),slots in sorted(group.items()):
        assert set(slots)=={(r,v) for r in range(4) for v in ('baseline','candidate')}
        assert len({x['count'] for rec,x,path in slots.values()})==1
        order=['AB' if slots[(r,'baseline')][0]['index']<slots[(r,'candidate')][0]['index'] else 'BA' for r in range(4)]
        assert sorted(order)==['AB','AB','BA','BA']
        mm={k:metrics(x) for k,(rec,x,path) in slots.items()};keys=set(mm[(0,'baseline')]);assert all(set(x)==keys for x in mm.values())
        stats={}
        for key in sorted(keys):
            a=[mm[(r,'baseline')][key][0] for r in range(4)];b=[mm[(r,'candidate')][key][0] for r in range(4)]
            memory=key.startswith(('sampled_','ending_','process_','last_gc_'))
            fn=statistics.median if memory else statistics.mean
            av,bv=fn(a),fn(b)
            stats[key]={'unit':mm[(0,'baseline')][key][1],'statistic':'median across four processes' if memory else 'arithmetic mean across four equal-count workloads','baseline':av,'candidate':bv,'delta_percent':delta(av,bv),'baseline_rounds':a,'candidate_rounds':b,'round_delta_percent':[delta(x,y) for x,y in zip(a,b)],'candidate_increase_rounds':sum(y>x for x,y in zip(a,b))}
        paired.append({'library':LIB,'parameter':param,'operation':op,'settings':setting,'calls_per_process':slots[(0,'baseline')][1]['count'],'order':order,'metrics':stats,'raw_sources':[path for rec,x,path in slots.values()]})
    unavailable=[{'indicator':'exact intra-operation heap/RSS peak','value':None,'reason':'post-operation samples miss synchronous internal peaks; OS RSS high-water includes startup and warmup'}, {'indicator':'consumed stack high-water','value':None,'reason':'configured limits and Go StackInuse are not consumed stack'}]
    if LIB=='noble':unavailable.append({'indicator':'total JS allocation bytes/rate and GC CPU','value':None,'reason':'public Node counters do not expose exact allocation traffic or GC CPU; heap balances and observed event durations cannot substitute'})
    unsupported=[]
    if LIB=='circl':
        for p in ('Falcon-512','Falcon-1024'):
            unsupported.append({'library':LIB,'parameter':p,'operations':['keygen','sign','verify'],'reason':'Pinned CIRCL signature registry lists no Falcon implementation; ByName returns nil for unregistered schemes','source':'https://github.com/cloudflare/circl/blob/91db3e785ba2635b4f24a023e1ad76d2780e2865/sign/schemes/schemes.go#L32-L56'})
    result={'schema':LIB+'-resource-followup-summary-v1','baseline_timings':baseline,'paired_resources':paired,'unsupported':unsupported,'unavailable':unavailable,'provenance':{'baseline_execution_sha256':sha(base/'execution.json'),'resource_execution_sha256':sha(resource/'execution.json'),'manifest_sha256':sha(base/'manifest.json'),'baseline_processes':len(bex['runs']),'resource_processes':len(rex['runs']),'all_output_digests_independently_recomputed':True},'interpretation':'Resource workloads include copies, key import, checking/digests, sampling and runtime activity. Metrics are not clean latency or crypto-only allocation/GC; zero observations are not proof of no cost. Percentages are null for zero baseline. No selected/lost rounds omitted.'}
    with out.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(out)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('baseline',type=Path);p.add_argument('resource',type=Path);p.add_argument('out',type=Path);a=p.parse_args();main(a.baseline,a.resource,a.out)
