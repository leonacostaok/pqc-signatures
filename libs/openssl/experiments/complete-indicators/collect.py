#!/usr/bin/env python3
"""Collect source-bound C indicators serially; run only in an exclusive window."""
import argparse, datetime, hashlib, json, math, os, random, subprocess, sys
from pathlib import Path

OPS=['keygen','sign','verify']
def need(ok,message):
    if not ok: raise ValueError(message)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,j):Path(p).write_text(json.dumps(j,indent=2)+'\n')
def checked_manifest(path):
    j=json.loads(path.read_text());need(j['complete'] is True and j['schema']=='c-provider-indicators-prepared-v1','invalid preparation')
    for p,h in j['sha256'].items():need(sha(p)==h,'changed prepared input '+p)
    for key,value in j['environment'].items():need(os.environ.get(key)==value,'changed environment '+key)
    for spec in j['parameters']:
        need(len(spec['records'])==11 and len({r['pk_sha256'] for r in spec['records']})==11,'not eleven distinct keys')
        sides=[spec['baseline']]+(['candidate'] if spec['paired_resource'] else [])
        need(all(spec['checks'][side][str(op)] is True for side in sides for op in range(3)),'missing correctness gate')
    return j
def jobs(j,phase):
    planned=[]
    if phase=='baseline-timing':
        for fork in range(3):
            cells=[(p,op) for p in j['parameters'] if p['baseline_timing'] for op in range(3)]
            random.Random(20261012+fork).shuffle(cells)
            for p,op in cells:planned.append(dict(parameter=p['parameter'],op=op,side=p['baseline'],mode='timing',key=0,fork=fork))
    else:
        for mode in ['allocation','rss','stack-a5']:
            for p in j['parameters']:
                if not p['paired_resource']:continue
                for op in range(3):
                    for fork,key in enumerate([1,2,3,4]):
                        order=['baseline','candidate'] if fork in [0,3] else ['candidate','baseline']
                        for side in order:planned.append(dict(parameter=p['parameter'],op=op,side=side,mode=mode,key=key,fork=fork))
        for side in ['baseline','candidate']:
            for mode in ['stack-control-a5','stack-control-5a']:
                planned.append(dict(parameter='SLH-DSA-SHA2-128f',op=2,side=side,mode=mode,key=1,fork=0))
            for parameter,op in [('SLH-DSA-SHA2-128f',2),('SLH-DSA-SHA2-256s',1)]:
                planned.append(dict(parameter=parameter,op=op,side=side,mode='stack-5a',key=1,fork=0))
    return planned
def validate(rows,job,spec):
    expected=list(range(1,11)) if job['key']==0 else [job['key']]
    need([r['key'] for r in rows]==expected,'missing/duplicate/wrong key rows')
    for r in rows:
        need(r['parameter']==spec['native_parameter'] and r['operation']==job['op'] and r['mode']==job['mode'],'wrong row identity')
        need(r['valid'] is True and r['input_unchanged'] is True,'incorrect output/input')
        control=job['mode'].startswith('stack-control')
        need(r['output_sha256']==('not-an-operation' if control else spec['records'][r['key']]['operation_sha256'][job['op']]),'wrong operation output')
        numeric=['wall_ns','cpu_ns','peak_rss_pre_bytes','peak_rss_post_bytes','observed_overwritten_thread_stack_bytes','allocations','allocated_requested_bytes','peak_tracked_live_bytes','retained_at_return_bytes','net_after_cleanup_bytes','frees']
        need(all(type(r[k]) is int and r[k]>=0 for k in numeric),'invalid integer metric')
        if job['mode']=='timing':need(r['wall_ns']>0 and r['cpu_ns']>0,'unusable clock value')
        if job['mode']=='allocation':need(r['allocations']==r['frees'] and r['net_after_cleanup_bytes']==0 and r['retained_at_return_bytes']<=r['peak_tracked_live_bytes']<=r['allocated_requested_bytes'],'bad allocation lifecycle')
        if job['mode']=='rss':need(r['peak_rss_post_bytes']>=r['peak_rss_pre_bytes']>0,'bad peak RSS')
        if job['mode'].startswith('stack-'):need(0<r['observed_overwritten_thread_stack_bytes']<16*1024*1024,'bad stack watermark')
    return rows
def main():
    need(sys.flags.optimize==0,'Python assertions/optimization configuration unsupported')
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--phase',choices=['baseline-timing','resources'],required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    manifest=args.manifest.resolve();j=checked_manifest(manifest);args.out.mkdir(parents=True,exist_ok=False)
    plan=jobs(j,args.phase);specs={s['parameter']:s for s in j['parameters']}
    status=dict(schema='c-provider-indicators-execution-v1',complete=False,provider=j['provider'],phase=args.phase,manifest=str(manifest),manifest_sha256=sha(manifest),collector_sha256=sha(__file__),python=sys.version,python_optimization=sys.flags.optimize,started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),jobs=plan,executed=[])
    write(args.out/'execution.json',status)
    for index,job in enumerate(plan):
        spec=specs[job['parameter']];cmd=[j['binaries'][job['side']],job['mode'],spec['native_parameter'],spec['input'],spec['corpus'],str(job['op']),str(job['key'])]
        start=datetime.datetime.now(datetime.timezone.utc).isoformat();r=subprocess.run(cmd,capture_output=True,text=True)
        raw=args.out/(f'{index:03d}.jsonl');raw.write_text(r.stdout);err=args.out/(f'{index:03d}.stderr');err.write_text(r.stderr)
        record=dict(index=index,job=job,command=cmd,started_at=start,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),returncode=r.returncode,raw_file=raw.name,raw_sha256=sha(raw),stderr_file=err.name,stderr_sha256=sha(err))
        status['executed'].append(record);write(args.out/'execution.json',status)
        need(r.returncode==0,'failed collection process; preserved '+str(raw))
        validate([json.loads(line) for line in r.stdout.splitlines()],job,spec)
    checked_manifest(manifest);need(sha(manifest)==status['manifest_sha256'],'changed manifest')
    status['complete']=True;status['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();write(args.out/'execution.json',status)
    print(json.dumps(dict(complete=True,provider=j['provider'],phase=args.phase,processes=len(plan),out=str(args.out))))
if __name__=='__main__':main()
