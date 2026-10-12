#!/usr/bin/env python3
"""Independently recompute serialized C indicator results without collector imports."""
import argparse, datetime, hashlib, json, math, random, statistics
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
OPS=['keygen','sign','verify']
def require(ok,message):
    if not ok:raise ValueError(message)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def equal(actual,expected):
    if expected is None:require(actual is None,'expected null');return
    require(type(actual) in [int,float] and math.isfinite(actual) and math.isclose(actual,expected,rel_tol=1e-12,abs_tol=1e-9),'numeric mismatch')
def pct(a,b):return 100*(b/a-1) if a else None
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--provider',choices=['liboqs','openssl'],required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--local-builds',action='store_true',help='also require and rehash every original absolute source/build path');args=p.parse_args()
    base=ROOT/'results'/args.provider/'complete-indicators';ready=json.loads((base/'ready.json').read_text());summary=json.loads((base/'summary.json').read_text())
    require(summary['complete'] is True and summary['library']==args.provider,'bad summary')
    require(summary['manifest_sha256']==sha(base/'ready.json'),'wrong manifest')
    inventory=json.loads((base/'artifact-inventory.json').read_text())
    require(inventory['schema']=='c-indicators-artifact-inventory-v1' and inventory['ready_sha256']==sha(base/'ready.json'),'wrong artifact inventory')
    entries=inventory['entries'];require(len(entries)==len(ready['sha256']) and {e['original_path']:e['sha256'] for e in entries}==ready['sha256'],'inventory coverage/digest mismatch')
    unavailable=[];saved_checks=0
    for entry in entries:
        relative=entry['repository_path']
        if relative is not None:
            path=(ROOT/relative).resolve();require(path.is_relative_to(ROOT) and sha(path)==entry['sha256'],'changed saved source/input');saved_checks+=1
        else:
            require(entry['availability']=='local-build-only' and bool(entry['unavailable_reason']),'unexplained unavailable artifact')
            require(entry['original_path'] in ready['binaries'].values() or Path(entry['original_path']).suffix in ['.a','.dylib','.so'],'source/configuration/fixture cannot be silently unavailable')
            unavailable.append(dict(original_path=entry['original_path'],sha256=entry['sha256'],reason=entry['unavailable_reason']))
        if args.local_builds:require(sha(entry['original_path'])==entry['sha256'],'changed local source/build/input')
    specs={s['parameter']:s for s in ready['parameters']};all_rows={};runs=0;rows_count=0
    for phase,count in [('baseline-timing',99 if args.provider=='liboqs' else 72),('resources',440)]:
        d=base/phase;status=json.loads((d/'execution.json').read_text())
        require(status['complete'] is True and status['provider']==args.provider and status['phase']==phase,'wrong execution')
        require(len(status['executed'])==count and len(status['jobs'])==count,'missing jobs')
        require(status['manifest_sha256']==sha(base/'ready.json') and status['python_optimization']==0 and status['collector_sha256']==sha(Path(__file__).with_name('collect.py')),'execution provenance mismatch')
        require(summary['execution_sha256'][phase]==sha(d/'execution.json'),'execution changed')
        expected_order=[]
        if phase=='baseline-timing':
            for fork in range(3):
                cells=[(s,o) for s in specs.values() if s['baseline_timing'] for o in range(3)];random.Random(20261012+fork).shuffle(cells)
                expected_order.extend((s['parameter'],o,s['baseline'],'timing',0,fork) for s,o in cells)
        else:
            for mode in ['allocation','rss','stack-a5']:
                for s in specs.values():
                    if not s['paired_resource']:continue
                    for op in range(3):
                        for fork,key in enumerate(range(1,5)):
                            for side in (['baseline','candidate'] if fork in [0,3] else ['candidate','baseline']):expected_order.append((s['parameter'],op,side,mode,key,fork))
            for side in ['baseline','candidate']:
                for mode in ['stack-control-a5','stack-control-5a']:expected_order.append(('SLH-DSA-SHA2-128f',2,side,mode,1,0))
                expected_order.extend([(parameter,op,side,'stack-5a',1,0) for parameter,op in [('SLH-DSA-SHA2-128f',2),('SLH-DSA-SHA2-256s',1)]])
        identities=set();previous=datetime.datetime.fromisoformat(status['started_at'])
        for i,run in enumerate(status['executed']):
            job=run['job'];identity=tuple(job[k] for k in ['parameter','op','side','mode','key','fork'])
            require(identity not in identities and identity==expected_order[i],'duplicate/misordered process');identities.add(identity)
            start=datetime.datetime.fromisoformat(run['started_at']);finish=datetime.datetime.fromisoformat(run['finished_at']);require(previous<=start<=finish,'process intervals overlap');previous=finish
            spec=specs[job['parameter']];cmd=[ready['binaries'][job['side']],job['mode'],spec['native_parameter'],spec['input'],spec['corpus'],str(job['op']),str(job['key'])]
            require(run['returncode']==0 and run['command']==cmd and run['index']==i and status['jobs'][i]==job,'process mismatch')
            raw=d/f'{i:03d}.jsonl';require(sha(raw)==run['raw_sha256'] and sha(d/run['stderr_file'])==run['stderr_sha256'],'raw changed')
            rows=[json.loads(line) for line in raw.read_text().splitlines()];require([r['key'] for r in rows]==(list(range(1,11)) if job['key']==0 else [job['key']]),'missing/duplicate key')
            for r in rows:
                require(r['valid'] is True and r['input_unchanged'] is True and r['parameter']==spec['native_parameter'] and r['operation']==job['op'] and r['mode']==job['mode'],'row mismatch')
                expected='not-an-operation' if job['mode'].startswith('stack-control') else spec['records'][r['key']]['operation_sha256'][job['op']]
                require(r['output_sha256']==expected,'wrong result')
                fields=['wall_ns','cpu_ns','peak_rss_pre_bytes','peak_rss_post_bytes','observed_overwritten_thread_stack_bytes','allocations','allocated_requested_bytes','peak_tracked_live_bytes','retained_at_return_bytes','net_after_cleanup_bytes','frees']
                require(all(type(r[f]) is int and r[f]>=0 for f in fields),'invalid raw numeric counter')
                if job['mode']=='timing':require(r['wall_ns']>0 and r['cpu_ns']>0,'invalid clock')
                if job['mode']=='allocation':require(r['allocations']==r['frees'] and r['net_after_cleanup_bytes']==0 and r['retained_at_return_bytes']<=r['peak_tracked_live_bytes']<=r['allocated_requested_bytes'],'allocation lifecycle failed')
                if job['mode']=='rss':require(r['peak_rss_post_bytes']>=r['peak_rss_pre_bytes']>0,'bad RSS')
                if job['mode'].startswith('stack-'):require(0<r['observed_overwritten_thread_stack_bytes']<16*1024*1024,'bad painted stack')
            all_rows[identity]=rows;runs+=1;rows_count+=len(rows)
        require(previous<=datetime.datetime.fromisoformat(status['finished_at']),'wrong completion interval')
    expected={(s['parameter'],op) for s in specs.values() if s['baseline_timing'] for op in OPS}
    require({(c['parameter'],c['operation']) for c in summary['baseline_timings']}==expected and len(summary['baseline_timings'])==len(expected),'timing coverage')
    for cell in summary['baseline_timings']:
        rows=[r for k,v in all_rows.items() if k[0]==cell['parameter'] and OPS[k[1]]==cell['operation'] and k[3]=='timing' for r in v]
        require(len(rows)==30 and cell['candidate_wall_ns'] is None,'timing sample count/candidate')
        for field in ['wall_ns','cpu_ns']:equal(cell[field],statistics.mean(r[field] for r in rows))
    expected={(s['parameter'],op) for s in specs.values() if s['paired_resource'] for op in OPS}
    require({(c['parameter'],c['operation']) for c in summary['resource_records']}==expected and len(summary['resource_records'])==len(expected),'resource coverage')
    for cell in summary['resource_records']:
        require(cell['wall_ns'] is None and cell['cpu_ns'] is None,'unmeasured times not null')
        for field,m in cell['metrics'].items():
            mode='rss' if field.startswith('peak_rss') else 'stack-a5' if field=='observed_overwritten_thread_stack_bytes' else 'allocation'
            sides=[]
            for side in ['baseline','candidate']:
                rows=[all_rows[(cell['parameter'],OPS.index(cell['operation']),side,mode,key,key-1)][0] for key in range(1,5)]
                values=[r['peak_rss_post_bytes']-r['peak_rss_pre_bytes'] if field=='peak_rss_new_high_water_bytes' else r[field] for r in rows]
                require(m[side+'_observations']==values,'observations mismatch');sides.append(values)
            fn=statistics.mean if mode=='allocation' else statistics.median;a,b=map(fn,sides)
            equal(m['baseline'],a);equal(m['candidate'],b);equal(m['change_percent'],pct(a,b))
            require(len(m['paired_changes_percent'])==4,'missing paired percentages')
            for actual,x,y in zip(m['paired_changes_percent'],*sides):equal(actual,pct(x,y))
    mutations=0
    for actual,expected in [(float('inf'),1),(1,2),(0,None)]:
        try:equal(actual,expected)
        except ValueError:mutations+=1
    require(mutations==3,'numeric gate did not fail closed')
    report=dict(complete=True,provider=args.provider,mode='saved-evidence plus local-builds' if args.local_builds else 'saved-evidence',processes=runs,raw_rows=rows_count,baseline_cells=len(summary['baseline_timings']),resource_cells=len(summary['resource_records']),numeric_mutations_rejected=mutations,summary_sha256=sha(base/'summary.json'),checker_sha256=sha(__file__),inventory_sha256=sha(base/'artifact-inventory.json'),saved_artifacts_verified=saved_checks,local_original_artifacts_verified=len(entries) if args.local_builds else None,local_verification_unavailable=[] if args.local_builds else unavailable,scope='Committed source/configuration/fixture hashes; complete raw process identities/results; independent means, medians and all percentages. Compiled binaries verified only with --local-builds; historical command provenance is not a fresh build or execution.')
    args.out.write_text(json.dumps(report,indent=2)+'\n');print(args.out)
if __name__=='__main__':main()
