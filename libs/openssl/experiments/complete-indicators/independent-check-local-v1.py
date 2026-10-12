#!/usr/bin/env python3
"""Independently recompute serialized C indicator results without collector imports."""
import argparse, hashlib, json, math, statistics
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
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--provider',choices=['liboqs','openssl'],required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    base=ROOT/'results'/args.provider/'complete-indicators';ready=json.loads((base/'ready.json').read_text());summary=json.loads((base/'summary.json').read_text())
    require(summary['complete'] is True and summary['library']==args.provider,'bad summary')
    require(summary['manifest_sha256']==sha(base/'ready.json'),'wrong manifest')
    for file,digest in ready['sha256'].items():require(sha(file)==digest,'changed source/build/input')
    specs={s['parameter']:s for s in ready['parameters']};all_rows={};runs=0;rows_count=0
    for phase,count in [('baseline-timing',99 if args.provider=='liboqs' else 72),('resources',440)]:
        d=base/phase;status=json.loads((d/'execution.json').read_text())
        require(status['complete'] is True and status['provider']==args.provider and status['phase']==phase,'wrong execution')
        require(len(status['executed'])==count and len(status['jobs'])==count,'missing jobs')
        require(summary['execution_sha256'][phase]==sha(d/'execution.json'),'execution changed')
        identities=set()
        for i,run in enumerate(status['executed']):
            job=run['job'];identity=tuple(job[k] for k in ['parameter','op','side','mode','key','fork'])
            require(identity not in identities,'duplicate process');identities.add(identity)
            spec=specs[job['parameter']];cmd=[ready['binaries'][job['side']],job['mode'],spec['native_parameter'],spec['input'],spec['corpus'],str(job['op']),str(job['key'])]
            require(run['returncode']==0 and run['command']==cmd and run['index']==i and status['jobs'][i]==job,'process mismatch')
            raw=d/f'{i:03d}.jsonl';require(sha(raw)==run['raw_sha256'] and sha(d/run['stderr_file'])==run['stderr_sha256'],'raw changed')
            rows=[json.loads(line) for line in raw.read_text().splitlines()];require([r['key'] for r in rows]==(list(range(1,11)) if job['key']==0 else [job['key']]),'missing/duplicate key')
            for r in rows:
                require(r['valid'] is True and r['input_unchanged'] is True and r['parameter']==spec['native_parameter'] and r['operation']==job['op'] and r['mode']==job['mode'],'row mismatch')
                expected='not-an-operation' if job['mode'].startswith('stack-control') else spec['records'][r['key']]['operation_sha256'][job['op']]
                require(r['output_sha256']==expected,'wrong result')
            all_rows[identity]=rows;runs+=1;rows_count+=len(rows)
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
    report=dict(complete=True,provider=args.provider,processes=runs,raw_rows=rows_count,baseline_cells=len(summary['baseline_timings']),resource_cells=len(summary['resource_records']),numeric_mutations_rejected=mutations,summary_sha256=sha(base/'summary.json'),checker_sha256=sha(__file__),scope='source/build/input hashes; complete raw process identities/results; independent means, medians and all percentages')
    args.out.write_text(json.dumps(report,indent=2)+'\n');print(args.out)
if __name__=='__main__':main()
