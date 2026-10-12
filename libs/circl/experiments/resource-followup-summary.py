#!/usr/bin/env python3
"""Normalize unavailable last-GC observations without altering sealed collectors."""
import hashlib,json,statistics,subprocess,sys
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('Python optimization disables checks')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def change(a,b):return None if a is None or b is None or a==0 else 100*(b/a-1)
base,resource,out=map(Path,sys.argv[1:])
assert not out.exists()
original=out.with_name('counter-summary.json')
subprocess.run([sys.executable,str(HERE/'resource-followup/summarize.py'),str(base),str(resource),str(original)],check=True)
data=json.loads(original.read_text());execution=json.loads((resource/'execution.json').read_text())
lookup={(r['parameter'],r['operation'],r['settings'],r['round'],r['variant']):resource/r['raw'] for r in execution['runs']}
for cell in data['paired_resources']:
    metric=cell['metrics']['last_gc_live_heap_at_end'];availability={}
    for variant in ('baseline','candidate'):
        observations=metric[variant+'_rounds'];ok=[]
        for rnd in range(4):
            raw=json.loads(lookup[(cell['parameter'],cell['operation'],cell['settings'],rnd,variant)].read_text())
            assert len(raw['rows'])==1
            has_gc=raw['rows'][0]['memory']['end']['gc_cycles']>0;ok.append(has_gc)
            if not has_gc:observations[rnd]=None
        availability[variant]=ok
        metric[variant]=statistics.median(observations) if all(ok) else None
    a,b=metric['baseline_rounds'],metric['candidate_rounds']
    metric['delta_percent']=change(metric['baseline'],metric['candidate'])
    metric['round_delta_percent']=[change(x,y) for x,y in zip(a,b)]
    metric['candidate_increase_rounds']=sum(y>x for x,y in zip(a,b) if x is not None and y is not None)
    metric['available_rounds']=availability
    metric['availability_reason']='Null if no completed GC was observed since process startup; non-null is last-GC heap, possibly from warmup, not end-of-workload live heap. Aggregate requires all four observations.'
for row in data['baseline_timings']:row['source']=str(out.resolve().relative_to(ROOT))
data['provenance']['counter_summary_sha256']=sha(original)
data['provenance']['normalization_script_sha256']=sha(__file__)
with out.open('x') as f:json.dump(data,f,indent=2);f.write('\n')
print(out)
