#!/usr/bin/env python3
"""Recompute constructor and post-GC descriptive diagnostics from raw stdout."""
import hashlib,json,statistics,sys
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('Run without Python optimization')
p=Path(sys.argv[1]);sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def checked(sub,mode,n):
 d=p/sub;ex=json.loads((d/'execution.json').read_text());m=json.loads((d/'manifest.json').read_text());plan=json.loads((d/'plan.json').read_text())
 assert ex['completed_at'] and ex['all_checks_passed'] is True and ex['manifest_sha256']==sha(d/'manifest.json')
 assert ex['python_optimize']==0 and ex['node_options']=='' and ex['mode']==mode
 root=Path(__file__).resolve().parents[3]
 for name,digest in m['inputs'].items():assert sha(root/name)==digest
 assert sha(Path(m['node']))==m['node_sha256'] and sha(Path(m['fixture']))==m['fixture_sha256']
 for v in m['variants'].values():assert {str(f.relative_to(v['path'])):sha(f) for f in Path(v['path']).rglob('*') if f.is_file()}==v['tree']
 assert len(ex['runs'])==len(plan)==n
 rows=[]
 for i,(cell,r) in enumerate(zip(plan,ex['runs'])):
  assert {k:r[k] for k in cell}==cell and r['index']==i and r['exit_code']==0 and r['sha256']==sha(d/r['raw'])
  a=json.loads((d/r['raw']).read_text());assert a['parameter']==cell['parameter'] and a['mode']==mode and a['node']==m['node_version']
  rows.append((r,a))
 return ex,rows
ex,rows=checked('constructors','constructors',6);constructors=[]
for par in (44,65,87):
 data={r['variant']:a for r,a in rows if r['parameter']==par};assert set(data)=={'baseline','candidate'}
 for op in ['keygen','getPublicKey','sign','verify','invalidLength']:
  vals={v:[x for x in a['rows'] if x['operation']==op] for v,a in data.items()}
  assert all([x['index'] for x in val]==list(range(12)) for val in vals.values())
  pairs=[]
  for a,b in zip(vals['baseline'],vals['candidate']):
   assert a['output_sha256']==b['output_sha256']
   for x in [a,b]:assert x['constructors']==x['numeric_length_constructors'] and x['view_constructors']==x['view_bytes']==0 and x['requested_bytes']==1024*x['constructors']
   pairs.append({'index':a['index'],'baseline_count':a['constructors'],'candidate_count':b['constructors'],'payload_bytes_saved':a['requested_bytes']-b['requested_bytes']})
  constructors.append({'parameter':par,'operation':op,'pairs':pairs,'bytes_saved_range':[min(x['payload_bytes_saved'] for x in pairs),max(x['payload_bytes_saved'] for x in pairs)]})
re,rows=checked('post-gc','retained',96);cells=[]
assert len({(r['round'],r['parameter'],r['operation'],r['variant']) for r,a in rows})==96
for par in (44,65,87):
 for op in ['keygen','getPublicKey','sign','verify']:
  selected=[(r,a) for r,a in rows if r['parameter']==par and r['operation']==op]
  assert len(selected)==8
  pairs=[]
  for rnd in range(4):
   pair=[(r,a) for r,a in selected if r['round']==rnd];assert len(pair)==2 and {r['variant'] for r,a in pair}=={'baseline','candidate'}
   pairs.append({'round':rnd,'order':[r['variant'] for r,a in pair]})
  assert sum(x['order']==['baseline','candidate'] for x in pairs)==2
  byv={}
  for v in ['baseline','candidate']:
   records=[a for r,a in selected if r['variant']==v]
   for a in records:
    assert a['checked']==288 and [e['calls'] for e in a['epochs']]==[0,96,192,288] and a['gc_events']['forced']>=8
    assert all(type(n) is int and n>0 for e in a['epochs'] for n in e['memory'].values())
   metrics={}
   for metric in ['heapUsed','heapTotal','external','arrayBuffers']:
    initial=[a['epochs'][0]['memory'][metric] for a in records];last=[a['epochs'][-1]['memory'][metric] for a in records]
    deltas=[b-a for a,b in zip(initial,last)]
    metrics[metric]={'initial_range':[min(initial),max(initial)],'final_range':[min(last),max(last)],'final_median':statistics.median(last),'delta_each_fork':deltas,'delta_range':[min(deltas),max(deltas)]}
   byv[v]={'memory':metrics,'automatic_gc_each_fork':[a['gc_events']['automatic'] for a in records],'epochs_each_fork':[a['epochs'] for a in records]}
  cells.append({'parameter':par,'operation':op,'order':pairs,'variants':byv})
print(json.dumps({'schema':'noble-resource-review-v1','constructor_execution_sha256':sha(p/'constructors/execution.json'),'post_gc_execution_sha256':sha(p/'post-gc/execution.json'),'constructor_checks':360,'post_gc_processes':96,'post_gc_measured_checks':27648,'metric_limit':'logical numeric-length polynomial payload and post-GC process diagnostics only; not total JS allocation, latency, RSS, leaks or peak memory','constructors':constructors,'post_gc':cells},indent=2))
