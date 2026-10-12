#!/usr/bin/env python3
"""Recompute paired allocation deltas from immutable process stdout."""
import hashlib,json,statistics,sys
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('Run without Python optimization')
p=Path(sys.argv[1]);ex=json.loads((p/'execution.json').read_text());m=json.loads((p/'manifest.json').read_text());plan=json.loads((p/'plan.json').read_text())
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
assert ex['completed_at'] and ex['all_outputs_match'] is True and ex['manifest_sha256']==sha(p/'manifest.json')
assert len(plan)==len(ex['runs'])==42
assert m['environment']['GOGC']=='off' and m['environment']['GOMEMLIMIT']=='off'
root=Path(__file__).resolve().parents[3]
for name,digest in m['inputs'].items():assert sha(root/name)==digest
assert sha(Path(m['corpus']))==m['corpus_sha256']
for v in m['variants'].values():
 assert sha(Path(v['binary']))==v['binary_sha256']
 assert {str(f.relative_to(v['path'])):sha(f) for f in Path(v['path']).rglob('*') if f.is_file() and f.suffix in ('.go','.s','.c','.h','.mod','.sum')}==v['source']
rows={}
for i,(entry,r) in enumerate(zip(plan,ex['runs'])):
 assert [r['round'],r['parameter'],r['variant']]==entry and r['index']==i and r['exit_code']==0
 assert r['sha256']==sha(p/r['raw'])
 d=json.loads((p/r['raw']).read_text());assert d['param']==r['parameter'] and len(d['rows'])==3
 for row in d['rows']:
  assert row['valid'] is True and row['tamper_rejected'] is True and row['inputs_preserved'] is True
  for a in row['allocation'].values():
   assert a['collections_during_call']==0 and all(type(a[k]) is int and a[k]>0 for k in ('allocated_bytes','allocated_objects'))
  rows[r['round'],r['parameter'],r['variant'],row['index']]=row
cells=[]
for param in sorted({r['parameter'] for r in ex['runs']}):
 for op in ('keygen','sign','verify'):
  pairs=[]
  for rnd in range(3):
   for idx in range(3):
    b=rows[rnd,param,'baseline',idx];c=rows[rnd,param,'candidate',idx]
    assert {k:v for k,v in b.items() if k!='allocation'}=={k:v for k,v in c.items() if k!='allocation'}
    pairs.append({'round':rnd,'index':idx,'baseline':b['allocation'][op],'candidate':c['allocation'][op]})
  cell={'parameter':param,'operation':op,'pairs':pairs}
  for metric in ('allocated_bytes','allocated_objects'):
   b=[x['baseline'][metric] for x in pairs];c=[x['candidate'][metric] for x in pairs];delta=[y-x for x,y in zip(b,c)]
   cell[metric]={'baseline_mean':statistics.mean(b),'candidate_mean':statistics.mean(c),'baseline_range':[min(b),max(b)],'candidate_range':[min(c),max(c)],'delta_range':[min(delta),max(delta)],'delta_median':statistics.median(delta),'candidate_over_baseline_total':sum(c)/sum(b),'increased_pairs':sum(d>0 for d in delta)}
  cells.append(cell)
print(json.dumps({'schema':'circl-resource-review-v1','execution_sha256':sha(p/'execution.json'),'processes':42,'checked_operations':378,'paired_operations':189,'all_raw_outputs_match':True,'no_gc_during_operations':True,'cells':cells},indent=2))
