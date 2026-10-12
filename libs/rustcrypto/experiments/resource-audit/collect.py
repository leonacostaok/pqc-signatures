#!/usr/bin/env python3
"""Validate sealed inputs and collect untimed allocation accounting, without exclusions."""
import argparse,json,sys
from pathlib import Path
import prepare as p
assert not sys.flags.optimize
def verify(m):
 for file,expected in m['files'].items():assert p.sha(file)==expected,file
 for side,path in m['sources'].items():assert p.tree(path)==m['source_hashes'][side]
 for mode,data in m['modes'].items():
  assert p.sha(data['binary'])==data['binary_sha256']
  assert p.sha(data['assembly'])==data['assembly_sha256']
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--manifest',required=True);parser.add_argument('--out',required=True);args=parser.parse_args()
 manifest=Path(args.manifest).resolve();m=json.loads(manifest.read_text());verify(m)
 assert m['base']==p.BASE and m['head']==p.HEAD and set(m['modes'])==set(p.MODES)
 output=Path(args.out);assert not output.exists();raw=Path(str(output)+'.raw');raw.mkdir(parents=True,exist_ok=False)
 result={'schema':'rust-resource-accounting-v1','manifest':str(manifest),'manifest_sha256':p.sha(manifest),'collector_sha256':p.sha(__file__),'modes':{},
  'scope':'Untimed single-thread global System-allocator requested-byte accounting. Inputs, caller-owned verifying-key clone, serialization, exact comparisons and tamper checks excluded. Results retained until separately observed drop. Not RSS or stack high water.'}
 for mode,data in m['modes'].items():
  rows=[json.loads(line) for line in p.run([data['binary'],'account'],raw,mode).splitlines()];assert len(rows)==12
  assert {(r['baseline']['parameter'],r['baseline']['case']) for r in rows}=={(param,i) for param in ['ML-DSA-44','ML-DSA-65','ML-DSA-87'] for i in range(4)}
  for row,check in zip(rows,data['checks']):
   assert row['exact_cross_variant']
   for side in ['baseline','candidate']:
    current=row[side];expected=check[side]
    for name in ['parameter','case','sizes','encoded_sizes','output_sha256','exact_output_checked','tamper_rejected']:assert current[name]==expected[name]
    metrics=current['metrics'];assert all(v['reallocations']==0 for v in metrics.values())
    assert metrics['keygen']['live_delta_bytes']+metrics['key_drop']['live_delta_bytes']==0
    assert metrics['fresh_key_sign']['live_delta_bytes']+metrics['fresh_key_drop']['live_delta_bytes']==0
    for op in ['keygen','fresh_key_sign','sign','verify']:
     v=metrics[op];assert v['live_delta_bytes']>=0 and v['peak_live_above_entry_bytes']>=v['live_delta_bytes']
     assert v['allocated_bytes']-v['freed_bytes']==v['live_delta_bytes']
    if mode=='noalloc-zeroize':
     assert not current['seed_deallocation_observed']
     assert all(all(value==0 for value in v.values()) for v in metrics.values())
    else:
     assert current['seed_deallocation_observed']
     assert current['seed_zero_before_deallocation']==(mode!='default')
    for op in ['key_drop','fresh_key_drop']:
     assert metrics[op]['allocations']==0 and metrics[op]['allocated_bytes']==0
   assert row['baseline']['metrics']==row['candidate']['metrics'],'allocation regression/delta: retain raw and investigate'
  result['modes'][mode]=rows;verify(m)
 p.write(output,result);print(output)
if __name__=='__main__':main()
