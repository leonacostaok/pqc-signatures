#!/usr/bin/env python3
"""Recompute the frozen confirmation decision from a checked raw-result summary."""
import argparse,hashlib,json,os,sys
from pathlib import Path
if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
    raise RuntimeError('Python optimization is forbidden, including PYTHONOPTIMIZE')
p=argparse.ArgumentParser();p.add_argument('--plan',required=True);p.add_argument('--audit',required=True);p.add_argument('--out',required=True);a=p.parse_args()
plan=json.loads(Path(a.plan).read_text());audit=json.loads(Path(a.audit).read_text())
assert plan['schema']=='bc-ntt-java17-plan-v1'and audit['passed']and audit['processes_checked']==216 and audit['output_rows_checked']==27648
assert audit['plan_sha256']==hashlib.sha256(Path(a.plan).read_bytes()).hexdigest()
result={v:{'replicated_cells':[],'blocking_regressions':[],'all_cells':[]}for v in plan['variants'][1:]}
for row in audit['summary']:
    v=row['variant'];cell=row['parameter']+'/'+row['operation'];w=row['wall_ns'];c=row['cpu_ns'];allocation=row['allocated_bytes'];faster=sum(x>1 for x in w['round_original_over_changed']);qualifies=w['percent_change']<=-3 and c['percent_change']<=-3 and faster==4
    replicated=qualifies and cell in plan['screen_qualifying_cells'][v];blocked=w['percent_change']>3 and faster==0
    if replicated:result[v]['replicated_cells'].append(cell)
    if blocked:result[v]['blocking_regressions'].append(cell)
    result[v]['all_cells'].append({'cell':cell,'wall_percent':w['percent_change'],'cpu_percent':c['percent_change'],'allocation_percent':allocation['percent_change'],'faster_wall_rounds':faster,'qualifies_on_java17':qualifies,'replicates_screen':replicated,'blocking_regression':blocked,'wall_slower_observations':w['changed_larger_keys'],'wall_round_ratios':w['round_original_over_changed']})
for v,r in result.items():
    assert len(r['all_cells'])==9;r['supported_by_frozen_rule']=bool(r['replicated_cells'])and not r['blocking_regressions']
with Path(a.out).open('x')as f:json.dump({'rule':plan['confirmation_rule'],'result':result,'measurement_pooling':False},f,indent=2);f.write('\n')
print(json.dumps({v:{k:x for k,x in r.items()if k!='all_cells'}for v,r in result.items()},indent=2))
