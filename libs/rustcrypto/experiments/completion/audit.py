#!/usr/bin/env python3
"""Independently recompute saved completion summaries from preserved raw records."""
import hashlib,json,math,re,statistics,sys
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('run without -O')
ROOT=Path(__file__).resolve().parents[4]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def close(a,b):assert math.isclose(a,b,rel_tol=1e-12,abs_tol=1e-9),(a,b)
def main():
 results={k:json.loads((ROOT/f'results/{k}/completion/result.json').read_text())for k in ['rustcrypto','bouncycastle']};counts={}
 for library,m in results.items():
  assert m['raw_hashes']=={f:sha(ROOT/f)for f in m['raw_hashes']}
  assert sha(ROOT/f'results/{library}/completion/prepared.json')==m['manifest_sha256']
  count=0
  for run in m['runs']:
   stem=ROOT/run['raw_stem'];raw=[json.loads(s)for s in Path(str(stem)+'.stdout.txt').read_text().splitlines()];status=json.loads(Path(str(stem)+'.status.json').read_text());command=json.loads(Path(str(stem)+'.command.json').read_text());assert status['exit_code']==0 and command['started_at']<=status['finished_at'];rss=re.findall(r'^\s*(\d+)\s+maximum resident set size\s*$',Path(str(stem)+'.stderr.txt').read_text(),re.M);assert len(rss)==1
   if library=='rustcrypto':
    assert [r for r in raw if r['phase']=='measured']==run['rows'];assert len(raw)==12 and len(run['rows'])==10 and int(rss[0])==run['rss_bytes'];count+=30
   else:
    assert [r for r in raw if r['type']=='sample']==run['samples'];assert [r for r in raw if r['type']=='batch']==run['batches'];assert int(rss[0])==run['max_rss_bytes'];assert all(r['checked']and r['input_integrity']for r in run['samples']);count+=len(run['samples'])
  if library=='rustcrypto':
   for r in m['runs']:
    assert all(set(x['metrics'])=={'keygen','sign','verify'}for x in r['rows'])
   for row in m['allocation']:
    values=[x['metrics'][row['operation']]for r in m['runs']if r['mode']=='accounting'and r['parameter']==row['parameter']and r['variant']==row['variant']for x in r['rows']]
    assert values==row['all_samples']
    assert row['mean']=={k:statistics.mean(x[k]for x in values)for k in values[0]}
   for parameter in ['ML-DSA-44','ML-DSA-65','ML-DSA-87']:
    selected=[r for r in m['runs']if r['parameter']==parameter and r['mode']=='normal'];assert [r['variant']for r in selected]==['baseline','candidate','candidate','baseline','baseline','candidate','candidate','baseline']
  for row in m['baseline_timings']:
   if library=='rustcrypto':values=[r['metrics'][row['operation']]['wall_ns']for run in m['runs']if run['mode']=='normal'and run['variant']=='baseline'and run['parameter']==row['parameter']for r in run['rows']]
   else:
    p=row['parameter'];internal=('ml_dsa_'+p.split('-')[-1])if p.startswith('ML')else('falcon_'+p.split('-')[-1]);values=[r['wall_ns']for run in m['runs']if run['job']['mode']=='timing'and run['job']['parameter']==internal for r in run['samples']if r['operation']==row['operation']]
   close(statistics.mean(values),row['wall_ns'])
  for row in m['paired_resources']:
   if library=='rustcrypto':
    assert row['original_samples']==[r['rss_bytes']for r in m['runs']if r['mode']=='normal'and r['parameter']==row['parameter']and r['variant']=='baseline'];assert row['changed_samples']==[r['rss_bytes']for r in m['runs']if r['mode']=='normal'and r['parameter']==row['parameter']and r['variant']=='candidate'];close(row['original_median'],statistics.median(row['original_samples']));close(row['changed_median'],statistics.median(row['changed_samples']));close(row['change_percent'],100*(row['changed_median']/row['original_median']-1));assert len(row['original_samples'])==len(row['changed_samples'])==4
   else:
    pp=row['parameter'];internal=('ml_dsa_'+pp.split('-')[-1])if pp.startswith('ML')else pp.split('-')[-2].lower()+'_'+pp.split('-')[-1];cell=[r for r in m['runs']if r['job']['experiment']==row['patch']and r['job']['parameter']==internal and r['job']['operation']==row['operation']];assert [r['job']['side']for r in cell]==['baseline',row['patch'],row['patch'],'baseline']
    for field,v in row['metrics'].items():
     for label,side in [('original_samples','baseline'),('changed_samples',row['patch'])]:
      values=[]
      for r in cell:
       if r['job']['side']!=side:continue
       if field=='max_rss_bytes':values.append(r[field])
       elif field.endswith('_per_op'):values.append(statistics.mean(s[field.replace('_per_op','')]for s in r['samples']))
       else:values.append(r['batches'][0][field])
      assert values==v[label],(row['parameter'],row['operation'],field,label)
     assert len(v['original_samples'])==len(v['changed_samples'])==2;close(v['original'],statistics.mean(v['original_samples']));close(v['changed'],statistics.mean(v['changed_samples']));assert v['change_percent']is None if not v['original']else math.isclose(v['change_percent'],100*(v['changed']/v['original']-1),rel_tol=1e-12,abs_tol=1e-9)
  counts[library]={'processes':len(m['runs']),'measured_operation_rows':count,'baseline_cells':len(m['baseline_timings']),'paired_resource_cells':len(m['paired_resources'])}
 assert results['rustcrypto']['finished_at']<results['bouncycastle']['started_at']
 assert counts['rustcrypto']=={'processes':54,'measured_operation_rows':1620,'baseline_cells':45,'paired_resource_cells':3}
 assert counts['bouncycastle']=={'processes':113,'measured_operation_rows':10950,'baseline_cells':15,'paired_resource_cells':27}
 output={'schema':'rust-bc-completion-independent-v1','pass':True,'counts':counts,'result_sha256':{k:sha(ROOT/f'results/{k}/completion/result.json')for k in results},'checker_sha256':sha(Path(__file__))}
 path=ROOT/'results/rustcrypto/completion/independent-check.json';path.write_text(json.dumps(output,indent=2)+'\n');print(json.dumps(output,indent=2))
if __name__=='__main__':main()
