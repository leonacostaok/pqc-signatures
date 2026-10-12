#!/usr/bin/env python3
import argparse,hashlib,json,os,re,statistics,sys
from pathlib import Path
import prepare as p
if sys.flags.optimize:raise RuntimeError('run without -O')
def packed(h):
 d=hashlib.sha256()
 for n,v in h.items():d.update(n.encode()+b'\0'+bytes.fromhex(v))
 return d.hexdigest()
def verify(m):
 assert m['schema']=='bc-completion-prepared-v1'and m['jvm_args']==p.JVM
 assert m['files']=={f:p.sha(f)for f in m['files']}
 assert m['class_hashes']=={v:p.tree(f,'.class')for v,f in m['classes'].items()}
 assert m['source_hashes']=={v:p.tree(f,'.java')for v,f in m['source_paths'].items()}
 assert m['driver_hashes']==p.tree(m['driver'],'.class')and m['environment']=={k:os.environ.get(k,'')for k in m['environment']}
 old={k:json.loads(Path(v['path']).read_text())for k,v in m['old_manifests'].items()};assert all(p.sha(v['path'])==v['sha256']for v in m['old_manifests'].values())
 assert packed(m['class_hashes']['fors'])==old['fors']['provenance']['candidate_classes']
 assert packed(m['class_hashes']['wots'])==old['wots']['provenance']['classes']['candidate']and packed(m['source_hashes']['wots'])==old['wots']['provenance']['sources']['candidate']
 for v in ['matrix','gamma','combined']:assert m['class_hashes'][v]==old['sampling']['variants'][v]['binaries']and m['source_hashes'][v]==old['sampling']['variants'][v]['source']
def canon(param):return ('ML-DSA-'+param.split('_')[-1])if param.startswith('ml_dsa')else('Falcon-'+param.split('_')[-1])if param.startswith('falcon')else'SLH-DSA-'+param.split('_')[0].upper()+'-'+param.split('_')[1]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--manifest',required=True);ap.add_argument('--out',required=True);ap.add_argument('--check-only',action='store_true');a=ap.parse_args();m=json.loads(Path(a.manifest).read_text());verify(m)
 if a.check_only:print('provenance PASS');return
 assert sys.platform=='darwin';out=Path(a.out).resolve();assert not out.exists();raw=Path(str(out)+'.raw');raw.mkdir(parents=True,exist_ok=False)
 jobs=[{'experiment':'baseline','side':'baseline','mode':'timing','parameter':q,'operation':'all','warm':2 if q.startswith('falcon')else 100,'cycles':1,'fork':0}for q in p.ML+p.FALCON]
 for experiment,params,ops,warm,cycles in [('fors',p.SLH,['verify'],100,10),('combined',p.ML,['keygen','sign','verify'],100,10),('wots',['sha2_128f','shake_128f'],['keygen','sign','verify'],100,10)]:
  for q in params:
   for op in ops:
    for fork in range(2):
     for side in (['baseline',experiment]if fork==0 else[experiment,'baseline']):jobs.append({'experiment':experiment,'side':side,'mode':'resource','parameter':q,'operation':op,'warm':warm,'cycles':cycles,'fork':fork})
 seal={'manifest':str(Path(a.manifest).resolve()),'manifest_sha256':p.sha(a.manifest),'collector_sha256':p.sha(__file__),'started_at':p.stamp(),'jobs':jobs};p.write(raw/'plan.json',seal);runs=[]
 for i,j in enumerate(jobs):
  stem=f'{i:03d}-{j["experiment"]}-{j["side"]}-{j["parameter"]}-{j["operation"]}-{j["fork"]}';print(stem,flush=True);cmd=['/usr/bin/time','-l',*p.command(m,j['side'],j['mode'],j['parameter'],j['operation'],j['warm'],j['cycles'])];text=p.run(cmd,raw,stem);rows=[json.loads(x)for x in text.splitlines()];samples=[r for r in rows if r['type']=='sample'];batch=[r for r in rows if r['type']=='batch'];ops=['keygen','sign','verify']if j['operation']=='all'else[j['operation']];assert len(samples)==len(ops)*10*j['cycles']and len(batch)==len(ops)
  check=m['checks']['baseline-'+j['parameter']+('-all'if j['parameter']in p.ML+p.FALCON+['sha2_128f','shake_128f']else'-verify')];expected={(r['operation'],r['index']):r['output_sha256']for r in check}
  assert {(r['operation'],r['index'],r['cycle'])for r in samples}=={(o,k,c)for o in ops for k in range(2,12)for c in range(j['cycles'])}
  for r in samples:assert r['checked']and r['input_integrity']and r['output_sha256']==expected[r['operation'],r['index']]and r['variant']==j['side']and r['parameter']==j['parameter']and r['class_source']==m['classes'][j['side']]and r['wall_ns']>0 and r['thread_cpu_ns']>=0 and r['allocated_bytes']>=0
  for b in batch:
   x=[r for r in samples if r['operation']==b['operation']];assert b['wall_ns_sum']==sum(r['wall_ns']for r in x)and b['thread_cpu_ns_sum']==sum(r['thread_cpu_ns']for r in x)and b['allocated_bytes_sum']==sum(r['allocated_bytes']for r in x)and b['warmup_calls']==2*j['warm']and b['cycles']==j['cycles'];assert b['gc_count']>=0 and b['gc_time_ms']>=0
  rss=re.findall(r'^\s*(\d+)\s+maximum resident set size\s*$',(raw/(stem+'.stderr.txt')).read_text(),re.M);assert len(rss)==1;runs.append({'job':j,'max_rss_bytes':int(rss[0]),'raw_stem':str((raw/stem).relative_to(p.ROOT)),'samples':samples,'batches':batch})
 verify(m);baseline=[];paired=[]
 for r in runs:
  if r['job']['mode']=='timing':
   for op in ['keygen','sign','verify']:
    values=[x['wall_ns']for x in r['samples']if x['operation']==op];baseline.append({'library':'bouncycastle','parameter':canon(r['job']['parameter']),'operation':op,'wall_ns':statistics.mean(values),'statistic':'arithmetic mean, 10 distinct keys, one pass','protocol':'fresh operation objects and key decoding; keygen includes encoding; ML200 warmup calls/op, Falcon4 cap','source':str(out.relative_to(p.ROOT))})
 for experiment in ['fors','combined','wots']:
  cells={(r['job']['parameter'],r['job']['operation'])for r in runs if r['job']['experiment']==experiment}
  for q,op in sorted(cells):
   cell=[r for r in runs if r['job']['experiment']==experiment and r['job']['parameter']==q and r['job']['operation']==op];metrics={}
   for field in ['max_rss_bytes','heap_before_bytes','heap_after_bytes','heap_post_requested_gc_bytes','gc_count','gc_time_ms','allocated_bytes_per_op','wall_ns_per_op','thread_cpu_ns_per_op']:
    values={}
    for side in ['baseline',experiment]:
     selected=[r for r in cell if r['job']['side']==side];v=[]
     for r in selected:
      if field=='max_rss_bytes':v.append(r[field])
      elif field.endswith('_per_op'):v.append(statistics.mean(s[field.replace('_per_op','')]for s in r['samples']))
      else:v.append(r['batches'][0][field])
     values[side]=v
    a0=statistics.mean(values['baseline']);b0=statistics.mean(values[experiment]);metrics[field]={'original':a0,'changed':b0,'change_percent':100*(b0/a0-1)if a0 else None,'original_samples':values['baseline'],'changed_samples':values[experiment]}
   paired.append({'library':'bouncycastle','patch':experiment,'parameter':canon(q),'operation':op,'metrics':metrics,'scope':'process RSS; heap snapshots; GC of checked batch (includes checks); allocated bytes and clocks only operation; two AB/BA process pairs'})
 result={'schema':'bc-completion-v1',**seal,'finished_at':p.stamp(),'baseline_timings':baseline,'paired_resources':paired,'runs':runs,'raw_hashes':{str(f.relative_to(p.ROOT)):p.sha(f)for f in sorted(raw.iterdir())if f.is_file()}};p.write(out,result);print(out)
if __name__=='__main__':main()
