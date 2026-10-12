#!/usr/bin/env python3
import argparse,json,re,statistics,sys
from pathlib import Path
import prepare as p
if sys.flags.optimize:raise RuntimeError('run without -O')
def verify(m):
 assert m['schema']=='rust-completion-prepared-v1'
 assert m['files']=={f:p.sha(f)for f in m['files']}
 assert m['binary_hashes']=={s:p.sha(f)for s,f in m['binaries'].items()}
 assert m['source_hashes']=={s:p.tree(f)for s,f in m['sources'].items()}
def main():
 a=argparse.ArgumentParser();a.add_argument('--manifest',required=True);a.add_argument('--out',required=True);a=a.parse_args();m=json.loads(Path(a.manifest).read_text());verify(m);assert sys.platform=='darwin'
 out=Path(a.out).resolve();assert not out.exists();raw=Path(str(out)+'.raw');raw.mkdir(parents=True,exist_ok=False);runs=[];seal={'manifest':str(Path(a.manifest).resolve()),'manifest_sha256':p.sha(a.manifest),'collector_sha256':p.sha(__file__),'started_at':p.stamp()};p.write(raw/'plan.json',seal)
 for mode in ['normal','accounting']:
  for param in m['parameters']:
   for fork in range(4 if mode=='normal'and param.startswith('ML')else 1):
    sides=(['baseline','candidate']if fork%2==0 else['candidate','baseline'])if param.startswith('ML')else['baseline']
    for side in sides:
     stem=f'{mode}-{param}-{side}-{fork}';print(stem,flush=True);text=p.run(['/usr/bin/time','-l',m['binaries'][mode],'collect',param,side],raw,stem);rows=[json.loads(x)for x in text.splitlines()];assert len(rows)==12 and list(map(p.comparable,rows))==m['checks'][param+'/'+side];assert all(r['accounting']==(mode=='accounting')for r in rows)
     measured=[r for r in rows if r['phase']=='measured'];assert len(measured)==10
     for r in measured:
      for op,v in r['metrics'].items():
       if mode=='normal':assert v['wall_ns']>0 and v['cpu_ns']>=0
       else:assert all(isinstance(x,int)and x>=0 for x in v.values())and v['reallocations']==0
     rss=re.findall(r'^\s*(\d+)\s+maximum resident set size\s*$',(raw/(stem+'.stderr.txt')).read_text(),re.M);assert len(rss)==1
     runs.append({'mode':mode,'parameter':param,'variant':side,'fork':fork,'rss_bytes':int(rss[0]),'raw_stem':str((raw/stem).relative_to(p.ROOT)),'rows':measured})
 verify(m);baseline=[];paired=[];resources=[]
 for param in m['parameters']:
  nr=[r for r in runs if r['mode']=='normal'and r['parameter']==param];ar=[r for r in runs if r['mode']=='accounting'and r['parameter']==param]
  for op in ['keygen','sign','verify']:
   original=[v['metrics'][op]['wall_ns']for r in nr if r['variant']=='baseline'for v in r['rows']]
   baseline.append({'library':'rustcrypto','parameter':param,'operation':op,'wall_ns':statistics.mean(original),'statistic':'arithmetic mean over 10 keys per process; ML four processes, SLH one','protocol':'default+zeroize; two disjoint warmup keys; output encoding and public-key extraction excluded','source':str(out.relative_to(p.ROOT))})
   for side in ['baseline','candidate']if param.startswith('ML')else['baseline']:
    cells=[v['metrics'][op]for r in ar if r['variant']==side for v in r['rows']];resources.append({'parameter':param,'operation':op,'variant':side,'mean':{k:statistics.mean(x[k]for x in cells)for k in cells[0]},'all_samples':cells})
   if param.startswith('ML'):
    arows=next(r['rows']for r in ar if r['variant']=='baseline');brows=next(r['rows']for r in ar if r['variant']=='candidate');assert [r['metrics'][op]for r in arows]==[r['metrics'][op]for r in brows]
  if param.startswith('ML'):
   ab=[r['rss_bytes']for r in nr if r['variant']=='baseline'];bb=[r['rss_bytes']for r in nr if r['variant']=='candidate'];paired.append({'parameter':param,'metric':'whole_process_max_rss_bytes','original_samples':ab,'changed_samples':bb,'original_median':statistics.median(ab),'changed_median':statistics.median(bb),'change_percent':100*(statistics.median(bb)/statistics.median(ab)-1),'scope':'whole three-operation process including startup, warmup, checks and teardown; not operation peak'})
 result={'schema':'rust-completion-v1',**seal,'finished_at':p.stamp(),'baseline_timings':baseline,'paired_resources':paired,'allocation':resources,'runs':runs,'unsupported':[{'library':'rustcrypto','parameter':f'Falcon-{n}','operations':['keygen','sign','verify'],'reason':'Pinned RustCrypto/signatures tree has no Falcon implementation; not measured'}for n in [512,1024]],'raw_hashes':{str(f.relative_to(p.ROOT)):p.sha(f)for f in sorted(raw.iterdir())if f.is_file()}};p.write(out,result);print(out)
if __name__=='__main__':main()
