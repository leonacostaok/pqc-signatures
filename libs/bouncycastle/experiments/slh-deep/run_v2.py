#!/usr/bin/env python3
"""Explicit exclusive-window stage/whole-operation screen; immutable preparation required."""
import argparse, json, os, platform, statistics, sys
from pathlib import Path
import prepare as p
if sys.flags.optimize: raise RuntimeError('assertions required; do not use -O')
STAGES=['verify.decode','sign.prf_msg','hmsg','fors.indices','verify.fors_leaves','verify.fors_auth','verify.fors_compress','verify.fors','verify.wots_chains','verify.wots_compress','verify.wots','verify.xmss_auth','verify.hypertree','sign.fors','sign.wots','sign.xmss_auth','sign.hypertree','sign.serialize']
TOTALS=['keygen.total','sign.total','verify.total']

def process(rows,m,side,parameter,operation,fork,args):
 assert rows and all(r['variant']==side and r['parameter']==parameter and r['operation']==operation and r['fork']==fork and r['class_source']==m['classes'][side] and r['checked'] is True and r['warmup_calls']==2*args.warmup_cycles for r in rows)
 expected=m['checks']['baseline'][parameter] if operation in TOTALS else m['stage_checks']['baseline'][parameter]
 expected={r['case']:r['output_sha256'] for r in expected if r['operation']==operation and r['phase']=='measured'}
 assert all(r['case'] in [0,3,6,9] and r['output_sha256']==expected[r['case']] for r in rows)
 assert {r['round'] for r in rows}==set(range(args.rounds))
 assert len({(r['round'],r['cycle'],r['case']) for r in rows})==len(rows)
 metrics=[]
 for round in range(args.rounds):
  current=[r for r in rows if r['round']==round];cycles=sorted({r['cycle'] for r in current})
  assert cycles==list(range(len(cycles))) and len(current)==4*len(cycles)
  assert [(r['cycle'],r['case']) for r in current]==[(cycle,case) for cycle in cycles for case in [0,3,6,9]]
  for r in current:
   for key in ['wall_ns','cpu_ns','thread_cpu_ns','allocated_bytes']:assert type(r[key]) is int and r[key]>=0
   if args.mode=='bench':assert r['wall_ns']>0 and r['thread_cpu_ns']>=0 and r['allocated_bytes']==0
   else:assert r['allocated_bytes']>0 and r['wall_ns']==r['cpu_ns']==r['thread_cpu_ns']==0
  if args.mode=='bench':assert sum(r['wall_ns'] for r in current)>=args.budget_ms*1000000
  else:assert len(cycles)==1
  metrics.append({'round':round,'iterations':len(current),**{key:sum(r[key] for r in current)/len(current) for key in ['wall_ns','cpu_ns','thread_cpu_ns','allocated_bytes']}})
 return {'rows':rows,'rounds':metrics,'medians':{key:statistics.median(r[key] for r in metrics) for key in ['wall_ns','cpu_ns','thread_cpu_ns','allocated_bytes']}}

def main(args):
 manifest=Path(args.manifest).resolve();m=json.loads(manifest.read_text())
 assert m['schema']=='bc-slh-deep-prepared-v1' and m['upstream_commit']==p.PIN and m['variants']==p.VARIANTS and m['parameters'] and set(m['parameters'])<=set(p.PARAMETERS)
 assert m['jvm_args']==p.JVM and m['environment']=={k:os.environ.get(k,'') for k in p.ENV}
 assert m['provenance']==p.provenance(m)
 assert args.forks>=2 and args.forks<=20 and args.forks%2==0 and 0<=args.start<1000000
 assert 1<=args.rounds<=20 and 1<=args.budget_ms<=10000 and 1<=args.warmup_cycles<=1000
 parameters=args.parameters.split(',');operations=args.operations.split(',')
 assert len(set(parameters))==len(parameters) and set(parameters)<=set(m['parameters'])
 assert len(set(operations))==len(operations) and set(operations)<=set(STAGES+TOTALS)
 output=Path(args.out).resolve();assert not output.exists();raw=Path(args.resume).resolve() if args.resume else Path(str(output)+'.raw')
 if args.resume:assert raw.is_dir()
 else:raw.mkdir(parents=True,exist_ok=False)
 collector_sha=p.sha(__file__)
 lock=p.BUILD/'.timing-lock';lock.mkdir()
 plan={'schema':'bc-slh-deep-plan-v1','prepared_manifest':str(manifest),'manifest_sha256':p.sha(manifest),'prepared':m,'mode':args.mode,
  'parameters':parameters,'operations':operations,'forks':args.forks,'start':args.start,'rounds':args.rounds,'budget_ms':args.budget_ms,
  'warmup_cycles':args.warmup_cycles,'warmup_calls':2*args.warmup_cycles,'measured_cases':[0,3,6,9],'corpus_policy':'four distinct measured keys reused in complete cycles; two distinct warmup keys disjoint from measured keys',
  'stage_scope':'precomputed inputs and operation-local initialized engine; nested stages overlap; do not sum',
  'total_scope':'fresh public generator/signer/verifier per call; key decoding outside; every output/input/tamper and exact entropy check after both clock endpoints',
  'jit_trace':args.jit_trace,'python':sys.version,'python_optimize':sys.flags.optimize,'host':platform.platform(),'arch':platform.machine(),
  'collector':str(Path(__file__).resolve()),'collector_sha256':collector_sha,'started_at':p.stamp(),'exclusions':'none; preserve all completed samples, failures, losses and controls; no normalization'}
 if args.resume:
  original=json.loads((raw/'plan.json').read_text())
  for key in ['manifest_sha256','prepared','mode','parameters','operations','forks','start','rounds','budget_ms','warmup_cycles','jit_trace']:assert original[key]==plan[key],key
  plan['original_plan']=original;plan['recovery']='Thread CPU may quantize to zero for short operations. Revalidate/reuse every completed process; continue missing processes. No samples discarded.'
  p.write(raw/'resume-plan.json',plan)
 else:p.write(raw/'plan.json',plan)
 pairs=[]
 try:
  for fork in range(args.start,args.start+args.forks):
   for pi,parameter in enumerate(parameters):
    for oi,operation in enumerate(operations):
     order=['baseline','candidate'] if (fork+pi+oi)%2==0 else ['candidate','baseline']
     print(f'{args.mode} {fork} {parameter} {operation} {order}',flush=True)
     pair={'fork':fork,'parameter':parameter,'operation':operation,'order':order}
     for side in order:
      stem=f'{fork:04d}-{parameter}-{operation}-{side}'
      command=p.command(m,side,args.mode,parameter,operation,fork,args.rounds,args.budget_ms,args.warmup_cycles)
      if args.jit_trace:command.insert(1,'-Xlog:jit+compilation=debug:file='+str(raw/(stem+'.jit.log'))+':uptimemillis,level,tags')
      status=raw/(stem+'.status.json')
      if args.resume and status.exists():
       assert json.loads(status.read_text())['exit_code']==0
       assert json.loads((raw/(stem+'.command.json')).read_text())['command']==list(map(str,command))
       stdout=(raw/(stem+'.stdout.txt')).read_text()
      else:stdout=p.persist(command,raw,stem)
      rows=[json.loads(line) for line in stdout.splitlines()]
      pair[side]=process(rows,m,side,parameter,operation,fork,args)
      metrics=raw/(stem+'.metrics.json')
      if args.resume and metrics.exists():assert json.loads(metrics.read_text())==pair[side]
      else:p.write(metrics,pair[side])
     for key in ['wall_ns','cpu_ns','thread_cpu_ns','allocated_bytes']:
      a=pair['baseline']['medians'][key];b=pair['candidate']['medians'][key]
      pair[key+'_ratio']=a/b if b else None
     pairs.append(pair);pairfile=raw/f'{fork:04d}-{parameter}-{operation}.pair.json'
     if args.resume and pairfile.exists():assert json.loads(pairfile.read_text())==pair
     else:p.write(pairfile,pair)
     assert m['provenance']==p.provenance(m) and p.sha(__file__)==collector_sha,'sealed inputs changed'
  summary=[]
  for parameter in parameters:
   for operation in operations:
    selected=[r for r in pairs if (r['parameter'],r['operation'])==(parameter,operation)]
    assert len(selected)==args.forks and sum(r['order'][0]=='baseline' for r in selected)==args.forks//2
    row={'parameter':parameter,'operation':operation,'forks':args.forks}
    for key in ['wall_ns','cpu_ns','thread_cpu_ns','allocated_bytes']:
     ratios=[r[key+'_ratio'] for r in selected]
     row[key]={'baseline':statistics.median(r['baseline']['medians'][key] for r in selected),
      'candidate':statistics.median(r['candidate']['medians'][key] for r in selected),'ratios':ratios,
      'median_ratio':statistics.median(ratios) if all(v is not None for v in ratios) else None,
      'min_ratio':min(ratios) if all(v is not None for v in ratios) else None,'max_ratio':max(ratios) if all(v is not None for v in ratios) else None,
      'losses':sum(v<1 for v in ratios if v is not None)}
    summary.append(row)
  p.write(output,{'schema':'bc-slh-deep-results-v1','plan':plan,'finished_at':p.stamp(),
   'statistic':'median across process-pair ratios of median within-process round means; descriptive ranges, no confidence interval',
   'summary':summary,'process_pairs':pairs,'raw_directory':str(raw)})
  print(output,flush=True)
 finally:lock.rmdir()
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--resume');parser.add_argument('--manifest',required=True);parser.add_argument('--out',required=True)
 parser.add_argument('--mode',choices=['bench','allocation'],default='bench');parser.add_argument('--parameters',required=True);parser.add_argument('--operations',required=True)
 parser.add_argument('--forks',type=int,default=2);parser.add_argument('--start',type=int,default=0);parser.add_argument('--rounds',type=int,default=2)
 parser.add_argument('--budget-ms',type=int,default=100);parser.add_argument('--warmup-cycles',type=int,default=2);parser.add_argument('--jit-trace',action='store_true')
 main(parser.parse_args())
