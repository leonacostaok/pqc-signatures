#!/usr/bin/env python3
"""Fresh-process paired public-API benchmark. Final runs require a quiet-host grant."""
import argparse, datetime, hashlib, json, math, os, platform, random, statistics, subprocess, threading, time
from pathlib import Path

PARAMS=['SLH_DSA_PURE_SHA2_'+p for p in ('128F','128S','192F','192S','256F','256S')]
p=argparse.ArgumentParser()
p.add_argument('--build',type=Path,required=True)
p.add_argument('--evidence',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--forks',type=int,default=6)
p.add_argument('--sign-iters',type=int,default=3)
p.add_argument('--verify-iters',type=int,default=30)
p.add_argument('--exclusive-window-granted',action='store_true')
p.add_argument('--pilot',action='store_true')
a=p.parse_args()
if not a.pilot and not a.exclusive_window_granted: p.error('reserve the exclusive machine window before final timing')
if not a.pilot and (a.forks < 6 or a.forks % 2): p.error('use at least six forks, in balanced AB/BA pairs')
if min(a.forks,a.sign_iters,a.verify_iters)<1: p.error('counts must be positive')
if a.output.exists(): p.error('output already exists; refusing to overwrite evidence')
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
corpus=a.build/'corpus.bin'
cm=json.loads((a.evidence/'corpus-manifest.json').read_text())
assert cm['byte_identical_keys_and_signatures'] and cm['cases']==24 and cm['sha256']==digest(corpus)
hashes=json.loads((a.evidence/'hash-checks.json').read_text())
assert len(hashes['results'])==4 and all(x['passed_checks']==5710 for x in hashes['results'].values())
assert 'cleanse calls: 2' in hashes['backend_probe'] and 'failed: 0' in hashes['backend_probe']
assert all(row['transform_and_cleanse_retained'] for row in json.loads((a.evidence/'cleanse-assembly.json').read_text()))
sig=json.loads((a.evidence/'upstream-signature-tests.json').read_text())
assert len(sig)==6 and all(x['returncode']==0 for x in sig)
checks=json.loads((a.evidence/'corpus-checks.json').read_text())
assert len(checks)==3 and all(x['returncode']==0 for x in checks)
for row in checks:
 records=[json.loads(s) for s in (a.evidence/row['log']).read_text().splitlines()]
 assert len(records)==24 and {(v['parameter'],v['case']) for v in records}=={(s,c) for s in PARAMS for c in range(4)} and all(v['checked'] is True for v in records)
ready=json.loads((a.evidence/'ready-manifest.json').read_text())
for path,expected in ready['experiment_files'].items():
 assert digest(Path(path))==expected, 'changed benchmark/test source: '+path
assert digest(Path(ready['crypto_library']))==ready['crypto_sha256'], 'changed OpenSSL library'
for relative,expected in ready['files'].items():
 assert digest(a.build/relative)==expected, 'changed build input or binary: '+relative
for relative,expected in ready['source_files'].items():
 assert digest(Path(ready['candidate_source'])/relative)==expected, 'changed candidate source: '+relative
assert all(row['returncode']==0 for row in json.loads((a.evidence/'config-checks-no-deprecated.json').read_text()))
for configuration in ('no-openssl','sha2-disabled'):
 rows=json.loads((a.evidence/('config-checks-'+configuration+'.json')).read_text())
 assert len(rows)==4 and all(r['returncode']==0 for r in rows)
a.output.mkdir(parents=True)
(a.output/'ready-manifest.json').write_bytes((a.evidence/'ready-manifest.json').read_bytes())
manifest={'pilot':a.pilot,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'platform':platform.platform(),'machine':platform.machine(),'forks':a.forks,'sign_iterations':a.sign_iters,'verify_iterations':a.verify_iters,'corpus':cm,'ready_manifest_sha256':digest(a.evidence/'ready-manifest.json'),'randomness':'Unmodified OQS_randombytes in timed public signing; fixed identical verification fixtures','order':[]}
(a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
# Low-frequency diagnostics only; no system services are changed or stopped.
stop_sampling=threading.Event()
load_samples=[]
current_cell=None
def sample_load():
 while not stop_sampling.is_set():
  cell=current_cell
  result=subprocess.run(['ps','-A','-o','pid=,pcpu=,comm='],capture_output=True,text=True)
  if result.returncode==0:
   processes=[]
   for line in result.stdout.splitlines():
    fields=line.strip().split(None,2)
    if len(fields)!=3: continue
    pid,cpu,command=fields
    name=Path(command).name
    if name in ('corpus','ps'): continue
    processes.append({'pid':int(pid),'cpu_percent':float(cpu),'name':name})
   total=sum(row['cpu_percent'] for row in processes)
   heavy=sorted((row for row in processes if row['cpu_percent']>=5),key=lambda row:row['cpu_percent'],reverse=True)[:12]
   load_samples.append({'monotonic_seconds':time.monotonic(),'cell':cell,'load_average':os.getloadavg(),'background_cpu_percent':total,'processes':heavy})
   (a.output/'host-load.json').write_text(json.dumps(load_samples,indent=2)+'\n')
  stop_sampling.wait(5)
monitor=threading.Thread(target=sample_load,daemon=True)
monitor.start()
expected={(param,case,op) for param in PARAMS for case in range(4) for op in ('sign','verify')}
rounds=[]
for fork in range(a.forks):
 order=['baseline','candidate'] if fork%2==0 else ['candidate','baseline']
 manifest['order'].append(order)
 pair={}
 for label in order:
  current_cell={'fork':fork+1,'variant':label}
  command=[str(a.build/label/'corpus'),'bench',str(corpus),str(a.sign_iters),str(a.verify_iters)]
  r=subprocess.run(command,capture_output=True,text=True)
  (a.output/f'{fork+1:02d}-{label}.jsonl').write_text(r.stdout)
  (a.output/f'{fork+1:02d}-{label}.stderr').write_text(r.stderr)
  if r.returncode: raise SystemExit(f'{label} fork {fork+1} failed with {r.returncode}')
  records=[json.loads(s) for s in r.stdout.splitlines()]
  assert len(records)==48 and {(x['parameter'],x['case'],x['operation']) for x in records}==expected
  for x in records:
   assert isinstance(x['total_ns'],int) and x['total_ns']>0
   assert x['iterations']==(a.sign_iters if x['operation']=='sign' else a.verify_iters)
   assert x['message_bytes']==[0,32,256,4096][x['case']] and x['context_bytes']==[0,1,17,255][x['case']]
  pair[label]=records
 rounds.append(pair)
 (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(f'paired fork {fork+1}/{a.forks} complete',flush=True)
stop_sampling.set()
monitor.join()
summary=[]
for param in PARAMS:
 for op in ('sign','verify'):
  ratios=[]; base=[]; candidate=[]
  for pair in rounds:
   times={label:sum(x['total_ns']/x['iterations'] for x in rows if x['parameter']==param and x['operation']==op)/4 for label,rows in pair.items()}
   ratios.append(times['baseline']/times['candidate']);base.append(times['baseline']);candidate.append(times['candidate'])
  rng=random.Random(1804205); boot=[]
  for _ in range(10000):
   boot.append(math.exp(sum(math.log(rng.choice(ratios)) for _ in ratios)/len(ratios)))
  boot.sort()
  summary.append({'parameter':param,'operation':op,'paired_speedups':ratios,'median_speedup':statistics.median(ratios),'geometric_mean_speedup':math.exp(statistics.mean(map(math.log,ratios))),'paired_bootstrap_95pct':[boot[249],boot[9749]],'baseline_median_ns':statistics.median(base),'candidate_median_ns':statistics.median(candidate)})
(a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
manifest['completed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
manifest['complete']=True
manifest['host_load_note']='ps percent CPU is a diagnostic, not an instantaneous utilization or isolation guarantee; background activity must be reviewed before accepting speed claims.'
manifest['background_cpu_max']=max((x['background_cpu_percent'] for x in load_samples),default=None)
manifest['background_cpu_median']=statistics.median([x['background_cpu_percent'] for x in load_samples]) if load_samples else None
manifest['raw_sha256']={f.name:digest(f) for f in sorted(a.output.glob('*.jsonl'))}
(a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(summary,indent=2))
