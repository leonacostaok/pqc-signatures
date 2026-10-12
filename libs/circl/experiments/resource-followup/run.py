#!/usr/bin/env python3
import argparse,datetime,hashlib,io,json,os,shutil,subprocess,sys,tarfile
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('Python optimization disables guards')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];BUILD=ROOT/'libs/circl/build/resource-followup'
REPO=Path('/Users/dandelionlabs/development/personal/circl');NOBLE=ROOT/'libs/noble/build/resource-followup'
REFS={'baseline':'91db3e785ba2635b4f24a023e1ad76d2780e2865','candidate':'1c31496b567c27e672979358befd2505cb735fa9'}
AFFECTED=[f'SLH-DSA-SHA2-{n}{s}' for n in (128,192,256) for s in ('f','s')]
MISSING=[f'ML-DSA-{n}' for n in (44,65,87)]+[f'SLH-DSA-SHAKE-{n}{s}' for n in (128,192,256) for s in ('f','s')]
ENV=dict(os.environ,GOMAXPROCS='1',GOTOOLCHAIN='local',GOGC='100',GOMEMLIMIT='off');ENV.pop('GOFLAGS',None);ENV.pop('GODEBUG',None)
def env(setting):return dict(ENV,GOMEMLIMIT='8MiB' if setting=='constrained' else 'off')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,x):
 with p.open('x') as f:json.dump(x,f,indent=2);f.write('\n')
def inputs():return {str(p.relative_to(ROOT)):sha(p) for p in sorted(HERE.iterdir()) if p.suffix in ('.py','.go')}
def tree(p):return {str(f.relative_to(p)):sha(f) for f in sorted(p.rglob('*')) if f.is_file() and f.suffix in ('.go','.s','.c','.h','.mod','.sum')}
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def prepare():
 BUILD.mkdir(parents=True,exist_ok=True);dest=BUILD/('snapshot-'+hashlib.sha256(json.dumps(inputs(),sort_keys=True).encode()).hexdigest()[:16]);dest.mkdir()
 npm=Path(json.loads((NOBLE/'prepared.json').read_text())['manifest']);nm=json.loads(npm.read_text())
 m={'schema':'circl-resource-followup-seal-v1','inputs':inputs(),'refs':REFS,'variants':{},'fixtures':{},'created_at':now(),'go':subprocess.check_output(['go','version'],text=True).strip(),'go_binary':str(Path(shutil.which('go')).resolve()),'go_binary_sha256':sha(Path(shutil.which('go')).resolve()),'fixture_parent_manifest':str(npm),'fixture_parent_manifest_sha256':sha(npm),'environments':{x:{k:env(x).get(k,'') for k in ['GOGC','GOMEMLIMIT','GOMAXPROCS','GOTOOLCHAIN','GODEBUG','GOFLAGS']} for x in ['default','constrained']}}
 for param in AFFECTED+MISSING:
  v=nm['fixtures'][param];assert sha(v['path'])==v['sha256'];p=dest/(param+'.json');shutil.copyfile(v['path'],p);m['fixtures'][param]={'path':str(p),'sha256':sha(p)}
 for v,ref in REFS.items():
  target=dest/v;target.mkdir();archive=subprocess.check_output(['git','-C',REPO,'archive',ref])
  with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
   assert all(not x.name.startswith('/') and '..' not in Path(x.name).parts and (x.isfile() or x.isdir()) for x in tar.getmembers());tar.extractall(target)
  assert (target/'sign/slhdsa/state.go').read_bytes()==subprocess.check_output(['git','-C',REPO,'show',ref+':sign/slhdsa/state.go'])
  driver=target/'cmd/resourcefollowup';driver.mkdir(parents=True);shutil.copyfile(HERE/'main.go',driver/'main.go');binary=target/'resourcefollowup'
  cmd=['go','build','-trimpath','-buildvcs=false','-pgo=off','-o',str(binary),'./cmd/resourcefollowup'];r=subprocess.run(cmd,cwd=target,env=ENV,text=True,capture_output=True);(dest/(v+'-build.log')).write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
  m['variants'][v]={'path':str(target),'tree':tree(target),'binary':str(binary),'binary_sha256':sha(binary),'build_argv':cmd};print('build',v,flush=True)
 assert m['variants']['baseline']['binary_sha256']!=m['variants']['candidate']['binary_sha256']
 write(dest/'manifest.json',m);(BUILD/'prepared.json').write_text(json.dumps({'manifest':str(dest/'manifest.json')})+'\n');print(dest/'manifest.json')
def load():
 path=Path(json.loads((BUILD/'prepared.json').read_text())['manifest']);m=json.loads(path.read_text());verify(m);return path,m
def verify(m):
 assert m['inputs']==inputs() and sha(m['go_binary'])==m['go_binary_sha256'] and sha(m['fixture_parent_manifest'])==m['fixture_parent_manifest_sha256']
 for v in m['variants'].values():assert tree(Path(v['path']))==v['tree'] and sha(v['binary'])==v['binary_sha256']
 for v in m['fixtures'].values():assert sha(v['path'])==v['sha256']
 for setting,e in m['environments'].items():assert e=={k:env(setting).get(k,'') for k in e}
def command(m,param,v,mode,op=None,setting='default'):
 return [m['variants'][v]['binary'],'-fixture',m['fixtures'][param]['path'],'-param',param,'-mode',mode,'-settings',setting]+(['-op',op] if op else [])
def check():
 path,m=load();out=path.parent/'checks';out.mkdir();records=[]
 for param in AFFECTED+MISSING:
  vs=['baseline','candidate'] if param in AFFECTED else ['baseline']
  for v in vs:
   for setting in (['default','constrained'] if param in AFFECTED else ['default']):
    cmd=command(m,param,v,'check',setting=setting);r=subprocess.run(cmd,env=env(setting),text=True,capture_output=True);raw=out/(param+'-'+v+'-'+setting+'.json');raw.write_text(r.stdout);raw.with_suffix('.stderr').write_text(r.stderr);assert r.returncode==0,r.stderr
    data=json.loads(r.stdout);output_gate(m,data);assert data['checks']=={'inputs_preserved':True,'exact_outputs':True,'tamper_rejections':3};records.append({'parameter':param,'variant':v,'settings':setting,'argv':cmd,'raw':str(raw),'sha256':sha(raw)});print('check',param,v,setting,flush=True)
 verify(m);write(path.parent/'gate.json',{'manifest_sha256':sha(path),'passed':True,'records':records})
def output_gate(m,data):
 fixture=json.loads(Path(m['fixtures'][data['parameter']]['path']).read_text());cases=[c for c in fixture['rows'] if c['group']=='measured']
 assert len(cases)==3
 for row in data['rows']:
  h=hashlib.sha256()
  for i in range(row['count']):
   c=cases[i%3];op=row['operation']
   for name in (['publicKey','secretKey'] if op=='keygen' else ['signature'] if op=='sign' else ['publicKey'] if op=='getPublicKey' else []):h.update(bytes.fromhex(c[name]))
   if op=='verify':h.update(b'\x01')
  assert h.hexdigest()==row['output_sha256']
  assert row['count']==len(row['api_ns']) and all(type(n) is int and n>0 for n in row['api_ns'])
def expected_calls(param,op):
 if op=='sign':return 3 if param.endswith('s') else 60 if '128' in param else 36 if '192' in param else 18
 if op=='keygen':return 24 if param.endswith('s') else 1536 if '128' in param else 768 if '192' in param else 384
 return 3072 if param.endswith('s') else 1536
def persist_gate(out,m,gate):
 (out/'fixtures').mkdir();(out/'checks').mkdir()
 for param,x in m['fixtures'].items():shutil.copyfile(x['path'],out/'fixtures'/(param+'.json'))
 for x in gate['records']:
  src=Path(x['raw']);shutil.copyfile(src,out/'checks'/src.name);shutil.copyfile(src.with_suffix('.stderr'),out/'checks'/src.with_suffix('.stderr').name)
def collect(out,profile):
 path,m=load();gate=json.loads((path.parent/'gate.json').read_text());assert gate['passed'] is True and gate['manifest_sha256']==sha(path)
 for v in gate['records']:assert sha(v['raw'])==v['sha256']
 out.mkdir(parents=True);write(out/'manifest.json',m);write(out/'gate.json',gate);persist_gate(out,m,gate);plan=[]
 if profile=='baseline':
  for rnd in range(3):
   for param in MISSING:plan.append({'round':rnd,'parameter':param,'variant':'baseline','mode':'latency','settings':'default','operation':None})
 else:
  for rnd in range(4):
   for pi,param in enumerate(AFFECTED):
    for oi,op in enumerate(['keygen','sign','verify']):
     for setting in ['default','constrained']:
      vs=['baseline','candidate']
      if (rnd+pi+oi)%2:vs.reverse()
      plan.extend({'round':rnd,'parameter':param,'variant':v,'mode':'resource','settings':setting,'operation':op} for v in vs)
 write(out/'plan.json',plan);runs=[];start=now()
 for i,c in enumerate(plan):
  cmd=command(m,c['parameter'],c['variant'],c['mode'],c['operation'],c['settings']);began=now();r=subprocess.run(cmd,env=env(c['settings']),text=True,capture_output=True);raw=out/f'{i:03d}.json';raw.write_text(r.stdout);raw.with_suffix('.stderr').write_text(r.stderr)
  runs.append({**c,'index':i,'argv':cmd,'started_at':began,'completed_at':now(),'exit_code':r.returncode,'raw':raw.name,'sha256':sha(raw),'stderr_sha256':sha(raw.with_suffix('.stderr'))})
  ex={'schema':'circl-resource-followup-execution-v1','profile':profile,'python_version':sys.version,'python_optimize':sys.flags.optimize,'started_at':start,'manifest_sha256':sha(path),'runs':runs};(out/'execution.json').write_text(json.dumps(ex,indent=2)+'\n');assert r.returncode==0,r.stderr
  data=json.loads(r.stdout);output_gate(m,data);assert data['parameter']==c['parameter'] and data['checks']=={'inputs_preserved':True,'exact_outputs':True,'tamper_rejections':3};assert data['mode']==c['mode'] and data['settings']==c['settings'];assert [x['operation'] for x in data['rows']]==([c['operation']] if c['operation'] else ['keygen','sign','verify']);assert all(x['count']==(expected_calls(c['parameter'],c['operation']) if profile=='resource' else 3) and len(x['api_ns'])==x['count'] and all(type(n) is int and n>0 for n in x['api_ns']) for x in data['rows']);print(i+1,len(plan),c,flush=True)
 verify(m);ex['completed_at']=now();ex['passed']=True;(out/'execution.json').write_text(json.dumps(ex,indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','check','collect']);p.add_argument('--profile',choices=['baseline','resource']);p.add_argument('--out',type=Path);a=p.parse_args()
 if a.mode=='prepare':prepare()
 elif a.mode=='check':check()
 else:assert a.profile and a.out;collect(a.out,a.profile)
