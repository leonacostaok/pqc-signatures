#!/usr/bin/env python3
import argparse,datetime,hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('Python optimization disables guards')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];BUILD=ROOT/'libs/noble/build/resource-followup'
OLD=ROOT.parent/'published-memory-audit/libs/noble/build/published-memory'
NODE=Path('/Users/dandelionlabs/.nvm/versions/node/v22.23.2/bin/node')
ML=[f'ML-DSA-{n}' for n in (44,65,87)]
MISSING=[f'SLH-DSA-{h}-{n}{s}' for h in ('SHA2','SHAKE') for n in (128,192,256) for s in ('f','s')]+['Falcon-512','Falcon-1024']
ENV=dict(os.environ);ENV.pop('NODE_OPTIONS',None)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,x):
 with p.open('x') as f:json.dump(x,f,indent=2);f.write('\n')
def inputs():return {str(p.relative_to(ROOT)):sha(p) for p in sorted(HERE.iterdir()) if p.suffix in ('.py','.mjs')}
def tree(p):return {str(f.relative_to(p)):sha(f) for f in sorted(p.rglob('*')) if f.is_file()}
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def prepare():
 BUILD.mkdir(parents=True,exist_ok=True);dest=BUILD/('snapshot-'+hashlib.sha256(json.dumps(inputs(),sort_keys=True).encode()).hexdigest()[:16]);dest.mkdir()
 m={'schema':'noble-resource-followup-seal-v1','inputs':inputs(),'node':str(NODE),'node_sha256':sha(NODE),'node_version':subprocess.check_output([NODE,'--version'],text=True).strip(),'source_parent_manifest':str(OLD/'manifest.json'),'source_parent_manifest_sha256':sha(OLD/'manifest.json'),'variants':{},'fixtures':{},'created_at':now(),'support':{'Falcon':'detached variable-length Falcon; explicit48-byte deterministic signing entropy; no context'}}
 old=json.loads((OLD/'manifest.json').read_text())
 for v in ('baseline','candidate'):
  assert tree(OLD/v)==old['variants'][v]['tree'];shutil.copytree(OLD/v,dest/v)
  m['variants'][v]={'path':str(dest/v),'root':str(dest/v/'node_modules/@noble/post-quantum'),'tree':tree(dest/v),'git_ref':old['refs'][v]}
 assert m['variants']['baseline']['tree']!=m['variants']['candidate']['tree']
 for param in ML+MISSING:
  out=dest/(param+'.json');cmd=[str(NODE),str(HERE/'fixture.mjs'),m['variants']['baseline']['root'],param,str(out)]
  r=subprocess.run(cmd,env=ENV,text=True,capture_output=True);(dest/(param+'-fixture.stderr')).write_text(r.stderr);assert r.returncode==0,(param,r.stderr)
  data=json.loads(out.read_text());assert len(data['rows'])==5 and len({x['seed'] for x in data['rows']})==5
  m['fixtures'][param]={'path':str(out),'sha256':sha(out)};print('fixture',param,flush=True)
 write(dest/'manifest.json',m);(BUILD/'prepared.json').write_text(json.dumps({'manifest':str(dest/'manifest.json')})+'\n');print(dest/'manifest.json')
def reseal():
 ptr=Path(json.loads((BUILD/'prepared.json').read_text())['manifest']);m=json.loads(ptr.read_text())
 assert not (ptr.parent/'gate.json').exists()
 assert sha(NODE)==m['node_sha256'] and sha(m['source_parent_manifest'])==m['source_parent_manifest_sha256']
 for name in ('common.mjs','fixture.mjs'):
  key=str((HERE/name).relative_to(ROOT));assert inputs()[key]==m['inputs'][key], 'fixture producer changed'
 for x in m['fixtures'].values():assert sha(x['path'])==x['sha256']
 for x in m['variants'].values():assert tree(Path(x['path']))==x['tree']
 m['preparation_parent_manifest']={'path':str(ptr),'sha256':sha(ptr)};m['inputs']=inputs();m['resealed_at']=now()
 out=ptr.parent/('manifest-'+hashlib.sha256(json.dumps(inputs(),sort_keys=True).encode()).hexdigest()[:16]+'.json');write(out,m)
 (BUILD/'prepared.json').write_text(json.dumps({'manifest':str(out)})+'\n');print(out)
def load():
 ptr=json.loads((BUILD/'prepared.json').read_text());path=Path(ptr['manifest']);m=json.loads(path.read_text());verify(m);return path,m
def verify(m):
 assert m['inputs']==inputs() and sha(NODE)==m['node_sha256']
 assert sha(m['source_parent_manifest'])==m['source_parent_manifest_sha256']
 for x in m['fixtures'].values():assert sha(x['path'])==x['sha256']
 for x in m['variants'].values():assert tree(Path(x['path']))==x['tree']
def command(m,param,v,mode,op=None,settings='default'):
 flags=[] if settings=='default' else ['--max-old-space-size=32','--max-semi-space-size=1']
 opts={'root':m['variants'][v]['root'],'fixture':m['fixtures'][param]['path'],'parameter':param,'mode':mode,'operation':op,'settings':settings}
 return [str(NODE),*flags,str(HERE/'worker.mjs'),json.dumps(opts,sort_keys=True)]
def check():
 path,m=load();out=path.parent/'checks';out.mkdir();records=[]
 for param in ML+MISSING:
  vs=['baseline','candidate'] if param in ML else ['baseline']
  for v in vs:
   for setting in (['default','constrained'] if param in ML else ['default']):
    cmd=command(m,param,v,'check',settings=setting);r=subprocess.run(cmd,env=ENV,text=True,capture_output=True);raw=out/(param+'-'+v+'-'+setting+'.json');raw.write_text(r.stdout);raw.with_suffix('.stderr').write_text(r.stderr);assert r.returncode==0,r.stderr
    data=json.loads(r.stdout);output_gate(m,data);assert data['checks']=={'inputs_preserved':True,'exact_outputs':True,'tamper_rejections':3}
    records.append({'parameter':param,'variant':v,'settings':setting,'argv':cmd,'raw':str(raw),'sha256':sha(raw)})
    print('check',param,v,setting,flush=True)
 verify(m);write(path.parent/'gate.json',{'manifest_sha256':sha(path),'records':records,'passed':True})
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
def persist_gate(out,m,gate):
 (out/'fixtures').mkdir();(out/'checks').mkdir()
 for param,x in m['fixtures'].items():shutil.copyfile(x['path'],out/'fixtures'/(param+'.json'))
 for x in gate['records']:
  src=Path(x['raw']);shutil.copyfile(src,out/'checks'/src.name);shutil.copyfile(src.with_suffix('.stderr'),out/'checks'/src.with_suffix('.stderr').name)
def collect(out,profile):
 path,m=load();gate=json.loads((path.parent/'gate.json').read_text());assert gate['passed'] is True and gate['manifest_sha256']==sha(path)
 for x in gate['records']:assert sha(x['raw'])==x['sha256']
 out.mkdir(parents=True);write(out/'manifest.json',m);write(out/'gate.json',gate);persist_gate(out,m,gate)
 plan=[]
 if profile=='baseline':
  for rnd in range(3):
   for param in MISSING:plan.append({'round':rnd,'parameter':param,'variant':'baseline','mode':'latency','settings':'default','operation':None})
 else:
  for rnd in range(4):
   for pi,param in enumerate(ML):
    for oi,op in enumerate(['keygen','getPublicKey','sign','verify']):
     for setting in ['default','constrained']:
      vs=['baseline','candidate']
      if (rnd+pi+oi)%2:vs.reverse()
      plan.extend({'round':rnd,'parameter':param,'variant':v,'mode':'resource','settings':setting,'operation':op} for v in vs)
 write(out/'plan.json',plan);records=[];start=now()
 for i,c in enumerate(plan):
  cmd=command(m,c['parameter'],c['variant'],c['mode'],c['operation'],c['settings']);began=now();r=subprocess.run(cmd,env=ENV,text=True,capture_output=True)
  raw=out/f'{i:03d}.json';raw.write_text(r.stdout);raw.with_suffix('.stderr').write_text(r.stderr)
  records.append({**c,'index':i,'argv':cmd,'started_at':began,'completed_at':now(),'exit_code':r.returncode,'raw':raw.name,'sha256':sha(raw),'stderr_sha256':sha(raw.with_suffix('.stderr'))})
  execution={'schema':'noble-resource-followup-execution-v1','profile':profile,'python_version':sys.version,'python_optimize':sys.flags.optimize,'started_at':start,'manifest_sha256':sha(path),'runs':records}
  (out/'execution.json').write_text(json.dumps(execution,indent=2)+'\n');assert r.returncode==0,r.stderr
  data=json.loads(r.stdout);output_gate(m,data);assert data['parameter']==c['parameter'] and data['checks']=={'inputs_preserved':True,'exact_outputs':True,'tamper_rejections':3};assert data['mode']==c['mode'] and data['settings']==c['settings'];assert [x['operation'] for x in data['rows']]==([c['operation']] if c['operation'] else ['keygen','sign','verify'])
  assert all(x['count']==(192 if profile=='resource' else 3) and all(type(n) is int and n>0 for n in x['api_ns']) for x in data['rows'])
  print(i+1,len(plan),c,flush=True)
 verify(m);execution['completed_at']=now();execution['passed']=True;(out/'execution.json').write_text(json.dumps(execution,indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','reseal','check','collect']);p.add_argument('--profile',choices=['baseline','resource']);p.add_argument('--out',type=Path);a=p.parse_args()
 if a.mode=='prepare':prepare()
 elif a.mode=='reseal':reseal()
 elif a.mode=='check':check()
 else:assert a.profile and a.out;collect(a.out,a.profile)
