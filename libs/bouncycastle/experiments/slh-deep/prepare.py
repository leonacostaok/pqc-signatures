#!/usr/bin/env python3
"""Prepare isolated BC SLH source/class copies and exact-output gates; never time here."""
import argparse, datetime, hashlib, io, json, os, shutil, subprocess, sys, tarfile
from pathlib import Path
if sys.flags.optimize: raise RuntimeError('assertions required; do not use -O')
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
BUILD=HERE.parents[1]/'build'/'slh-deep'
PIN='c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
PARAMETERS=[f'{a}_{b}{c}' for a in ['sha2','shake'] for b in [128,192,256] for c in ['f','s']]
VARIANTS=['baseline','candidate']
JVM=['-Xmx512m','-XX:ActiveProcessorCount=2']
ENV=['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS']

def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,v):
 with Path(p).open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def tree(p,suffix):
 h=hashlib.sha256()
 for f in sorted(Path(p).rglob('*'+suffix)):
  h.update(str(f.relative_to(p)).encode()+b'\0'+bytes.fromhex(sha(f)))
 return h.hexdigest()
def persist(command,dest,stem,cwd=None):
 command=list(map(str,command));write(dest/(stem+'.command.json'),{'command':command,'cwd':str(cwd) if cwd else None,'started_at':stamp()})
 with (dest/(stem+'.stdout.txt')).open('x') as out,(dest/(stem+'.stderr.txt')).open('x') as err:
  r=subprocess.run(command,cwd=cwd,stdout=out,stderr=err)
 write(dest/(stem+'.status.json'),{'exit_code':r.returncode,'finished_at':stamp()})
 if r.returncode:raise RuntimeError(f'{stem} exit {r.returncode}; logs retained at {dest}')
 return (dest/(stem+'.stdout.txt')).read_text()
def provenance(m):
 return {'files':{p:sha(p) for p in m['bound_files']},'java':sha(m['java']),
  'classes':{v:tree(m['classes'][v],'.class') for v in VARIANTS},
  'sources':{v:tree(m['sources'][v],'.java') for v in VARIANTS},
  'driver_classes':{v:tree(m['drivers'][v],'.class') for v in VARIANTS},
  'test_classes':{v:tree(m['tests'][v],'.class') for v in VARIANTS}}
def command(m,side,*args):
 return [m['java'],*JVM,'-cp',os.pathsep.join([m['drivers'][side],m['classes'][side]]),
  'org.bouncycastle.crypto.signers.slhdsa.SlhDeepProbe',args[0],m['fixtures'],args[1],side,*args[2:]]
def prepare(args):
 parameters=args.parameters.split(',')
 assert parameters and len(set(parameters))==len(parameters) and set(parameters)<=set(PARAMETERS)
 upstream=Path(args.upstream).resolve();old=json.loads(Path(args.original).read_text())
 assert old['old']['upstream_commit']==PIN
 java=Path(old['old']['java']);javac=java.with_name('javac')
 files=[HERE/'SlhDeepProbe.java',HERE/'prepare.py',HERE/'run.py',HERE/'wots-buffer.patch',HERE/'treehash-stack.patch']
 tests=sorted((upstream/'core/src/test/java/org/bouncycastle/crypto/signers/slhdsa').glob('*.java'))
 assert {p.name for p in tests}=={'AllTests.java','WotsPlusTest.java','TreehashTest.java'}
 identity=hashlib.sha256((''.join(sha(p) for p in files+tests)+sha(old['fixtures'])+','.join(parameters)).encode()).hexdigest()[:16]
 dest=BUILD/('prepared-'+identity);dest.mkdir(parents=True,exist_ok=False);logs=dest/'checks';logs.mkdir()
 fixture=dest/'fixtures.tsv';shutil.copyfile(old['fixtures'],fixture)
 assert sha(fixture)==old['provenance']['fixtures']
 archive=subprocess.check_output(['git','-C',str(upstream),'archive',PIN,'core/src/main/java'])
 (dest/'baseline-source.tar').write_bytes(archive)
 copied_tests=dest/'native-tests';copied_tests.mkdir()
 for file in tests:shutil.copyfile(file,copied_tests/file.name)
 m={'schema':'bc-slh-deep-prepared-v1','upstream_commit':PIN,'created_at':stamp(),'java':str(java),
  'java_version':subprocess.run([java,'-version'],text=True,capture_output=True,check=True).stderr,
  'jvm_args':JVM,'environment':{k:os.environ.get(k,'') for k in ENV},'parameters':parameters,'variants':VARIANTS,
  'fixtures':str(fixture),'fixture_origin_manifest_sha256':sha(args.original),'classes':{},'sources':{},'drivers':{},'tests':{},
  'bound_files':list(map(str,files+list(copied_tests.glob('*.java'))+[fixture,dest/'baseline-source.tar',java.parent.parent/'release'])),
  'checks':{},'stage_checks':{}}
 initial_files={file:sha(file) for file in m['bound_files']}
 for side in VARIANTS:
  print('Building '+side,flush=True);source=dest/(side+'-src');source.mkdir()
  with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
   assert all(not p.name.startswith('/') and '..' not in Path(p.name).parts and (p.isfile() or p.isdir()) for p in tar.getmembers());tar.extractall(source)
  persist(['git','init','-q'],logs,side+'-git-init',source)
  assert Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],cwd=source,text=True).strip()).resolve()==source.resolve()
  if side!='baseline':
   persist(['git','apply','--check',HERE/'wots-buffer.patch'],logs,side+'-patch-check',source)
   persist(['git','apply',HERE/'wots-buffer.patch'],logs,side+'-patch',source)
   persist(['git','apply','--reverse','--check',HERE/'wots-buffer.patch'],logs,side+'-patch-reverse-check',source)
   original=Path(m['sources']['baseline'])
   before={str(f.relative_to(original)):sha(f) for f in original.rglob('*.java')}
   after={str(f.relative_to(source)):sha(f) for f in source.rglob('*.java')}
   assert before.keys()==after.keys()
   changed={name for name in before if before[name]!=after[name]}
   intended={'core/src/main/java/org/bouncycastle/crypto/signers/slhdsa/'+name for name in ['WotsPlus.java','SLHDSAEngine.java']}
   assert changed==intended and tree(original,'.java')!=tree(source,'.java'),changed
   assert all(sha(source/name)==sha(upstream/name) for name in intended),'candidate does not match intended production edits'
   m['patch_verification']={'changed_files':sorted(changed),'baseline_hashes':{name:before[name] for name in sorted(changed)},'candidate_hashes':{name:after[name] for name in sorted(changed)},'reverse_apply_check':True,'isolated_git_root':str(source)}
  classes=dest/(side+'-classes');classes.mkdir();driver=dest/(side+'-driver');driver.mkdir();testout=dest/(side+'-tests');testout.mkdir()
  main=source/'core/src/main/java';entries=[main/('org/bouncycastle/'+p) for p in ['crypto/signers/SLHDSASigner.java','crypto/signers/HashSLHDSASigner.java','crypto/generators/SLHDSAKeyPairGenerator.java']]
  persist([javac,'-J-XX:ActiveProcessorCount=2','--release','8','-sourcepath',main,'-d',classes,*entries],logs,side+'-compile')
  persist([javac,'-J-XX:ActiveProcessorCount=2','--release','8','-cp',classes,'-d',driver,HERE/'SlhDeepProbe.java'],logs,side+'-driver')
  deps=Path(args.dependencies).resolve();cp=os.pathsep.join(map(str,[classes,deps/'junit-4.13.2.jar',deps/'hamcrest-core-1.3.jar']))
  persist([javac,'-J-XX:ActiveProcessorCount=2','--release','8','-cp',cp,'-d',testout,*copied_tests.glob('*.java')],logs,side+'-test-compile')
  unit=persist([java,*JVM,'-cp',str(testout)+os.pathsep+cp,'org.junit.runner.JUnitCore','org.bouncycastle.crypto.signers.slhdsa.AllTests'],logs,side+'-unit')
  assert 'OK (2 tests)' in unit
  for field,path in [('classes',classes),('sources',source),('drivers',driver),('tests',testout)]:m[field][side]=str(path)
 assert tree(m['classes']['baseline'],'.class')!=tree(m['classes']['candidate'],'.class'),'identical implementation classes'
 for side in VARIANTS:
  classes=Path(m['classes'][side])
  m['checks'][side]={};m['stage_checks'][side]={}
  for parameter in parameters:
   print('Checking '+side+' '+parameter,flush=True)
   result=persist(command(m,side,'check',parameter),logs,side+'-'+parameter+'-check')
   rows=[json.loads(line) for line in result.splitlines()];assert len(rows)==36
   assert {(r['phase'],r['case'],r['operation']) for r in rows}=={(phase,i,op) for phase,n in [('warmup',2),('measured',10)] for i in range(n) for op in ['keygen.total','sign.total','verify.total']}
   for row in rows:assert row['variant']==side and row['parameter']==parameter and row['class_source']==str(classes) and row['checked'] is True
   m['checks'][side][parameter]=rows
   result=persist(command(m,side,'stages-check',parameter),logs,side+'-'+parameter+'-stages')
   rows=[json.loads(line) for line in result.splitlines()];assert len(rows)==72 and len({(r['case'],r['operation']) for r in rows})==72
   for row in rows:assert row['variant']==side and row['parameter']==parameter and row['class_source']==str(classes) and row['checked'] is True and row['phase']=='measured' and row['case'] in [0,3,6,9]
   m['stage_checks'][side][parameter]=rows
 def comparable(row):return {k:v for k,v in row.items() if k not in ['variant','class_source']}
 for side in VARIANTS[1:]:
  for parameter in parameters:
   for field in ['checks','stage_checks']:
    assert list(map(comparable,m[field]['baseline'][parameter]))==list(map(comparable,m[field][side][parameter])),(field,side,parameter)
 assert initial_files=={file:sha(file) for file in m['bound_files']},'bound files changed during preparation'
 m['provenance']=provenance(m);write(dest/'manifest.json',m)
 evidence=ROOT/'results/bouncycastle/slh-deep'/dest.name;evidence.mkdir(parents=True,exist_ok=False)
 shutil.copytree(logs,evidence/'checks');shutil.copyfile(dest/'manifest.json',evidence/'manifest.json')
 print(dest/'manifest.json',flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--upstream',required=True);p.add_argument('--original',required=True);p.add_argument('--dependencies',required=True);p.add_argument('--parameters',default='sha2_128f,shake_128f');prepare(p.parse_args())
