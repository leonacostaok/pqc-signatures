#!/usr/bin/env python3
import datetime,hashlib,io,json,os,shutil,subprocess,sys,tarfile
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('run without -O')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];UP=Path('/Users/dandelionlabs/development/personal/rustcrypto-signatures')
BASE='a84081789729c96dabb35f96cd000e434b247e02';HEAD='43cad14d86b36607a3c4b47c59c30d91145f64c1'
PARAMS=['ML-DSA-'+str(p) for p in [44,65,87]]+['SLH-DSA-'+f+'-'+str(n)+s for f in ['SHA2','SHAKE'] for n in [128,192,256] for s in ['f','s']]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def tree(p):return {str(f.relative_to(p)):sha(f) for f in sorted(Path(p).rglob('*')) if f.is_file()}
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write(p,v):
 with Path(p).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def run(cmd,dest,stem,cwd=None,env=None):
 write(dest/(stem+'.command.json'),{'command':list(map(str,cmd)),'cwd':str(cwd),'started_at':stamp()})
 with (dest/(stem+'.stdout.txt')).open('x')as o,(dest/(stem+'.stderr.txt')).open('x')as e:r=subprocess.run(cmd,cwd=cwd,env=env,stdout=o,stderr=e)
 write(dest/(stem+'.status.json'),{'exit_code':r.returncode,'finished_at':stamp()});assert r.returncode==0,(stem,r.returncode)
 return (dest/(stem+'.stdout.txt')).read_text()
def comparable(r):return {k:v for k,v in r.items()if k not in ['variant','metrics','accounting']}
def main():
 initial={str(p):sha(p)for p in [HERE/'probe.rs',Path(__file__)]}
 compiler=subprocess.check_output(['rustc','-Vv'],text=True);identity=hashlib.sha256((sha(HERE/'probe.rs')+sha(__file__)+compiler).encode()).hexdigest()[:16]
 dest=ROOT/'libs/rustcrypto/build/completion'/('prepared-'+identity);dest.mkdir(parents=True,exist_ok=False);logs=dest/'logs';logs.mkdir();sources={}
 for side,commit in [('baseline',BASE),('candidate',HEAD)]:
  names=['ml-dsa/src','ml-dsa/Cargo.toml','ml-dsa/README.md','Cargo.toml']+(['slh-dsa/src','slh-dsa/Cargo.toml','slh-dsa/README.md']if side=='baseline'else[])
  data=subprocess.check_output(['git','-C',str(UP),'archive',commit,*names]);(dest/(side+'.tar')).write_bytes(data);source=dest/side;source.mkdir()
  with tarfile.open(fileobj=io.BytesIO(data))as t:
   assert all(not x.name.startswith('/')and'..'not in Path(x.name).parts and(x.isfile()or x.isdir())for x in t.getmembers());t.extractall(source)
  p=source/'ml-dsa/Cargo.toml';p.write_text(p.read_text().replace('name = "ml-dsa"',f'name = "ml-dsa-{side}"\nworkspace = ".."',1));p=source/'Cargo.toml';original=p.read_text();lints=original[original.index('[workspace.lints.clippy]'):original.index('[patch.crates-io]')];p.write_text('[workspace]\nresolver="2"\nmembers=["ml-dsa"'+(',"slh-dsa"'if side=='baseline'else'')+']\n'+lints);sources[side]=str(source)
 a=tree(dest/'baseline/ml-dsa/src');b=tree(dest/'candidate/ml-dsa/src');assert a.keys()==b.keys()and[p for p in a if a[p]!=b[p]]==['signing.rs']
 (dest/'Cargo.toml').write_text('''[package]
name="rust-completion"
version="0.0.0"
edition="2024"
[workspace]
exclude=["baseline","candidate"]
[features]
accounting=[]
[dependencies]
baseline={package="ml-dsa-baseline",path="baseline/ml-dsa",features=["zeroize"]}
candidate={package="ml-dsa-candidate",path="candidate/ml-dsa",features=["zeroize"]}
slh-dsa={path="baseline/slh-dsa",features=["zeroize"]}
serde_json="=1.0.150"
sha2="=0.10.9"
libc="0.2"
''');(dest/'src').mkdir();shutil.copyfile(HERE/'probe.rs',dest/'src/main.rs');shutil.copyfile(ROOT/'libs/rustcrypto/Cargo.lock',dest/'Cargo.lock')
 env=dict(os.environ,CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0');bins={}
 for mode in ['normal','accounting']:
  cmd=['cargo','build','--offline','--release']+(['--locked','--features','accounting']if mode=='accounting'else[]);run(cmd,logs,mode+'-build',dest,env);binary=dest/mode;shutil.copyfile(dest/'target/release/rust-completion',binary);binary.chmod(0o755);bins[mode]=str(binary)
 checks={}
 for param in PARAMS:
  sides=['baseline','candidate']if param.startswith('ML')else['baseline']
  for side in sides:
   print('Checking '+param+' '+side,flush=True);rows=[json.loads(x)for x in run([bins['normal'],'check',param,side],logs,param+'-'+side+'-check').splitlines()];assert len(rows)==12 and all(r['valid']and r['tamper_rejected']for r in rows);checks[param+'/'+side]=list(map(comparable,rows))
  if len(sides)==2:assert checks[param+'/baseline']==checks[param+'/candidate']
 files=[HERE/'probe.rs',Path(__file__),dest/'src/main.rs',dest/'Cargo.toml',dest/'Cargo.lock',dest/'baseline.tar',dest/'candidate.tar']
 assert initial=={p:sha(p)for p in initial}and sha(HERE/'probe.rs')==sha(dest/'src/main.rs'),'source changed during preparation'
 m={'schema':'rust-completion-prepared-v1','base':BASE,'head':HEAD,'compiler':compiler,'features':'library defaults + zeroize','parameters':PARAMS,'binaries':bins,'sources':sources,'source_hashes':{s:tree(p)for s,p in sources.items()},'files':{str(p):sha(p)for p in files},'binary_hashes':{s:sha(p)for s,p in bins.items()},'checks':checks};write(dest/'manifest.json',m);print(dest/'manifest.json')
if __name__=='__main__':main()
