#!/usr/bin/env python3
"""Build untimed resource probes from exact Git snapshots, preserving all logs."""
import datetime, hashlib, io, json, os, shutil, subprocess, sys, tarfile
from pathlib import Path
assert not sys.flags.optimize
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
UPSTREAM=Path('/Users/dandelionlabs/development/personal/rustcrypto-signatures')
BASE='a84081789729c96dabb35f96cd000e434b247e02'
HEAD='43cad14d86b36607a3c4b47c59c30d91145f64c1'
MODES={'default':['library-default'],'default-zeroize':['library-default','zeroization'],
       'alloc-zeroize':['allocation','zeroization'],'noalloc-zeroize':['zeroization']}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,v):
 with Path(p).open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def tree(p):return {str(f.relative_to(p)):sha(f) for f in sorted(Path(p).rglob('*')) if f.is_file()}
def run(cmd,dest,stem,cwd=None,env=None):
 write(dest/(stem+'.command.json'),{'command':list(map(str,cmd)),'cwd':str(cwd),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
 with (dest/(stem+'.stdout.txt')).open('x') as out,(dest/(stem+'.stderr.txt')).open('x') as err:r=subprocess.run(cmd,cwd=cwd,env=env,stdout=out,stderr=err)
 write(dest/(stem+'.status.json'),{'exit_code':r.returncode,'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
 assert r.returncode==0,(stem,r.returncode)
 return (dest/(stem+'.stdout.txt')).read_text()
def main():
 compiler=subprocess.check_output(['rustc','-Vv'],text=True)
 names=['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_TARGET_DIR','CARGO_BUILD_TARGET','RUSTUP_TOOLCHAIN']
 names+=sorted(k for k in os.environ if k.startswith('CARGO_PROFILE_') or (k.startswith('CARGO_TARGET_') and k.endswith(('_RUSTFLAGS','_LINKER'))))
 environment={k:os.environ.get(k,'') for k in names}
 assert not any(os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_TARGET_DIR','CARGO_BUILD_TARGET'])
 identity=hashlib.sha256((sha(HERE/'probe.rs')+sha(__file__)+compiler+json.dumps(environment,sort_keys=True)).encode()).hexdigest()[:16]
 dest=ROOT/'libs/rustcrypto/build/resource-audit'/('prepared-'+identity);dest.mkdir(parents=True,exist_ok=False)
 logs=dest/'logs';logs.mkdir();bins=dest/'binaries';bins.mkdir();sources={}
 for side,commit in [('baseline',BASE),('candidate',HEAD)]:
  archive=subprocess.check_output(['git','-C',str(UPSTREAM),'archive',commit,'ml-dsa/src','ml-dsa/Cargo.toml','ml-dsa/README.md','Cargo.toml'])
  (dest/(side+'.tar')).write_bytes(archive);source=dest/side;source.mkdir()
  with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
   assert all(not t.name.startswith('/') and '..' not in Path(t.name).parts and (t.isfile() or t.isdir()) for t in tar.getmembers());tar.extractall(source)
  manifest=source/'ml-dsa/Cargo.toml';original=manifest.read_text();assert original.count('name = "ml-dsa"')==1
  manifest.write_text(original.replace('name = "ml-dsa"',f'name = "ml-dsa-{side}"\nworkspace = ".."',1))
  workspace=source/'Cargo.toml';original=workspace.read_text();lints=original[original.index('[workspace.lints.clippy]'):original.index('[patch.crates-io]')]
  workspace.write_text('[workspace]\nresolver="2"\nmembers=["ml-dsa"]\n'+lints);sources[side]=str(source)
 a=tree(dest/'baseline/ml-dsa/src');b=tree(dest/'candidate/ml-dsa/src');assert a.keys()==b.keys()
 assert [p for p in a if a[p]!=b[p]]==['signing.rs']
 (dest/'Cargo.toml').write_text('''[package]
name="mldsa-resource-audit"
version="0.0.0"
edition="2024"
[workspace]
exclude=["baseline","candidate"]
[features]
allocation=["baseline/alloc","candidate/alloc"]
zeroization=["baseline/zeroize","candidate/zeroize"]
library-default=["baseline/default","candidate/default"]
[dependencies]
baseline={package="ml-dsa-baseline",path="baseline/ml-dsa",default-features=false}
candidate={package="ml-dsa-candidate",path="candidate/ml-dsa",default-features=false}
serde_json="=1.0.150"
sha2="=0.10.9"
''')
 (dest/'src').mkdir();shutil.copyfile(HERE/'probe.rs',dest/'src/main.rs')
 lock=HERE.parent/'keygen.Cargo.lock';shutil.copyfile(lock,dest/'Cargo.lock')
 env=dict(os.environ,CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0'); modes={}
 for mode,features in MODES.items():
  print('Building '+mode,flush=True)
  cmd=['cargo','rustc','--offline','--release','--no-default-features','--features',','.join(features),'--','--emit=asm,link']
  if modes:cmd.insert(3,'--locked')
  run(cmd,logs,mode+'-build',dest,env)
  binary=bins/mode;shutil.copyfile(dest/'target/release/mldsa-resource-audit',binary);binary.chmod(0o755)
  asm=max((dest/'target/release/deps').glob('mldsa_resource_audit-*.s'),key=lambda p:p.stat().st_mtime_ns)
  shutil.copyfile(asm,bins/(mode+'.s'))
  output=run([str(binary),'check'],logs,mode+'-check');rows=[json.loads(line) for line in output.splitlines()];assert len(rows)==12
  for row in rows:assert row['exact_cross_variant'] and all(row[s]['exact_output_checked'] and row[s]['tamper_rejected'] for s in ['baseline','candidate'])
  modes[mode]={'features':features,'binary':str(binary),'binary_sha256':sha(binary),'assembly':str(bins/(mode+'.s')),'assembly_sha256':sha(bins/(mode+'.s')),'checks':rows}
 manifest={'schema':'rust-resource-prepared-v1','base':BASE,'head':HEAD,'compiler':compiler,'environment':environment,'build_jobs':2,'sources':sources,'modes':modes,
  'source_hashes':{s:tree(p) for s,p in sources.items()},'files':{str(p):sha(p) for p in [HERE/'probe.rs',Path(__file__),dest/'src/main.rs',dest/'Cargo.toml',dest/'Cargo.lock',dest/'baseline.tar',dest/'candidate.tar']}}
 write(dest/'manifest.json',manifest)
 evidence=ROOT/'results/rustcrypto/resource-audit';evidence.mkdir(parents=True,exist_ok=True);shutil.copytree(logs,evidence/dest.name);shutil.copyfile(dest/'manifest.json',evidence/(dest.name+'.json'))
 print(dest/'manifest.json')
if __name__=='__main__':main()
