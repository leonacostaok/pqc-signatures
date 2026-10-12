#!/usr/bin/env python3
import datetime,hashlib,io,json,os,shutil,subprocess,sys,tarfile
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('run without -O')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];WORKTREES=ROOT.parent;UP=Path('/Users/dandelionlabs/development/personal/bc-java');PIN='c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
JVM=['-Xms64m','-Xmx512m','-XX:ActiveProcessorCount=2','-XX:+UseG1GC'];SLH=[f'{f}_{n}{s}'for f in ['sha2','shake']for n in [128,192,256]for s in ['f','s']];ML=['ml_dsa_'+str(n)for n in [44,65,87]];FALCON=['falcon_512','falcon_1024']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def tree(p,suffix):return {str(f.relative_to(p)):sha(f)for f in sorted(Path(p).rglob('*'+suffix))if f.is_file()}
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write(p,v):
 with Path(p).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def run(cmd,dest,stem,cwd=None):
 cmd=list(map(str,cmd));write(dest/(stem+'.command.json'),{'command':cmd,'cwd':str(cwd),'started_at':stamp()})
 with (dest/(stem+'.stdout.txt')).open('x')as o,(dest/(stem+'.stderr.txt')).open('x')as e:r=subprocess.run(cmd,cwd=cwd,stdout=o,stderr=e)
 write(dest/(stem+'.status.json'),{'exit_code':r.returncode,'finished_at':stamp()});assert r.returncode==0,(stem,r.returncode)
 return (dest/(stem+'.stdout.txt')).read_text()
def command(m,side,mode,p,op,warm,cycles):return [m['java'],*JVM,'-cp',os.pathsep.join([m['driver'],m['classes'][side],m['classes']['baseline']]),'CompletionProbe',mode,p,side,m['fixture'],op,str(warm),str(cycles)]
def proof(rows):return [{k:r[k]for k in ['parameter','operation','index','cycle','output_sha256','checked']}for r in rows if r['type']=='sample']
def main():
 files=[HERE/'CompletionProbe.java',Path(__file__)];initial={str(p):sha(p)for p in files};identity=hashlib.sha256(json.dumps(initial,sort_keys=True).encode()).hexdigest()[:16];dest=ROOT/'libs/bouncycastle/build/completion'/('prepared-'+identity);dest.mkdir(parents=True,exist_ok=False);logs=dest/'logs';logs.mkdir()
 oldpaths={'fors':WORKTREES/'bc-performance/libs/bouncycastle/build/fors-base2b/prepared-38afeddcb55e90be/manifest.json','wots':WORKTREES/'bc-slh-deep/libs/bouncycastle/build/slh-deep/prepared-c8eeabbff5cec835/manifest.json','sampling':WORKTREES/'bc-ml-deep/libs/bouncycastle/build/ml-deep/prepared-v6/manifest.json'}
 old={k:json.loads(p.read_text())for k,p in oldpaths.items()};java=Path(old['fors']['java']);assert old['fors']['upstream_commit']==PIN and old['wots']['upstream_commit']==PIN and old['sampling']['upstream']==PIN
 data=subprocess.check_output(['git','-C',str(UP),'archive',PIN,'core/src/main/java']);(dest/'baseline.tar').write_bytes(data);source=dest/'baseline-src';source.mkdir()
 with tarfile.open(fileobj=io.BytesIO(data))as t:
  assert all(not x.name.startswith('/')and'..'not in Path(x.name).parts and(x.isfile()or x.isdir())for x in t.getmembers());t.extractall(source)
 classes=dest/'baseline';classes.mkdir();main=source/'core/src/main/java';entries=['crypto/generators/'+n+'KeyPairGenerator.java'for n in ['MLDSA','SLHDSA']]+['crypto/signers/'+n+'Signer.java'for n in ['MLDSA','SLHDSA']]+['pqc/crypto/falcon/FalconKeyPairGenerator.java','pqc/crypto/falcon/FalconSigner.java']
 run([java.with_name('javac'),'-J-XX:ActiveProcessorCount=2','--release','8','-sourcepath',main,'-d',classes,*[main/('org/bouncycastle/'+n)for n in entries]],logs,'compile')
 driver=dest/'driver';driver.mkdir();run([java.with_name('javac'),'-J-XX:ActiveProcessorCount=2','--release','8','-cp',classes,'-d',driver,HERE/'CompletionProbe.java'],logs,'driver')
 fixture=Path(old['wots']['fixtures']);m={'schema':'bc-completion-prepared-v1','base':PIN,'java':str(java),'jvm_args':JVM,'fixture':str(fixture),'driver':str(driver),'classes':{'baseline':str(classes),'fors':old['fors']['candidate'],'wots':old['wots']['classes']['candidate'],**{v:old['sampling']['variants'][v]['classes']for v in ['matrix','gamma','combined']}},'old_manifests':{k:{'path':str(p),'sha256':sha(p)}for k,p in oldpaths.items()},'checks':{},'environment':{k:os.environ.get(k,'')for k in ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS']}}
 # Retain exact reused source and bytecode bindings; source snapshots are read only.
 m['source_paths']={'baseline':str(source),'fors':str(Path(old['fors']['candidate']).parent/'candidate-src'),'wots':old['wots']['sources']['candidate'],**{v:str(Path(old['sampling']['variants'][v]['classes']).parent/(v+'-src'))for v in ['matrix','gamma','combined']}}
 m['source_hashes']={v:tree(p,'.java')for v,p in m['source_paths'].items()};m['class_hashes']={v:tree(p,'.class')for v,p in m['classes'].items()};m['driver_hashes']=tree(driver,'.class')
 assert all(m['source_hashes'].values())and all(m['class_hashes'].values())
 for side,params,ops in [('baseline',ML+FALCON,'all'),('baseline',SLH,'verify'),('baseline',['sha2_128f','shake_128f'],'all'),('fors',SLH,'verify'),('wots',['sha2_128f','shake_128f'],'all')]+[(v,ML,'all')for v in ['matrix','gamma','combined']]:
  for p in params:
   stem=side+'-'+p+'-'+ops;print('Checking '+stem,flush=True);rows=[json.loads(x)for x in run(command(m,side,'check',p,ops,0,1),logs,stem).splitlines()];checks=proof(rows);assert len(checks)==(36 if ops=='all'else 12)and all(r['checked']for r in checks);assert all(r['class_source']==m['classes'][side]for r in rows if r['type']=='sample');m['checks'][stem]=checks
 for side in ['matrix','gamma','combined','wots','fors']:
  for key,checks in list(m['checks'].items()):
   if key.startswith(side+'-'):assert checks==m['checks']['baseline'+key[len(side):]],key
 assert initial=={p:sha(p)for p in initial},'source changed during preparation';m['files']={str(p):sha(p)for p in files+[fixture,dest/'baseline.tar',java,java.parent.parent/'release']};m['java_version']=subprocess.run([java,'-version'],capture_output=True,text=True,check=True).stderr;write(dest/'manifest.json',m);print(dest/'manifest.json')
if __name__=='__main__':main()
