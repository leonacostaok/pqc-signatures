#!/usr/bin/env python3
"""Freeze independent NTT variants and correctness evidence. Never measures performance."""
import argparse,datetime,difflib,gzip,hashlib,io,json,os,platform,re,shutil,subprocess,sys,tarfile
from pathlib import Path
if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
    raise RuntimeError('Python optimization is forbidden, including PYTHONOPTIMIZE')
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
PIN='c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
PACKAGE='core/src/main/java/org/bouncycastle/crypto/signers/mldsa'
VARIANTS=['baseline','fused','companion','both']
PARAMETERS=['ml_dsa_44','ml_dsa_65','ml_dsa_87']
JVM=['-Xms64m','-Xmx512m','-XX:ActiveProcessorCount=2','-XX:+UseG1GC']
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def tree(p,suffix):return {str(x.relative_to(p)):digest(x)for x in sorted(Path(p).rglob('*'+suffix))if x.is_file()}
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def hmap(o):return hashlib.sha256(json.dumps(o,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def write(p,value):
    with Path(p).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
def run(command,logs,stem,cwd=None):
    command=list(map(str,command));write(logs/(stem+'.command.json'),{'argv':command,'cwd':str(cwd)if cwd else None,'started_at':stamp()})
    with (logs/(stem+'.stdout')).open('x')as out,(logs/(stem+'.stderr')).open('x')as err:r=subprocess.run(command,cwd=cwd,stdout=out,stderr=err)
    write(logs/(stem+'.status.json'),{'exit_code':r.returncode,'completed_at':stamp()})
    if r.returncode:raise RuntimeError('command failed; retained logs: '+stem)
    return (logs/(stem+'.stdout')).read_text()
def modify(original,variant):
    s=original
    if variant in ['fused','both']:
        s=s.replace('for (len = 1; len < MLDSAEngine.DilithiumN; len <<= 1)','for (len = 1; len < 128; len <<= 1)')
        old='''        for (j = 0; j < MLDSAEngine.DilithiumN; ++j)
        {
            out[j] = Reduce.montgomeryReduce((long)((long)f * (long)out[j]));
        }'''
        new='''        // Combine the last twiddle with f: MontgomeryReduce(f * -25847) = 3975713.
        // Inputs satisfy |x| < q. The last sum/difference is below 256*q < 2^31;
        // outputs remain in (-q, q), though their signed representatives may differ.
        for (j = 0; j < 128; ++j)
        {
            int a = out[j], b = out[j + 128];
            out[j] = Reduce.montgomeryReduce(41978L * (a + b));
            out[j + 128] = Reduce.montgomeryReduce(3975713L * (a - b));
        }'''
        assert s.count(old)==1;s=s.replace(old,new)
    if variant in ['companion','both']:
        zetas=list(map(int,re.search(r'nttZetas = \{(.*?)\};',s,re.S).group(1).replace('\n','').split(',')))
        vals=[((z*58728449+(1<<31))%(1<<32))-(1<<31)for z in zetas]
        table='\n    // Low-word Montgomery companions for the fixed public twiddles.\n    private static final int[] nttZetasQInv = {\n'
        table+='\n'.join('        '+', '.join(map(str,vals[i:i+8]))+(','if i+8<len(vals)else'')for i in range(0,len(vals),8))+'\n    };\n\n'
        table+='''    private static int multiplyTwiddle(int x, int zeta, int zetaQInv)
    {
        int t = x * zetaQInv;
        return (int)(((long)x * zeta - (long)t * MLDSAEngine.DilithiumQ) >>> 32);
    }
'''
        token='    static void ntt(int[] r)';assert s.count(token)==1;s=s.replace(token,table+'\n'+token)
        s=s.replace('zeta = nttZetas[++k];','zeta = nttZetas[++k];\n                int zetaQInv = nttZetasQInv[k];')
        s=s.replace('zeta = (-1) * nttZetas[--k];','zeta = (-1) * nttZetas[--k];\n                int zetaQInv = -nttZetasQInv[k];')
        s=s.replace('Reduce.montgomeryReduce(((long)zeta * (long)r[j + len]))','multiplyTwiddle(r[j + len], zeta, zetaQInv)')
        s=s.replace('Reduce.montgomeryReduce((long)((long)zeta * (long)out[j + len]))','multiplyTwiddle(out[j + len], zeta, zetaQInv)')
        s=s.replace('Reduce.montgomeryReduce((long)((long)f * (long)out[j]))','multiplyTwiddle(out[j], f, -8395782)')
        s=s.replace('Reduce.montgomeryReduce(41978L * (a + b))','multiplyTwiddle(a + b, 41978, -8395782)')
        s=s.replace('Reduce.montgomeryReduce(3975713L * (a - b))','multiplyTwiddle(a - b, 3975713, 151046689)')
        assert 'Reduce.montgomeryReduce'not in s
    return s

def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',required=True);p.add_argument('--old-manifest',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False);logs=out/'logs';logs.mkdir();build=ROOT/'results/bouncycastle/ntt-alternatives/.build'/out.name;build.mkdir(parents=True,exist_ok=False)
    inputs={str(p.relative_to(ROOT)):digest(p)for p in sorted(HERE.glob('*'))if p.is_file()and p.suffix in ['.py','.java']}
    oldpath=Path(a.old_manifest).resolve();old=json.loads(oldpath.read_text());assert old['upstream']==PIN
    java=Path(old['java']).resolve();assert digest(java)==old['java_sha256']
    archive=subprocess.check_output(['git','-C',a.upstream,'archive',PIN,'core/src/main/java']);(out/'baseline-source.tar.gz').write_bytes(gzip.compress(archive,mtime=0))
    fixtures=out/'fixtures';fixtures.mkdir();corpora={}
    for label,expected,source in [('correctness',old['correctness_corpus_sha256'],oldpath.parent/'correctness.bin')]+[(label,old['corpora'][label]['sha256'],Path(old['corpora'][label]['path']))for label in ['warmup','measured']]:
        assert digest(source)==expected;target=fixtures/(label+'.bin');shutil.copy2(source,target);corpora[label]={'path':str(target),'sha256':expected}
    driver=build/'driver';driver.mkdir();m={'schema':'bc-ntt-prepared-v1','upstream':PIN,'created_at':stamp(),'source_archive':str(out/'baseline-source.tar.gz'),'source_archive_sha256':digest(out/'baseline-source.tar.gz'),'parent_manifest':{'path':str(oldpath),'sha256':digest(oldpath)},'inputs':inputs,'java':str(java),'jvm_args':JVM,'corpora':corpora,'variants':{},'environment':{k:os.environ.get(k,'')for k in ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH','PYTHONOPTIMIZE']},'machine':{'system':platform.system(),'release':platform.release(),'machine':platform.machine()}}
    javahome=java.parent.parent;m['runtime_files']={str(p):digest(p)for p in [java,java.with_name('javac'),javahome/'release',javahome/'lib/modules',javahome/'lib/server/libjvm.dylib']}
    basehash=None;baseclasses=None
    for variant in VARIANTS:
        source=build/(variant+'-src');source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive))as t:
            assert all(not x.name.startswith('/')and '..'not in Path(x.name).parts and(x.isfile()or x.isdir())for x in t.getmembers());t.extractall(source)
        ntt=source/PACKAGE/'Ntt.java';original=ntt.read_text();ntt.write_text(modify(original,variant))
        overlay=out/'overlays'/variant;overlay.mkdir(parents=True);shutil.copy2(ntt,overlay/'Ntt.java')
        (overlay/'change.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),ntt.read_text().splitlines(True),fromfile='a/'+PACKAGE+'/Ntt.java',tofile='b/'+PACKAGE+'/Ntt.java')))
        classes=build/variant;classes.mkdir();main=source/'core/src/main/java';entries=[main/('org/bouncycastle/'+s)for s in ['crypto/signers/MLDSASigner.java','crypto/signers/HashMLDSASigner.java','crypto/generators/MLDSAKeyPairGenerator.java']]
        run([java.with_name('javac'),'-J-XX:ActiveProcessorCount=2','--release','8','-sourcepath',main,'-d',classes,*entries],logs,variant+'-build')
        sh=tree(source,'.java');ch=tree(classes,'.class')
        if variant=='baseline':
            basehash=sh;baseclasses=ch
            run([java.with_name('javac'),'-J-XX:ActiveProcessorCount=2','-cp',classes,'-d',driver,*sorted(HERE.glob('*.java'))],logs,'driver-build')
        else:
            assert [k for k in sh if sh[k]!=basehash[k]]==[PACKAGE+'/Ntt.java']
            assert set(ch)==set(baseclasses)and[k for k in ch if ch[k]!=baseclasses[k]]==['org/bouncycastle/crypto/signers/mldsa/Ntt.class']
        cp=os.pathsep.join([str(driver),str(classes)])
        arithmetic=json.loads(run([java,*JVM,'-cp',cp,'org.bouncycastle.crypto.signers.mldsa.NTTGate'],logs,variant+'-arithmetic'))
        assert arithmetic['passed']and arithmetic['reductions']==2313 and arithmetic['forward_vectors']==516 and arithmetic['inverse_vectors']==516 and arithmetic['sparse_products']==108
        correctness=json.loads(run([java,*JVM,'-cp',cp,'org.bouncycastle.crypto.signers.mldsa.MLDeep','check',corpora['correctness']['path']],logs,variant+'-correctness'))
        assert correctness=={'operation_checks':432,'negative_checks':288,'inputs_preserved':True}
        info={'source':str(source),'classes':str(classes),'source_hashes':sh,'class_hashes':ch,'source_identity':hmap(sh),'class_identity':hmap(ch),'arithmetic':arithmetic,'correctness':correctness}
        malformed=HERE/'MalformedCheck.java'
        if malformed.exists():info['malformed']=json.loads(run([java,*JVM,'-cp',cp,'org.bouncycastle.crypto.signers.mldsa.MalformedCheck',corpora['correctness']['path']],logs,variant+'-malformed'))
        m['variants'][variant]=info;print('Checked '+variant,flush=True)
    assert len({x['source_identity']for x in m['variants'].values()})==4 and len({x['class_identity']for x in m['variants'].values()})==4
    m['driver']={'path':str(driver),'class_hashes':tree(driver,'.class')};m['java_version']=run([java,'-version'],logs,'java-version')+(logs/'java-version.stderr').read_text()
    run([sys.executable,HERE/'arithmetic_oracle.py',Path(m['variants']['baseline']['source'])/PACKAGE/'Ntt.java'],logs,'python-oracle')
    assert inputs=={str(p.relative_to(ROOT)):digest(p)for p in sorted(HERE.glob('*'))if p.is_file()and p.suffix in ['.py','.java']},'driver source changed during preparation'
    m['portable_hashes']=tree(out,'.java')|tree(out,'.patch');m['completed_at']=stamp();write(out/'manifest.json',m);print(out/'manifest.json')
if __name__=='__main__':main()
