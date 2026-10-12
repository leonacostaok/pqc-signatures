#!/usr/bin/env python3
import argparse, hashlib, io, json, subprocess, tarfile, shutil, os
from instrument import instrument
from pathlib import Path
import sys
if sys.flags.optimize:
    raise RuntimeError("Python optimization disables required checks; run without -O")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PIN = 'c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
PACKAGE = 'core/src/main/java/org/bouncycastle/crypto/signers/mldsa'
def run(args, log):
    result = subprocess.run(list(map(str,args)), capture_output=True, text=True)
    log.write_text('$ ' + ' '.join(map(str,args)) + '\n' + result.stdout + result.stderr)
    if result.returncode: raise RuntimeError(str(log))
    return result.stdout
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def tree(p, glob):
    return {str(x.relative_to(p)):digest(x) for x in sorted(p.rglob(glob)) if x.is_file()}
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream', required=True);p.add_argument('--java-home',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    dest=Path(a.out).resolve();dest.mkdir(parents=True,exist_ok=False)
    java=Path(a.java_home)/'bin/java';javac=Path(a.java_home)/'bin/javac'
    patch=HERE.parents[1]/'patches/ml-deep/sampling-buffers.patch'
    archive=subprocess.check_output(['git','-C',a.upstream,'archive',PIN,'core/src/main/java'])
    manifest={'upstream':PIN,'java':str(java),'variants':{},'inputs':{str(p.relative_to(ROOT)):digest(p) for p in [patch,*HERE.glob('*.java'),*HERE.glob('*.py')]}}
    for variant in ['baseline','matrix','gamma','combined']:
        source=dest/(variant+'-src');source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as t:
            for m in t.getmembers():
                assert not m.name.startswith('/') and '..' not in Path(m.name).parts and (m.isfile() or m.isdir())
            t.extractall(source)
        if variant!='baseline':
            run(['git','-C',source,'init','-q'],dest/(variant+'-init.log'))
            run(['git','-C',source,'apply','--check',patch],dest/(variant+'-patch-check.log'))
            run(['git','-C',source,'apply',patch],dest/(variant+'-patch.log'))
            run(['git','-C',source,'apply','--reverse','--check',patch],dest/(variant+'-patch-reverse-check.log'))
            v=source/PACKAGE/'PolyVec.java';s=v.read_text()
            if variant=='matrix':
                s=s.replace('        byte[] buf = vec[0].createGamma1Buffer();\n','').replace('vec[i].uniformGamma1(seed, (short)(vec.length * nonce + i), buf);','vec[i].uniformGamma1(seed, (short)(vec.length * nonce + i));')
            if variant=='gamma':
                s=s.replace('void uniformBlocks(byte[] rho, int t, byte[] buf)','void uniformBlocks(byte[] rho, int t)').replace('vec[i].uniformBlocks(rho, (short)(t + i), buf);','vec[i].uniformBlocks(rho, (short)(t + i));')
                m=source/PACKAGE/'PolyVecMatrix.java';s2=m.read_text().replace('        byte[] buf = matrix[0].getVectorIndex(0).createUniformBuffer();\n','').replace('matrix[i].uniformBlocks(rho, i << 8, buf);','matrix[i].uniformBlocks(rho, i << 8);');m.write_text(s2)
            v.write_text(s)
        classes=dest/variant;classes.mkdir()
        main=source/'core/src/main/java'
        entries=[main/('org/bouncycastle/'+s) for s in ['crypto/signers/MLDSASigner.java','crypto/signers/HashMLDSASigner.java','crypto/generators/MLDSAKeyPairGenerator.java']]
        run([javac,'--release','8','-sourcepath',main,'-d',classes,*entries],dest/(variant+'-build.log'))
        run([javac,'-cp',classes,'-d',classes,*HERE.glob('*.java')],dest/(variant+'-driver-build.log'))
        gate=run([java,'-Xmx512m','-XX:ActiveProcessorCount=2','-cp',classes,'org.bouncycastle.crypto.signers.mldsa.SamplingCheck',str(variant in ['matrix','combined']).lower(),str(variant in ['gamma','combined']).lower()],dest/(variant+'-gate.log'))
        result=json.loads(gate);assert result['checks']>=100
        manifest['variants'][variant]={'classes':str(classes),'source':tree(source,'*.java'),'binaries':tree(classes,'*.class'),'gate':result}
    assert len({json.dumps(x['source'],sort_keys=True) for x in manifest['variants'].values()})==4
    assert len({json.dumps(x['binaries'],sort_keys=True) for x in manifest['variants'].values()})==4
    baseline = dest/'baseline'
    command = [java,'-Xmx512m','-XX:ActiveProcessorCount=2','-cp',baseline,'org.bouncycastle.crypto.signers.mldsa.MLDeep']
    correctness = dest/'correctness.bin'
    run(command+['emit',correctness,'12','correctness', 'true'],dest/'corpus-build.log')
    for variant in manifest['variants']:
        output = run([java,'-Xmx512m','-XX:ActiveProcessorCount=2','-cp',dest/variant,'org.bouncycastle.crypto.signers.mldsa.MLDeep','check',correctness],dest/(variant+'-correctness.log'))
        result = json.loads(output)
        assert result['operation_checks'] == 432 and result['negative_checks'] == 288
        manifest['variants'][variant]['correctness'] = result
    failed = subprocess.run(list(map(str,[java,'-cp',baseline,'org.bouncycastle.crypto.signers.mldsa.SamplingCheck','true','true'])),capture_output=True,text=True)
    (dest/'baseline-resource-red.log').write_text(failed.stdout+failed.stderr)
    assert failed.returncode != 0 and 'matrix buffer count' in failed.stderr
    failed = subprocess.run(list(map(str,[java,'-cp',baseline,'org.bouncycastle.crypto.signers.mldsa.SamplingCheck','false','true'])),capture_output=True,text=True)
    (dest/'baseline-gamma-resource-red.log').write_text(failed.stdout+failed.stderr)
    assert failed.returncode != 0 and 'gamma buffer count' in failed.stderr
    manifest['correctness_corpus_sha256'] = digest(correctness)
    baseline_sources=manifest['variants']['baseline']['source']
    for variant,info in manifest['variants'].items():
        changed=[n for n,h in info['source'].items() if baseline_sources[n]!=h]
        expected=[] if variant=='baseline' else [PACKAGE+'/'+n for n in (['Poly.java','PolyVec.java'] if variant=='gamma' else ['Poly.java','PolyVec.java','PolyVecMatrix.java'])]
        assert sorted(changed)==sorted(expected), (variant,changed)
        info['changed_source_files']=changed
    manifest['corpora']={}
    for label,count in [('warmup',32),('measured',128)]:
        corpus=dest/(label+'.bin')
        run(command+['emit',corpus,str(count),label,'false'],dest/(label+'-build.log'))
        manifest['corpora'][label]={'path':str(corpus),'sha256':digest(corpus),'keys_per_parameter':count}
    manifest['profiles']={}
    for variant in ['baseline','combined']:
        source=dest/(variant+'-profile-src');shutil.copytree(dest/(variant+'-src'),source,ignore=shutil.ignore_patterns('.git'))
        instrument(source)
        shutil.copy2(HERE/'StageProfile.java',source/PACKAGE/'StageProfile.java')
        classes=dest/(variant+'-profile');classes.mkdir()
        main=source/'core/src/main/java'
        entries=[main/('org/bouncycastle/'+n) for n in ['crypto/signers/MLDSASigner.java','crypto/signers/HashMLDSASigner.java','crypto/generators/MLDSAKeyPairGenerator.java']]
        run([javac,'--release','8','-sourcepath',main,'-d',classes,*entries],dest/(variant+'-profile-build.log'))
        run([javac,'-cp',classes,'-d',classes,*HERE.glob('*.java')],dest/(variant+'-profile-driver.log'))
        result=json.loads(run([java,'-Xmx512m','-XX:ActiveProcessorCount=2','-cp',classes,'org.bouncycastle.crypto.signers.mldsa.MLDeep','check',correctness],dest/(variant+'-profile-check.log')))
        assert result['operation_checks']==432 and result['negative_checks']==288
        manifest['profiles'][variant]={'classes':str(classes),'source':tree(source,'*.java'),'binaries':tree(classes,'*.class'),'correctness':result}
    manifest['environment']={k:os.environ.get(k,'') for k in ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS']}

    run([java,'-version'],dest/'java-version.log')
    manifest['java_version'] = (dest/'java-version.log').read_text()
    manifest['java_sha256'] = digest(java.resolve())
    (dest/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(dest/'manifest.json')
if __name__=='__main__':main()
