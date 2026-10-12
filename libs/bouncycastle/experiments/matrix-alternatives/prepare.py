#!/usr/bin/env python3
"""Build and correctness-check alternatives; never collect timings or allocation counters."""
import sys
if sys.flags.optimize:
    raise RuntimeError('Python optimization disables required checks; run without -O')
import argparse, datetime, difflib, gzip, hashlib, io, json, os, shutil, subprocess, tarfile
from pathlib import Path
from variants import change, PACKAGE, VARIANTS, replace_once

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PIN = 'c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
RESULTS = ROOT/'results/bouncycastle/matrix-alternatives'
def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def tree(p, pattern): return {str(f.relative_to(p)):digest(f) for f in sorted(p.rglob(pattern)) if f.is_file()}
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def dump(path, data): path.write_text(json.dumps(data, indent=2)+'\n')
def run(args, log):
    args = list(map(str,args)); started=now(); r=subprocess.run(args,capture_output=True,text=True)
    log.write_text(r.stdout+r.stderr)
    record={'argv':args,'started_at':started,'completed_at':now(),'exit_code':r.returncode,'log':str(log),'log_sha256':digest(log)}
    if r.returncode: raise RuntimeError(record)
    return r.stdout,record
def extract(data, dest):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            if member.name.startswith('/') or '..' in Path(member.name).parts or not (member.isdir() or member.isfile()): raise ValueError(member.name)
            target=dest/member.name
            if member.isdir(): target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
def main():
    p=argparse.ArgumentParser();p.add_argument('--upstream',required=True);p.add_argument('--java-home',required=True);p.add_argument('--corpus-parent',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    dest=Path(a.out).resolve();dest.mkdir(parents=True,exist_ok=False);RESULTS.mkdir(parents=True,exist_ok=True)
    java=Path(a.java_home).resolve()/'bin/java';javac=java.with_name('javac')
    archive=subprocess.check_output(['git','-C',a.upstream,'archive',PIN,'core/src/main/java'])
    archive_path=RESULTS/'baseline-source.tar.gz';archive_path.write_bytes(gzip.compress(archive,mtime=0))
    m={'schema':'bc-matrix-preparation-v1','upstream':PIN,'started_at':now(),'java':str(java),'java_sha256':digest(java),'javac_sha256':digest(javac),'source_archive_sha256':digest(archive_path),'environment':{k:os.environ.get(k,'') for k in ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS']},'variants':{},'commands':[],'corpora':{}}
    for label in ['correctness','warmup','measured']:
        path=RESULTS/(label+'.bin');shutil.copyfile(Path(a.corpus_parent)/(label+'.bin'),path)
        m['corpora'][label]={'path':str(path),'sha256':digest(path),'keys_per_parameter':{'correctness':12,'warmup':32,'measured':128}[label]}
    m['java_version'],record=run([java,'-version'],RESULTS/'java-version.log');m['commands'].append(record)
    entries=['crypto/signers/MLDSASigner.java','crypto/signers/HashMLDSASigner.java','crypto/generators/MLDSAKeyPairGenerator.java']
    for variant in VARIANTS:
        source=dest/(variant+'-src');source.mkdir();extract(archive,source);change(source,variant)
        classes=dest/variant;classes.mkdir();main=source/'core/src/main/java'
        _,record=run([javac,'--release','8','-sourcepath',main,'-d',classes,*[main/'org/bouncycastle'/e for e in entries]],RESULTS/(variant+'-build.log'));m['commands'].append(record)
        _,record=run([javac,'-cp',classes,'-d',classes,*[HERE/n for n in ['MLDeep.java','MatrixBench.java','MalformedCheck.java']]],RESULTS/(variant+'-driver-build.log'));m['commands'].append(record)
        gates={}
        for label in ['correctness','measured']:
            output,record=run([java,'-Xmx512m','-XX:ActiveProcessorCount=2','-cp',classes,'org.bouncycastle.crypto.signers.mldsa.MLDeep','check',m['corpora'][label]['path']],RESULTS/(variant+'-'+label+'-gate.log'));m['commands'].append(record)
            gates[label]=json.loads(output)
            count=72 if label=='correctness' else 384
            assert gates[label]['operation_checks']==6*count and gates[label]['negative_checks']==4*count
        output,record=run([java,'-Xmx512m','-XX:ActiveProcessorCount=2','-cp',classes,'org.bouncycastle.crypto.signers.mldsa.MalformedCheck',m['corpora']['correctness']['path']],RESULTS/(variant+'-malformed-gate.log'));m['commands'].append(record)
        gates['malformed']=json.loads(output);assert gates['malformed']=={'cases':72,'checks':936,'ownership':True}
        gate_src=dest/(variant+'-gate-src');gate_src.mkdir();gate_classes=dest/(variant+'-gate');gate_classes.mkdir()
        s=(source/PACKAGE/'Reduce.java').read_text();s=replace_once(s,'class Reduce\n{','class Reduce\n{\n    static long probeCalls;');s=replace_once(s,'        int t;\n        t = (int)(a *','        probeCalls++;\n        int t;\n        t = (int)(a *');(gate_src/'Reduce.java').write_text(s)
        s=(source/PACKAGE/'Poly.java').read_text();s=replace_once(s,'class Poly\n{','class Poly\n{\n    static long probeObjects;');s=replace_once(s,'    public Poly(MLDSAEngine engine)\n    {','    public Poly(MLDSAEngine engine)\n    {\n        probeObjects++;');(gate_src/'Poly.java').write_text(s)
        _,record=run([javac,'--release','8','-cp',classes,'-d',gate_classes,*sorted(gate_src.glob('*.java')),HERE/'MatrixCheck.java'],RESULTS/(variant+'-matrix-gate-build.log'));m['commands'].append(record)
        output,record=run([java,'-Xmx512m','-XX:ActiveProcessorCount=2','-cp',str(gate_classes)+os.pathsep+str(classes),'org.bouncycastle.crypto.signers.mldsa.MatrixCheck',str(variant in ['lazy','combined']).lower(),str(variant in ['stream','combined']).lower()],RESULTS/(variant+'-matrix-gate.log'));m['commands'].append(record)
        gates['matrix']=json.loads(output);assert gates['matrix']['arithmetic_coefficients']==18432 and gates['matrix']['stream_cases']==6
        src=tree(source,'*.java');bins=tree(classes,'*.class')
        m['variants'][variant]={'source_path':str(source),'classes':str(classes),'source':src,'binaries':bins,'gates':gates,'instrumented_gate_classes':str(gate_classes),'instrumented_binaries':tree(gate_classes,'*.class')}
        baseline=m['variants']['baseline']['source']
        changed=[f for f,h in src.items() if baseline[f]!=h]
        wanted=[] if variant=='baseline' else ['Poly.java'] if variant=='lazy' else ['PolyVecMatrix.java','MLDSAEngine.java'] if variant=='stream' else ['Poly.java','PolyVecMatrix.java','MLDSAEngine.java']
        assert sorted(changed)==sorted(str(PACKAGE/f) for f in wanted),(variant,changed)
        m['variants'][variant]['changed_files']=changed
        patch=[]
        for name in changed:
            before=(dest/'baseline-src'/name).read_text().splitlines(keepends=True);after=(source/name).read_text().splitlines(keepends=True)
            patch+=difflib.unified_diff(before,after,fromfile='a/'+name,tofile='b/'+name)
        (RESULTS/(variant+'.patch')).write_text(''.join(patch))
        print(variant+' correctness gates passed',flush=True)
    assert len({json.dumps(x['source'],sort_keys=True) for x in m['variants'].values()})==4
    assert len({json.dumps(x['binaries'],sort_keys=True) for x in m['variants'].values()})==4
    m['inputs']={str(p.relative_to(ROOT)):digest(p) for p in sorted(HERE.glob('*')) if p.is_file()}
    m['completed_at']=now();dump(RESULTS/'prepared.json',m);print(RESULTS/'prepared.json')
if __name__=='__main__':main()
