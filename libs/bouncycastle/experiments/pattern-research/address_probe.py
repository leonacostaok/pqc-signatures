#!/usr/bin/env python3
"""Bounded, fresh-process ADRS-hoisting screen; never changes a sealed prior build."""
import argparse, datetime, difflib, hashlib, json, os, shutil, statistics, subprocess, tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BUILD = ROOT/'libs/bouncycastle/build/pattern-research'
OUT = ROOT/'results/bouncycastle/pattern-research/address'
PACKAGE = 'org/bouncycastle/crypto/signers/slhdsa'
PARAMETERS = ['sha2_128f', 'shake_128f']
OPERATIONS = ['keygen.total', 'sign.total', 'verify.total']

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write(p,d):
    with Path(p).open('x') as f: json.dump(d,f,indent=2); f.write('\n')
def tree(p): return {str(f.relative_to(p)):sha(f) for f in sorted(p.rglob('*.class'))}
def run(command, stem):
    write(OUT/(stem+'.command.json'),dict(command=list(map(str,command)),started_at=stamp()))
    with (OUT/(stem+'.stdout.jsonl')).open('x') as out, (OUT/(stem+'.stderr.txt')).open('x') as err:
        result=subprocess.run(list(map(str,command)),stdout=out,stderr=err)
    write(OUT/(stem+'.status.json'),dict(exit_code=result.returncode,finished_at=stamp()))
    if result.returncode: raise RuntimeError(stem+' failed; logs retained')
    return [json.loads(s) for s in (OUT/(stem+'.stdout.jsonl')).read_text().splitlines()]

def modified(source):
    # Only local address setup changes. Every hash input is checked by the trace oracle.
    old='''        byte[][] tmp = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            ADRS adrs = new ADRS(paramAdrs);
            adrs.setTypeAndClear(ADRS.WOTS_PRF);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);

            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);

            adrs.setTypeAndClear(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            tmp[i] = chain(sk, 0, w - 1, pkSeed, adrs);
        }'''
    setup='''        ADRS prfAdrs = new ADRS(paramAdrs);
        prfAdrs.setTypeAndClear(ADRS.WOTS_PRF);
        prfAdrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
        ADRS hashAdrs = new ADRS(paramAdrs);
        hashAdrs.setTypeAndClear(ADRS.WOTS_HASH);
        hashAdrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
'''
    new=setup+'''        byte[][] tmp = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            prfAdrs.setChainAddress(i);
            byte[] sk = engine.PRF(pkSeed, skSeed, prfAdrs);
            hashAdrs.setChainAddress(i);
            hashAdrs.setHashAddress(0);
            tmp[i] = chain(sk, 0, w - 1, pkSeed, hashAdrs);
        }'''
    assert source.count(old)==1
    source=source.replace(old,new)
    old='''        byte[][] sig = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            adrs.setTypeAndClear(ADRS.WOTS_PRF);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            byte[] sk = engine.PRF(pkSeed, skSeed, adrs);
            adrs.setTypeAndClear(ADRS.WOTS_HASH);
            adrs.setKeyPairAddress(paramAdrs.getKeyPairAddress());
            adrs.setChainAddress(i);
            adrs.setHashAddress(0);
            sig[i] = chain(sk, 0, msg[i], pkSeed, adrs);
        }'''
    new=setup+'''        byte[][] sig = new byte[engine.WOTS_LEN][];
        for (int i = 0; i < engine.WOTS_LEN; i++)
        {
            prfAdrs.setChainAddress(i);
            byte[] sk = engine.PRF(pkSeed, skSeed, prfAdrs);
            hashAdrs.setChainAddress(i);
            hashAdrs.setHashAddress(0);
            sig[i] = chain(sk, 0, msg[i], pkSeed, hashAdrs);
        }'''
    assert source.count(old)==1
    source=source.replace(old,new)
    source=source.replace('''        ADRS adrs = new ADRS(paramAdrs);

        int[] msg''','''        int[] msg''',1)
    return source

def prepare(path):
    original=json.loads(path.read_text()); assert original['upstream_commit']=='c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
    old_classes=tree(Path(original['classes']['baseline'])); sealed=hashlib.sha256()
    for name,digest in old_classes.items(): sealed.update(name.encode()+b'\0'+bytes.fromhex(digest))
    assert sealed.hexdigest()==original['provenance']['classes']['baseline']
    BUILD.mkdir(parents=True,exist_ok=False); OUT.mkdir(parents=True,exist_ok=False)
    preparation=OUT/'preparation'; preparation.mkdir()
    source=Path(original['sources']['baseline'])/'core/src/main/java'/PACKAGE/'WotsPlus.java'
    baseline=source.read_text(); candidate=modified(baseline)
    with tarfile.open(path.parent/'baseline-source.tar') as archive:
        assert archive.extractfile('core/src/main/java/'+PACKAGE+'/WotsPlus.java').read()==source.read_bytes()
    for name,text in [('baseline-WotsPlus.java',baseline),('candidate-WotsPlus.java',candidate)]:
        (preparation/name).write_text(text)
    (preparation/'address-hoist.patch').write_text(''.join(difflib.unified_diff(baseline.splitlines(True),candidate.splitlines(True),fromfile='a/core/src/main/java/'+PACKAGE+'/WotsPlus.java',tofile='b/core/src/main/java/'+PACKAGE+'/WotsPlus.java')))
    shutil.copyfile(original['fixtures'],preparation/'fixtures.tsv')
    driver=ROOT/'libs/bouncycastle/experiments/slh-deep/SlhDeepProbe.java'
    java=Path(original['java']); javac=java.with_name('javac')
    manifest=dict(schema='bc-address-screen-v1',upstream_commit=original['upstream_commit'],parent_manifest_sha256=sha(path),parent_manifest=str(path),java=str(java),java_sha256=sha(java),jvm_args=['-Xmx512m','-XX:ActiveProcessorCount=2'],environment={k:os.environ.get(k,'') for k in ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS']},source_sha256=sha(source),fixtures=str(preparation/'fixtures.tsv'),classes={},drivers={},files={str(p):sha(p) for p in [Path(__file__),HERE/'AddressTrace.java',driver,preparation/'baseline-WotsPlus.java',preparation/'candidate-WotsPlus.java',preparation/'fixtures.tsv']})
    # Frozen copied class trees differ in WotsPlus only; no overlays or shared mutable builds.
    for side in ['baseline','candidate']:
        classes=BUILD/(side+'-classes'); shutil.copytree(original['classes']['baseline'],classes)
        sources=BUILD/(side+'-source'); sources.mkdir(); (sources/'WotsPlus.java').write_text(baseline if side=='baseline' else candidate)
        # Compile both variants with identical commands/options and the same dependency classes.
        run([javac,'--release','8','-cp',classes,'-sourcepath',sources,'-d',classes,sources/'WotsPlus.java'],'compile-'+side)
        drivers=BUILD/(side+'-driver'); drivers.mkdir()
        run([javac,'--release','8','-cp',classes,'-d',drivers,driver,HERE/'AddressTrace.java'],'compile-driver-'+side)
        manifest['classes'][side]=str(classes); manifest['drivers'][side]=str(drivers)
    maps={s:tree(Path(p)) for s,p in manifest['classes'].items()}
    assert maps['baseline'].keys()==maps['candidate'].keys()
    assert [k for k in maps['baseline'] if maps['baseline'][k]!=maps['candidate'][k]]==[PACKAGE+'/WotsPlus.class']
    manifest['class_hashes']=maps; manifest['driver_hashes']={s:tree(Path(p)) for s,p in manifest['drivers'].items()}
    assert manifest['driver_hashes']['baseline']==manifest['driver_hashes']['candidate']
    write(OUT/'manifest.json',manifest)
    traces={s:run(command(manifest,s,'AddressTrace'),'trace-'+s) for s in ['baseline','candidate']}
    assert traces['baseline']==traces['candidate'] and len(traces['baseline'])==24
    for parameter in PARAMETERS:
        checks={s:run(command(manifest,s,'SlhDeepProbe','check',manifest['fixtures'],parameter,s),'check-'+parameter+'-'+s) for s in ['baseline','candidate']}
        for s,rows in checks.items():
            assert len(rows)==36 and all(r['checked'] and r['class_source']==manifest['classes'][s] for r in rows)
        strip=lambda rows:[{k:v for k,v in r.items() if k not in ['variant','class_source']} for r in rows]
        assert strip(checks['baseline'])==strip(checks['candidate'])
    verify(manifest)
    write(OUT/'gates.json',dict(passed=True,trace_cases=24,whole_operation_cases_per_variant=72,scope='Trace equality covers all n and nonzero ADRS bytes; real whole operations cover two fast sets and twelve keys each. Not full ACVP or upstream-suite approval.'))

def command(m,side,main,*args):
    return [m['java'],*m['jvm_args'],'-cp',os.pathsep.join([m['drivers'][side],m['classes'][side]]),PACKAGE.replace('/','.')+'.'+main,*map(str,args)]
def verify(m):
    assert sha(m['java'])==m['java_sha256']
    assert all(sha(p)==h for p,h in m['files'].items())
    assert {s:tree(Path(p)) for s,p in m['classes'].items()}==m['class_hashes']
    assert {s:tree(Path(p)) for s,p in m['drivers'].items()}==m['driver_hashes']
    assert m['environment']=={k:os.environ.get(k,'') for k in m['environment']}

def collect():
    m=json.loads((OUT/'manifest.json').read_text()); assert json.loads((OUT/'gates.json').read_text())['passed']; verify(m)
    jobs=[]
    for mode in ['bench','allocation']:
        for parameter in PARAMETERS:
            for operation in OPERATIONS:
                for fork in range(2):
                    for side in (['baseline','candidate'] if fork==0 else ['candidate','baseline']):
                        jobs.append(dict(mode=mode,parameter=parameter,operation=operation,fork=fork,variant=side,rounds=2,budget_ms=100,warmup_cycles=40))
    write(OUT/'plan.json',dict(jobs=jobs,created_at=stamp(),limits='Two balanced process pairs; 80 disjoint-key warmup calls, four measured keys cycled per process, two rounds. Exploratory screen; wall/CPU and allocation separate; imports excluded by inherited harness.'))
    records=[]; started=stamp()
    for i,job in enumerate(jobs):
        s=job['variant']; name='run-'+str(i).zfill(3)
        rows=run(command(m,s,'SlhDeepProbe',job['mode'],m['fixtures'],job['parameter'],s,job['operation'],job['fork'],job['rounds'],job['budget_ms'],job['warmup_cycles']),name)
        assert rows and all(r['checked'] and r['variant']==s and r['class_source']==m['classes'][s] and r['parameter']==job['parameter'] and r['operation']==job['operation'] for r in rows)
        assert {r['case'] for r in rows}=={0,3,6,9} and {r['round'] for r in rows}=={0,1}
        records.append(dict(job=job,raw=name+'.stdout.jsonl',sha256=sha(OUT/(name+'.stdout.jsonl')),rows=len(rows)))
        print(f'{i+1}/{len(jobs)} {job["mode"]} {job["parameter"]} {job["operation"]} {s}',flush=True)
    verify(m)
    write(OUT/'execution.json',dict(passed=True,started_at=started,finished_at=stamp(),manifest_sha256=sha(OUT/'manifest.json'),runs=records))
    summarize()

def summarize():
    execution=json.loads((OUT/'execution.json').read_text()); cells={}
    for record in execution['runs']:
        path=OUT/record['raw']; assert sha(path)==record['sha256']
        rows=[json.loads(s) for s in path.read_text().splitlines()]; j=record['job']
        key=(j['mode'],j['parameter'],j['operation']); slots=cells.setdefault(key,{})
        slots[(j['fork'],j['variant'])]={k:statistics.mean(r[k] for r in rows) for k in ['wall_ns','thread_cpu_ns','allocated_bytes']}
    out=[]
    for (mode,p,op),slots in cells.items():
        metrics={}
        for k in (['wall_ns','thread_cpu_ns'] if mode=='bench' else ['allocated_bytes']):
            a=[slots[(i,'baseline')][k] for i in range(2)]; b=[slots[(i,'candidate')][k] for i in range(2)]
            metrics[k]=dict(baseline_process_means=a,candidate_process_means=b,change_percent=[100*(y/x-1) for x,y in zip(a,b)],aggregate_change_percent=100*(statistics.mean(b)/statistics.mean(a)-1))
        out.append(dict(mode=mode,parameter=p,operation=op,metrics=metrics))
    write(OUT/'summary.json',dict(schema='bc-address-screen-summary-v1',cells=out,execution_sha256=sha(OUT/'execution.json'),limits='Preliminary two-pair screen; no confidence interval, peak-memory claim, or upstream readiness. Keep both pairs and unchanged verification control.'))
    print(json.dumps(out,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['prepare','collect']);parser.add_argument('--original',type=Path);args=parser.parse_args()
    prepare(args.original.resolve()) if args.mode=='prepare' else collect()
