#!/usr/bin/env python3
"""Isolated WOTS alternatives: prepare/check first, collect only in an authorized window."""
import argparse, concurrent.futures, datetime, difflib, gzip, hashlib, json, os, shutil, statistics, subprocess, sys, tarfile
from pathlib import Path
if sys.flags.optimize:
    raise RuntimeError('Assertions required; do not use Python -O or PYTHONOPTIMIZE')
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
OUT=ROOT/'results/bouncycastle/wots-alternatives'
BUILD=ROOT/'libs/bouncycastle/build/wots-alternatives'
PIN='c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
PKG='org/bouncycastle/crypto/signers/slhdsa'
VARIANTS=['baseline','object_hoist','field_rewrite','two_addresses','buffer','buffer_peeled']
PARAMETERS=[f'{family}_{size}{speed}' for family in ['sha2','shake'] for size in [128,192,256] for speed in ['f','s']]
OPS=['keygen.total','sign.total','verify.total']
ENV=['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS']
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,v):
    with Path(p).open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def tree(p,suffix='.class'):
    return {str(f.relative_to(p)):sha(f) for f in sorted(Path(p).rglob('*'+suffix))}
def seal(d):
    h=hashlib.sha256()
    for k,v in d.items():h.update(k.encode()+b'\0'+bytes.fromhex(v))
    return h.hexdigest()
def run(command,stem,expected=0):
    command=list(map(str,command));write(OUT/(stem+'.command.json'),{'command':command,'started_at':stamp()})
    with (OUT/(stem+'.stdout.jsonl')).open('x') as out,(OUT/(stem+'.stderr.txt')).open('x') as err:
        result=subprocess.run(command,stdout=out,stderr=err)
    write(OUT/(stem+'.status.json'),{'exit_code':result.returncode,'finished_at':stamp()})
    assert result.returncode==expected,(stem,result.returncode)
    return (OUT/(stem+'.stdout.jsonl')).read_text()
def rows(command,stem):return [json.loads(x) for x in run(command,stem).splitlines()]
def replace(s,old,new,count=1):
    assert s.count(old)==count,(old,s.count(old),count)
    return s.replace(old,new)
def variants(baseline,buffer,two):
    out={'baseline':baseline,'two_addresses':two,'buffer':buffer}
    out['object_hoist']=replace(baseline,'        byte[][] tmp = new byte[engine.WOTS_LEN][];\n        for (int i = 0; i < engine.WOTS_LEN; i++)\n        {\n            ADRS adrs = new ADRS(paramAdrs);','        ADRS adrs = new ADRS(paramAdrs);\n        byte[][] tmp = new byte[engine.WOTS_LEN][];\n        for (int i = 0; i < engine.WOTS_LEN; i++)\n        {')
    # These four sites overwrite all three suffix words before PRF/F. Keep allocations identical.
    s=replace(baseline,'adrs.setTypeAndClear(ADRS.WOTS_PRF);','adrs.changeType(ADRS.WOTS_PRF);',2)
    out['field_rewrite']=replace(s,'adrs.setTypeAndClear(ADRS.WOTS_HASH);','adrs.changeType(ADRS.WOTS_HASH);',2)
    old='''        byte[] result = X;
        for (int j = 0; j < s; ++j)
        {
            adrs.setHashAddress(i + j);
            if (j == 0)
            {
                result = engine.F(pkSeed, adrs, result);
            }
            else
            {
                // F consumes its input before writing the output, so later steps can reuse it.
                engine.F(pkSeed, adrs, result, result);
            }
        }
        return result;'''
    new='''        byte[] result = X;
        if (s > 0)
        {
            adrs.setHashAddress(i);
            result = engine.F(pkSeed, adrs, result);
            for (int j = 1; j < s; ++j)
            {
                adrs.setHashAddress(i + j);
                engine.F(pkSeed, adrs, result, result);
            }
        }
        return result;'''
    out['buffer_peeled']=replace(buffer,old,new)
    assert set(out)==set(VARIANTS) and len(set(out.values()))==6
    return out
def command(m,v,main,*args):return [m['java'],*m['jvm_args'],'-cp',os.pathsep.join([m['drivers'][v],m['classes'][v]]),PKG.replace('/','.')+'.'+main,*map(str,args)]
def verify(m):
    assert sha(m['java'])==m['java_sha256'] and sha(m['javac'])==m['javac_sha256']
    assert all(sha(ROOT/p)==h for p,h in m['files'].items())
    assert {v:tree(Path(p)) for v,p in m['classes'].items()}==m['class_hashes']
    assert {v:tree(Path(p)) for v,p in m['drivers'].items()}==m['driver_hashes']
    assert m['environment']=={k:os.environ.get(k,'') for k in ENV}
def prepare(parent_path):
    original=json.loads(parent_path.read_text());assert original['upstream_commit']==PIN
    assert seal(tree(Path(original['classes']['baseline'])))==original['provenance']['classes']['baseline']
    for v in ['baseline','candidate']:
        assert seal(tree(Path(original['sources'][v]),'.java'))==original['provenance']['sources'][v]
    archive=parent_path.parent/'baseline-source.tar'
    assert sha(archive)==original['provenance']['files'][str(archive)]
    assert sha(original['fixtures'])==original['provenance']['files'][original['fixtures']]
    BUILD.mkdir(parents=True,exist_ok=False);pre=OUT/'preparation';pre.mkdir(exist_ok=False)
    shutil.copyfile(parent_path,pre/'parent-manifest.json');shutil.copyfile(original['fixtures'],pre/'fixtures.tsv')
    with archive.open('rb') as src,gzip.GzipFile(filename=str(pre/'baseline-source.tar.gz'),mode='wb',mtime=0) as dst:shutil.copyfileobj(src,dst)
    bsrc=Path(original['sources']['baseline'])/'core/src/main/java'/PKG
    csrc=Path(original['sources']['candidate'])/'core/src/main/java'/PKG
    two=(ROOT/'results/bouncycastle/pattern-research/address/preparation/candidate-WotsPlus.java').read_text()
    assert (ROOT/'results/bouncycastle/pattern-research/address/preparation/baseline-WotsPlus.java').read_bytes()==(bsrc/'WotsPlus.java').read_bytes()
    ws=variants((bsrc/'WotsPlus.java').read_text(),(csrc/'WotsPlus.java').read_text(),two)
    java=Path(original['java']);m={'schema':'bc-wots-alternatives-v1','upstream_commit':PIN,'created_at':stamp(),'parent_manifest_sha256':sha(parent_path),'java':str(java),'java_sha256':sha(java),'javac':str(java.with_name('javac')),'javac_sha256':sha(java.with_name('javac')),'jvm_args':['-Xms64m','-Xmx512m','-XX:ActiveProcessorCount=2','-XX:+UseG1GC'],'environment':{k:os.environ.get(k,'') for k in ENV},'fixtures':str(pre/'fixtures.tsv'),'variants':VARIANTS,'parameters':PARAMETERS,'classes':{},'drivers':{}}
    run([java,'-version'],'java-version')
    for v in VARIANTS:
        folder=pre/v;folder.mkdir();(folder/'WotsPlus.java').write_text(ws[v])
        engine=(csrc if v.startswith('buffer') else bsrc)/'SLHDSAEngine.java';shutil.copyfile(engine,folder/'SLHDSAEngine.java')
        patch=''
        for name in ['WotsPlus.java','SLHDSAEngine.java']:
            patch+=''.join(difflib.unified_diff((bsrc/name).read_text().splitlines(True),(folder/name).read_text().splitlines(True),fromfile='a/core/src/main/java/'+PKG+'/'+name,tofile='b/core/src/main/java/'+PKG+'/'+name))
        (folder/'change.patch').write_text(patch)
        classes=BUILD/(v+'-classes');shutil.copytree(original['classes']['baseline'],classes)
        drivers=BUILD/(v+'-driver');drivers.mkdir()
        m['classes'][v]=str(classes);m['drivers'][v]=str(drivers)
    def compile_one(v):
        run([m['javac'],'-J-XX:ActiveProcessorCount=2','--release','8','-cp',m['classes'][v],'-sourcepath',pre/v,'-d',m['classes'][v],pre/v/'WotsPlus.java',pre/v/'SLHDSAEngine.java'],'compile-'+v)
        run([m['javac'],'-J-XX:ActiveProcessorCount=2','--release','8','-cp',m['classes'][v],'-d',m['drivers'][v],*sorted(HERE.glob('*.java'))],'driver-'+v)
    # Preparation is allowed concurrently; no timing or allocation runs here.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(compile_one,VARIANTS))
    m['class_hashes']={v:tree(Path(p)) for v,p in m['classes'].items()};m['driver_hashes']={v:tree(Path(p)) for v,p in m['drivers'].items()}
    allowed={PKG+'/'+x+'.class' for x in ['WotsPlus','SLHDSAEngine','SLHDSAEngine$Sha2Engine','SLHDSAEngine$Shake256Engine']}
    for v in VARIANTS:
        assert m['class_hashes'][v].keys()==m['class_hashes']['baseline'].keys()
        changed={k for k,h in m['class_hashes'][v].items() if h!=m['class_hashes']['baseline'][k]}
        assert changed<=allowed and (v=='baseline' or PKG+'/WotsPlus.class' in changed)
        assert m['driver_hashes'][v]==m['driver_hashes']['baseline']
    assert len({m['class_hashes'][v][PKG+'/WotsPlus.class'] for v in VARIANTS})==6
    files=sorted(HERE.glob('*'))+sorted(f for f in pre.rglob('*') if f.is_file())
    m['files']={str(f.relative_to(ROOT)):sha(f) for f in files if f.is_file()}
    write(OUT/'manifest.json',m)
    traces={};checks={};chain={}
    for v in VARIANTS:
        print('Gate '+v,flush=True)
        traces[v]=rows(command(m,v,'AddressTrace'),'trace-'+v)
        chain[v]=rows(command(m,v,'ChainGate'),'chain-'+v)
        assert len(traces[v])==24 and traces[v]==traces['baseline']
        assert chain[v]==chain['baseline'] and chain[v][0]['checked']
        checks[v]={}
        for parameter in PARAMETERS:
            print('Check '+v+' '+parameter,flush=True)
            r=rows(command(m,v,'WotsAlternativeProbe','check',m['fixtures'],parameter,v,'all',0,0),'check-'+v+'-'+parameter)
            expected={(phase,i,op) for phase,n in [('warmup',2),('measured',10)] for i in range(n) for op in OPS} if parameter.endswith('f') else {('measured',0,op) for op in OPS}
            assert {(x['phase'],x['case'],x['operation']) for x in r}==expected and len(r)==len(expected)
            assert all(x['checked'] and x['class_source']==m['classes'][v] for x in r)
            checks[v][parameter]=[{k:z for k,z in x.items() if k not in ['variant','class_source']} for x in r]
            assert checks[v][parameter]==checks['baseline'][parameter]
    verify(m)
    write(OUT/'gates.json',{'passed':True,'trace_cases_per_variant':24,'native_chain_cases_per_variant':chain['baseline'][0]['cases'],'whole_checks_per_variant':sum(len(v) for v in checks['baseline'].values()),'fast_coverage':'six fast sets,12 keys each,3 operations','slow_coverage':'six slow sets,measured case0 only,3 operations','manifest_sha256':sha(OUT/'manifest.json')})
    print('Preparation and correctness gates complete; collection requires separate window.',flush=True)
def plan():
    comparisons=[('baseline','object_hoist'),('baseline','field_rewrite'),('baseline','two_addresses'),('baseline','buffer'),('buffer','buffer_peeled')]
    jobs=[]
    for mode in ['bench','allocation']:
        for parameter in ['sha2_128f','shake_128f']:
            for op in OPS:
                for a,b in comparisons:
                    for fork in range(2):
                        for v in ([a,b] if fork==0 else [b,a]):jobs.append({'mode':mode,'parameter':parameter,'operation':op,'comparison':[a,b],'fork':fork,'variant':v,'warmup_calls':20})
    write(OUT/'plan.json',{'created_at':stamp(),'jobs':jobs,'scope':'Prespecified lean128f screen;10 distinct measured keys once/process;20 warmup calls on2 disjoint keys; two balanced independent pairs; modes separate; no steady-state claim.'})
def collect(window):
    assert window.strip(),'Name the authorization/window in the invocation'
    m=json.loads((OUT/'manifest.json').read_text());verify(m);assert json.loads((OUT/'gates.json').read_text())['passed']
    p=json.loads((OUT/'plan.json').read_text());records=[]
    write(OUT/'window.json',{'authorization':window,'started_at':stamp(),'plan_sha256':sha(OUT/'plan.json')})
    for i,j in enumerate(p['jobs']):
        stem='run-'+str(i).zfill(3);v=j['variant']
        r=rows(command(m,v,'WotsAlternativeProbe',j['mode'],m['fixtures'],j['parameter'],v,j['operation'],j['fork'],j['warmup_calls']),stem)
        assert len(r)==10 and [x['case'] for x in r]==list(range(10))
        assert all(x['checked'] and x['class_source']==m['classes'][v] and all(x[k]==j[k] for k in ['mode','variant','parameter','operation','fork','warmup_calls']) for x in r)
        records.append({'job':j,'raw':stem+'.stdout.jsonl','sha256':sha(OUT/(stem+'.stdout.jsonl'))})
        print(str(i+1)+'/'+str(len(p['jobs']))+' '+j['mode']+' '+j['parameter']+' '+j['operation']+' '+v,flush=True)
    verify(m);write(OUT/'execution.json',{'passed':True,'finished_at':stamp(),'manifest_sha256':sha(OUT/'manifest.json'),'plan_sha256':sha(OUT/'plan.json'),'runs':records})
    summarize()
def summarize():
    e=json.loads((OUT/'execution.json').read_text());cells={}
    for r in e['runs']:
        assert sha(OUT/r['raw'])==r['sha256'];obs=[json.loads(x) for x in (OUT/r['raw']).read_text().splitlines()];j=r['job'];key=(j['mode'],j['parameter'],j['operation'],*j['comparison'])
        cells.setdefault(key,{})[(j['fork'],j['variant'])]={k:statistics.mean(x[k] for x in obs) for k in ['wall_ns','thread_cpu_ns','allocated_bytes']}
    out=[]
    for (mode,p,op,a,b),slots in cells.items():
        metrics={}
        for k in (['allocated_bytes'] if mode=='allocation' else ['wall_ns','thread_cpu_ns']):
            aa=[slots[(i,a)][k] for i in range(2)];bb=[slots[(i,b)][k] for i in range(2)]
            metrics[k]={'reference_process_means':aa,'candidate_process_means':bb,'paired_change_percent':[100*(y/x-1) for x,y in zip(aa,bb)],'aggregate_change_percent':100*(statistics.mean(bb)/statistics.mean(aa)-1)}
        out.append({'mode':mode,'parameter':p,'operation':op,'comparison':[a,b],'metrics':metrics})
    write(OUT/'summary.json',{'cells':out,'execution_sha256':sha(OUT/'execution.json'),'limits':'Two independent balanced pairs; preserve all losses and verification controls. No confidence intervals,peak memory,all-parameter or steady-state claim.'})
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','plan','collect','summarize','verify']);p.add_argument('--parent',type=Path);p.add_argument('--window');a=p.parse_args()
    if a.mode=='prepare':prepare(a.parent.resolve())
    elif a.mode=='plan':plan()
    elif a.mode=='collect':collect(a.window)
    elif a.mode=='verify':verify(json.loads((OUT/'manifest.json').read_text()));print('Seals verified')
    else:summarize()
