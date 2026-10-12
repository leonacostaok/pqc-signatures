#!/usr/bin/env python3
"""Exact-source constructor counts and post-GC diagnostics; never latency/peak claims."""
import argparse, datetime, hashlib, json, os, shutil, subprocess, sys
from pathlib import Path
if sys.flags.optimize: raise RuntimeError('Run without Python optimization')
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[3]
BUILD=ROOT/'libs/noble/build/published-memory'
OLD=ROOT.parent/'noble-robustness/libs/noble/build/robustness/snapshots/c07d4385a773caa3/0.7.1'
UPSTREAM=Path('/Users/dandelionlabs/development/personal/noble-post-quantum')
NODE=Path('/Users/dandelionlabs/.nvm/versions/node/v22.23.2/bin/node')
REFS={'baseline':'48e493397e69fa3e377bd454ff5261b1a7e22651','candidate':'39d56d145aa0127f3117f191aec0522aeb76397f'}
ENV=dict(os.environ); ENV.pop('NODE_OPTIONS',None)
OPS=['keygen','getPublicKey','sign','verify']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def tree(p):return {str(x.relative_to(p)):sha(x) for x in sorted(p.rglob('*')) if x.is_file()}
def inputs():return {str(p.relative_to(ROOT)):sha(p) for p in sorted(HERE.iterdir()) if p.suffix in ('.py','.mjs')}
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write(p,o):
    with p.open('x') as f:json.dump(o,f,indent=2);f.write('\n')
def prepare():
    BUILD.mkdir(parents=True,exist_ok=False)
    m={'schema':'noble-resource-seal-v1','refs':REFS,'inputs':inputs(),'node':str(NODE),'node_sha256':sha(NODE),'node_version':subprocess.check_output([NODE,'--version'],text=True).strip(),'node_options':'','excluded_nonproduction_file':'ml-dsa.audit.js (prior arithmetic-test instrumentation; never imported here)','variants':{}}
    for v,ref in REFS.items():
        dest=BUILD/v;shutil.copytree(OLD/v,dest,ignore=shutil.ignore_patterns('ml-dsa.audit.js'))
        module=dest/'node_modules/@noble/post-quantum/ml-dsa.js'
        source=module.parent/'src/ml-dsa.ts'
        assert source.read_bytes()==subprocess.check_output(['git','-C',UPSTREAM,'show',ref+':src/ml-dsa.ts'])
        m['variants'][v]={'path':str(dest),'module':str(module),'tree':tree(dest),'production_sha256':sha(source),'compiled_js_sha256':sha(module)}
    assert m['variants']['baseline']['production_sha256']!=m['variants']['candidate']['production_sha256']
    assert m['variants']['baseline']['compiled_js_sha256']!=m['variants']['candidate']['compiled_js_sha256']
    # The measured package differs only in the sealed production TS and compiled JS files.
    a=m['variants']['baseline']['tree'];b=m['variants']['candidate']['tree']
    assert set(a)==set(b)
    assert {p for p in a if a[p]!=b[p]}=={'node_modules/@noble/post-quantum/src/ml-dsa.ts','node_modules/@noble/post-quantum/ml-dsa.js'}
    fixture=BUILD/'fixture.json'
    subprocess.run([NODE,HERE/'fixture.mjs',m['variants']['baseline']['module'],fixture],env=ENV,check=True)
    data=json.loads(fixture.read_text());assert len(data['rows'])==72
    assert len({r['seed'] for r in data['rows']})==72
    assert {(p,g):sum(r['parameter']==p and r['group']==g for r in data['rows']) for p in (44,65,87) for g in ('warmup','measured')}=={(p,g):12 for p in (44,65,87) for g in ('warmup','measured')}
    m.update(fixture=str(fixture),fixture_sha256=sha(fixture))
    write(BUILD/'manifest.json',m);print(BUILD/'manifest.json')
def verify(m):
    assert inputs()==m['inputs'] and sha(NODE)==m['node_sha256'] and sha(m['fixture'])==m['fixture_sha256']
    assert subprocess.check_output([NODE,'--version'],text=True).strip()==m['node_version']
    for v in m['variants'].values():assert tree(Path(v['path']))==v['tree']
def collect(out,mode):
    m=json.loads((BUILD/'manifest.json').read_text());verify(m)
    out.mkdir(parents=True,exist_ok=False);write(out/'manifest.json',m)
    if mode=='constructors':plan=[{'round':0,'parameter':p,'variant':v} for p in (44,65,87) for v in ('baseline','candidate')]
    else:
        plan=[]
        for rnd in range(4):
            for pi,p in enumerate((44,65,87)):
                for oi,op in enumerate(OPS):
                    vs=['baseline','candidate']
                    if (rnd+pi+oi)%2:vs.reverse()
                    plan.extend({'round':rnd,'parameter':p,'operation':op,'variant':v} for v in vs)
    write(out/'plan.json',plan);runs=[];start=now()
    for i,cell in enumerate(plan):
        opts=dict(cell,mode=mode,module=m['variants'][cell['variant']]['module'],fixture=m['fixture'])
        argv=[str(NODE),'--expose-gc',str(HERE/'worker.mjs'),json.dumps(opts,sort_keys=True)]
        began=now();r=subprocess.run(argv,env=ENV,text=True,capture_output=True)
        raw=out/f'{i:03d}.json';raw.write_text(r.stdout);(out/f'{i:03d}.stderr').write_text(r.stderr)
        runs.append(dict(cell,index=i,argv=argv,started_at=began,completed_at=now(),exit_code=r.returncode,raw=raw.name,sha256=sha(raw)))
        execution={'schema':'noble-resource-execution-v1','mode':mode,'started_at':start,'manifest_sha256':sha(BUILD/'manifest.json'),'python_version':sys.version,'python_optimize':sys.flags.optimize,'node_options':'','runs':runs}
        (out/'execution.json').write_text(json.dumps(execution,indent=2)+'\n')
        assert r.returncode==0,r.stderr
        data=json.loads(r.stdout);assert data['mode']==mode and data['parameter']==cell['parameter'] and data['node']==m['node_version']
        if mode=='constructors':
            assert len(data['rows'])==60 and {(x['operation'],x['index']) for x in data['rows']}=={(op,j) for op in OPS+['invalidLength'] for j in range(12)}
            assert all(type(x['constructors']) is int and x['constructors']>=0 and x['requested_bytes']==1024*x['constructors'] for x in data['rows'])
        else:
            assert data['operation']==cell['operation'] and data['checked']==288
            assert [x['calls'] for x in data['epochs']]==[0,96,192,288]
            assert all(type(n) is int and n>0 for x in data['epochs'] for n in x['memory'].values())
            assert data['gc_events']['forced']>=8
        print(f'{i+1}/{len(plan)} {cell}',flush=True)
    if mode=='constructors':
        for p in (44,65,87):
            a,b=[json.loads((out/r['raw']).read_text()) for r in runs if r['parameter']==p]
            assert [r['output_sha256'] for r in a['rows']]==[r['output_sha256'] for r in b['rows']]
    verify(m);execution['completed_at']=now();execution['all_checks_passed']=True
    (out/'execution.json').write_text(json.dumps(execution,indent=2)+'\n');print(out/'execution.json')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','constructors','retained']);p.add_argument('--out',type=Path);a=p.parse_args()
    if a.mode=='prepare':prepare()
    else:assert a.out;collect(a.out,a.mode)
