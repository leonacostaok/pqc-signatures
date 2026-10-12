#!/usr/bin/env python3
"""Allocation audit: copied exact Git sources, counter-only public operations."""
import argparse, hashlib, io, json, os, random, shutil, subprocess, sys, tarfile
from pathlib import Path
if sys.flags.optimize: raise RuntimeError('Run without Python optimization')
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[3]
BUILD=ROOT/'libs/circl/build/published-memory'; REPO=ROOT.parents[2]/'circl'
# Worktrees are under pqc-signatures/worktrees; the upstream sibling is explicit.
REPO=Path('/Users/dandelionlabs/development/personal/circl')
OLD=ROOT.parent/'circl-performance'
REFS={'baseline':'91db3e785ba2635b4f24a023e1ad76d2780e2865','candidate':'1c31496b567c27e672979358befd2505cb735fa9'}
PARAMS=[f'SLH-DSA-SHA2-{n}{s}' for n in (128,192,256) for s in ('f','s')]+['SLH-DSA-SHAKE-128f']
ENV=dict(os.environ,GOMAXPROCS='1',GOTOOLCHAIN='local',GOGC='off',GOMEMLIMIT='off')
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def tree(path): return {str(p.relative_to(path)):sha(p) for p in sorted(path.rglob('*')) if p.is_file() and p.suffix in ('.go','.s','.c','.h','.mod','.sum')}
def inputs(): return {str(p.relative_to(ROOT)):sha(p) for p in HERE.iterdir() if p.suffix in ('.py','.go')}
def run(args,cwd=None): return subprocess.check_output(list(map(str,args)),cwd=cwd,env=ENV,text=True,stderr=subprocess.STDOUT)
def write(path,obj):
    with path.open('x') as f: json.dump(obj,f,indent=2);f.write('\n')
def prepare():
    BUILD.mkdir(parents=True,exist_ok=False)
    pointer=json.loads((OLD/'libs/circl/build/tenkeys/prepared.json').read_text())
    prior=json.loads(Path(pointer['manifest']).read_text())
    corpus=BUILD/'corpus.json';shutil.copyfile(prior['corpora']['final'],corpus)
    m={'schema':'circl-published-memory-seal-v1','refs':REFS,'inputs':inputs(),'go':run(['go','version']).strip(),'go_env':json.loads(run(['go','env','-json','GOROOT','GOOS','GOARCH','GOEXPERIMENT','CGO_ENABLED'])),'corpus':str(corpus),'corpus_sha256':sha(corpus),'variants':{},'metric':'counter-only; no performance timing','environment':{k:ENV.get(k,'') for k in ['GOMAXPROCS','GOTOOLCHAIN','GOGC','GOMEMLIMIT','GODEBUG','GOEXPERIMENT','GOFLAGS']},'go_binary_sha256':sha(Path(shutil.which('go')).resolve())}
    for variant,ref in REFS.items():
        dest=BUILD/variant;dest.mkdir()
        archive=subprocess.check_output(['git','-C',str(REPO),'archive',ref])
        with tarfile.open(fileobj=io.BytesIO(archive)) as t:
            assert all(not x.name.startswith('/') and '..' not in Path(x.name).parts and (x.isfile() or x.isdir()) for x in t.getmembers())
            t.extractall(dest)
        expected=subprocess.check_output(['git','-C',str(REPO),'show',ref+':sign/slhdsa/state.go'])
        assert (dest/'sign/slhdsa/state.go').read_bytes()==expected
        driver=dest/'cmd/memoryaudit';driver.mkdir(parents=True)
        shutil.copyfile(HERE/'main.go',driver/'main.go')
        shutil.copyfile(HERE/'layout_test.go',dest/'sign/slhdsa/memory_audit_layout_test.go')
        if variant=='candidate':shutil.copyfile(HERE/'cleanup_test.go',dest/'sign/slhdsa/memory_audit_cleanup_test.go')
        log=run(['go','test','-json','-run','^TestMemoryAudit','-count=1','./sign/slhdsa'],dest)
        (BUILD/(variant+'-checks.jsonl')).write_text(log)
        events=[json.loads(x) for x in log.splitlines() if x.startswith('{')]
        passed={x.get('Test') for x in events if x.get('Action')=='pass'}
        required={'TestMemoryAuditLayout','TestMemoryAuditSetup'}
        if variant=='candidate':required|={'TestMemoryAuditPrefixCleanup','TestMemoryAuditBaseCleanup','TestMemoryAuditTCleanup'}
        assert required<=passed
        binary=dest/'memoryaudit'
        build=run(['go','build','-trimpath','-pgo=off','-buildvcs=false','-gcflags=github.com/cloudflare/circl/sign/slhdsa=-m=2 -S','-o',binary,'./cmd/memoryaudit'],dest)
        (BUILD/(variant+'-build.log')).write_text(build)
        frames=[x for x in build.splitlines() if '\tTEXT\t' in x]
        (BUILD/(variant+'-frames.txt')).write_text('\n'.join(frames)+'\n')
        m['variants'][variant]={'path':str(dest),'binary':str(binary),'binary_sha256':sha(binary),'source':tree(dest),'checks_sha256':sha(BUILD/(variant+'-checks.jsonl')),'frames_sha256':sha(BUILD/(variant+'-frames.txt'))}
    assert m['variants']['baseline']['binary_sha256']!=m['variants']['candidate']['binary_sha256']
    write(BUILD/'manifest.json',m);print(BUILD/'manifest.json')
def verify(m):
    assert m['inputs']==inputs() and sha(m['corpus'])==m['corpus_sha256']
    assert m['go']==run(['go','version']).strip()
    assert m['environment']=={k:ENV.get(k,'') for k in m['environment']}
    assert m['go_binary_sha256']==sha(Path(shutil.which('go')).resolve())
    for variant,v in m['variants'].items():
        assert tree(Path(v['path']))==v['source'] and sha(v['binary'])==v['binary_sha256']
        assert sha(BUILD/(variant+'-checks.jsonl'))==v['checks_sha256']
def collect(out):
    m=json.loads((BUILD/'manifest.json').read_text());verify(m)
    out.mkdir(parents=True,exist_ok=False);write(out/'manifest.json',m)
    plan=[]
    for rnd in range(3):
        for i,p in enumerate(PARAMS):
            vs=['baseline','candidate']
            if (rnd+i)%2:vs.reverse()
            plan.extend([rnd,p,v] for v in vs)
    write(out/'plan.json',plan);runs=[]
    import datetime
    now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
    start=now()
    for index,(rnd,p,v) in enumerate(plan):
        command=[m['variants'][v]['binary'],'-corpus',m['corpus'],'-param',p,'-warmup-cycles','1']
        began=now();result=subprocess.run(command,env=ENV,text=True,capture_output=True)
        raw=out/f'{index:03d}.json';raw.write_text(result.stdout);(out/f'{index:03d}.stderr').write_text(result.stderr)
        runs.append({'index':index,'round':rnd,'parameter':p,'variant':v,'argv':command,'started_at':began,'completed_at':now(),'exit_code':result.returncode,'raw':raw.name,'sha256':sha(raw)})
        (out/'execution.json').write_text(json.dumps({'schema':'circl-published-memory-execution-v1','started_at':start,'runs':runs,'manifest_sha256':sha(BUILD/'manifest.json')},indent=2)+'\n')
        assert result.returncode==0,result.stderr
        data=json.loads(result.stdout);assert data['param']==p and len(data['rows'])==3
        corpus=json.loads(Path(m['corpus']).read_text())
        assert data['corpus_id']==corpus['id'] and data['measured_calls']=={'keygen':3,'sign':3,'verify':3}
        for row,case in zip(data['rows'],corpus['parameters'][p]['measured'][:3]):
            assert row['index']==case['index'] and row['seed']==case['seed']
            assert row['valid'] and row['tamper_rejected'] and row['inputs_preserved']
            assert all(a['allocated_bytes']>0 and a['allocated_objects']>0 for a in row['allocation'].values())
            assert all(a['collections_during_call']==0 for a in row['allocation'].values())
        print(f'{index+1}/{len(plan)} {v} {p}',flush=True)
    verify(m)
    for rnd in range(3):
        for p in PARAMS:
            pair=[json.loads((out/r['raw']).read_text()) for r in runs if r['round']==rnd and r['parameter']==p]
            for a,b in zip(pair[0]['rows'],pair[1]['rows']):
                assert {k:v for k,v in a.items() if k!='allocation'}=={k:v for k,v in b.items() if k!='allocation'}
    (out/'execution.json').write_text(json.dumps({'schema':'circl-published-memory-execution-v1','started_at':start,'completed_at':now(),'runs':runs,'all_outputs_match':True,'manifest_sha256':sha(BUILD/'manifest.json')},indent=2)+'\n')
    print(out/'execution.json')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','collect']);p.add_argument('--out',type=Path);a=p.parse_args()
    if a.mode=='prepare':prepare()
    else:assert a.out;collect(a.out)
