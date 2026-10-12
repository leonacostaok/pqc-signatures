#!/usr/bin/env python3
"""Package or verify follow-up evidence without the ignored build directories."""
import argparse,gzip,hashlib,io,json,sys,tarfile
from pathlib import Path
if sys.flags.optimize:raise RuntimeError('Python optimization disables checks')
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];LIB=HERE.parent.name
RESULT=ROOT/'results'/LIB/'resource-followup'
def sha(b):return hashlib.sha256(b).hexdigest()
def expected_sources(m):
    out={}
    for variant,v in m['variants'].items():
        for name,h in v['tree'].items():out[variant+'/'+name]=(Path(v['path'])/name,h)
        if LIB=='circl':out[variant+'/resourcefollowup']=(Path(v['binary']),v['binary_sha256'])
    return out

def package():
    m=json.loads((RESULT/'resource/manifest.json').read_text());dest=RESULT/'preparation/sources.tar.gz'
    with dest.open('xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as gz,tarfile.open(fileobj=gz,mode='w|') as tar:
        for name,(p,h) in sorted(expected_sources(m).items()):
            data=p.read_bytes();assert sha(data)==h
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o755 if name.endswith('/resourcefollowup') else 0o644;info.mtime=0
            tar.addfile(info,io.BytesIO(data))
    (RESULT/'preparation/sources.sha256').write_text(sha(dest.read_bytes())+'  sources.tar.gz\n')
    print(dest)

def verify():
    source=RESULT/'preparation/sources.tar.gz';assert sha(source.read_bytes())==(RESULT/'preparation/sources.sha256').read_text().split()[0]
    manifests=[json.loads((RESULT/p/'manifest.json').read_text()) for p in ('baseline','resource')];assert manifests[0]==manifests[1];m=manifests[0]
    for path,h in m['inputs'].items():assert sha((ROOT/path).read_bytes())==h
    expected=expected_sources(m)
    with tarfile.open(source,'r:gz') as tar:
        assert {x.name for x in tar.getmembers()}==set(expected)
        assert len(tar.getmembers())==len(expected)
        for member in tar.getmembers():
            assert member.isfile();assert sha(tar.extractfile(member).read())==expected[member.name][1]
    processes=0;calls=0;execution_hashes={};pairs={}
    affected=[f'ML-DSA-{n}' for n in (44,65,87)] if LIB=='noble' else [f'SLH-DSA-SHA2-{n}{s}' for n in (128,192,256) for s in ('f','s')]
    missing=([f'SLH-DSA-{h}-{n}{s}' for h in ('SHA2','SHAKE') for n in (128,192,256) for s in ('f','s')]+['Falcon-512','Falcon-1024']) if LIB=='noble' else [f'ML-DSA-{n}' for n in (44,65,87)]+[f'SLH-DSA-SHAKE-{n}{s}' for n in (128,192,256) for s in ('f','s')]
    ops=['keygen','getPublicKey','sign','verify'] if LIB=='noble' else ['keygen','sign','verify']
    for profile in ('baseline','resource'):
        folder=RESULT/profile;ex=json.loads((folder/'execution.json').read_text());plan=json.loads((folder/'plan.json').read_text())
        assert ex['passed'] is True and ex['python_optimize']==0 and ex['profile']==profile
        assert ex['manifest_sha256']==sha((folder/'manifest.json').read_bytes())
        expected_cells={(r,p,'baseline','default',None) for r in range(3) for p in missing} if profile=='baseline' else {(r,p,v,s,o) for r in range(4) for p in affected for v in ('baseline','candidate') for s in ('default','constrained') for o in ops}
        observed={(x['round'],x['parameter'],x['variant'],x['settings'],x['operation']) for x in plan}
        assert observed==expected_cells and len(observed)==len(plan)==len(ex['runs'])
        execution_hashes[profile]=sha((folder/'execution.json').read_bytes())
        gate=json.loads((folder/'gate.json').read_text());assert gate['passed'] is True and gate['manifest_sha256']==ex['manifest_sha256']
        for rec in gate['records']:assert sha((folder/'checks'/Path(rec['raw']).name).read_bytes())==rec['sha256']
        for i,(rec,want) in enumerate(zip(ex['runs'],plan)):
            assert rec['index']==i and rec['exit_code']==0 and all(rec[k]==v for k,v in want.items())
            raw=folder/rec['raw'];assert sha(raw.read_bytes())==rec['sha256'];assert sha(raw.with_suffix('.stderr').read_bytes())==rec['stderr_sha256']
            d=json.loads(raw.read_text());assert d['checks']=={'exact_outputs':True,'inputs_preserved':True,'tamper_rejections':3}
            assert all(d[k]==rec[k] for k in ('parameter','mode','settings'))
            if LIB=='noble':
                flags=[] if rec['settings']=='default' else ['--max-old-space-size=32','--max-semi-space-size=1']
                options={'root':m['variants'][rec['variant']]['root'],'fixture':m['fixtures'][rec['parameter']]['path'],'parameter':rec['parameter'],'mode':rec['mode'],'operation':rec['operation'],'settings':rec['settings']}
                assert rec['argv']==[m['node'],*flags,str(Path(m['variants']['baseline']['path']).parents[5]/'libs/noble/experiments/resource-followup/worker.mjs'),json.dumps(options,sort_keys=True)]
                assert d['node']==m['node_version'] and d['exec_argv']==flags
            else:
                command=[m['variants'][rec['variant']]['binary'],'-fixture',m['fixtures'][rec['parameter']]['path'],'-param',rec['parameter'],'-mode',rec['mode'],'-settings',rec['settings']]+(['-op',rec['operation']] if rec['operation'] else [])
                assert rec['argv']==command and d['go']==m['go'].split()[2]
                assert d['environment']=={'GOGC':'100','GOMAXPROCS':'1','GOMEMLIMIT':'8MiB' if rec['settings']=='constrained' else 'off'}
            fp=folder/'fixtures'/(rec['parameter']+'.json');assert sha(fp.read_bytes())==m['fixtures'][rec['parameter']]['sha256']
            cases=[c for c in json.loads(fp.read_text())['rows'] if c['group']=='measured'];assert len(cases)==3
            expected_ops=['keygen','sign','verify'] if profile=='baseline' else [rec['operation']]
            assert [r['operation'] for r in d['rows']]==expected_ops
            for row in d['rows']:
                n=row['count'];assert type(n) is int and n>0 and n%3==0
                assert n==len(row['api_ns']) and all(type(t) is int and t>0 for t in row['api_ns'])
                if profile=='baseline':assert n==3
                elif LIB=='noble':assert n==192
                else:
                    p,o=rec['parameter'],rec['operation'];expected_n=(3 if p.endswith('s') else 60 if '128' in p else 36 if '192' in p else 18) if o=='sign' else (24 if p.endswith('s') else 1536 if '128' in p else 768 if '192' in p else 384) if o=='keygen' else (3072 if p.endswith('s') else 1536)
                    assert n==expected_n
                h=hashlib.sha256()
                for j in range(n):
                    c=cases[j%3]
                    for name in {'keygen':['publicKey','secretKey'],'getPublicKey':['publicKey'],'sign':['signature'],'verify':[]}[row['operation']]:h.update(bytes.fromhex(c[name]))
                    if row['operation']=='verify':h.update(b'\x01')
                assert h.hexdigest()==row['output_sha256'];calls+=n
            if profile=='resource':pairs[(rec['parameter'],rec['operation'],rec['settings'],rec['round'],rec['variant'])]=i
            processes+=1
    for p in affected:
        for o in ops:
            for s in ('default','constrained'):
                assert sum(pairs[(p,o,s,r,'baseline')]<pairs[(p,o,s,r,'candidate')] for r in range(4))==2
    out={'schema':LIB+'-resource-followup-portable-audit-v1','passed':True,'verifier_sha256':sha(Path(__file__).read_bytes()),'source_archive_sha256':sha(source.read_bytes()),'source_entries_verified':len(expected),'execution_sha256':execution_hashes,'processes':processes,'checked_calls':calls,'complete_declared_cells_and_balanced_orders':True,'all_raw_hashes_and_output_digests_verified':True,'requires_original_build_directories':False,'limitation':'Verifies archived selected source files/binaries and their bindings, not a new compiler rebuild or independent cryptographic implementation.'}
    target=RESULT/'portable-audit.json'
    if target.exists():assert json.loads(target.read_text())==out
    else:
        with target.open('x') as f:json.dump(out,f,indent=2);f.write('\n')
    print(json.dumps(out))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['package','verify']);a=p.parse_args();package() if a.mode=='package' else verify()
