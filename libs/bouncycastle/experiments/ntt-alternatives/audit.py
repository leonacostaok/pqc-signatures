#!/usr/bin/env python3
"""Read-only independent source/corpus/raw arithmetic checker; never runs cryptography."""
import argparse,hashlib,io,json,os,struct,sys,tarfile
from pathlib import Path
if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
    raise RuntimeError('Python optimization is forbidden, including PYTHONOPTIMIZE')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def hmap(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def read_corpus(p):
    f=io.BytesIO(Path(p).read_bytes())
    def read(n):
        b=f.read(n);assert len(b)==n;return b
    def u32():return struct.unpack('>I',read(4))[0]
    def utf():return read(struct.unpack('>H',read(2))[0]).decode('ascii')
    assert u32()==0x4d4c4431
    out={}
    for _ in range(u32()):
        parameter,case=utf(),utf();data=[read(u32())for _ in range(7)];assert case not in out;out[case]=(parameter,data)
    assert f.read()==b'';return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--plan',required=True);p.add_argument('--timing');p.add_argument('--allocation');p.add_argument('--out',required=True);a=p.parse_args()
    pp=Path(a.plan).resolve();plan=json.loads(pp.read_text());mp=pp.parent.parent/Path(plan['manifest']).parent.name/'manifest.json';assert sha(mp)==plan['manifest_sha256'];m=json.loads(mp.read_text());base=mp.parent
    assert m['upstream']=='c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
    archive=base/'baseline-source.tar.gz';assert sha(archive)==m['source_archive_sha256']
    with tarfile.open(archive,'r:gz')as tar:baseline={x.name:hashlib.sha256(tar.extractfile(x).read()).hexdigest()for x in tar.getmembers()if x.isfile()and x.name.endswith('.java')}
    binary_available=True
    for variant,info in m['variants'].items():
        overlay=base/'overlays'/variant/'Ntt.java';expected=baseline.copy();expected['core/src/main/java/org/bouncycastle/crypto/signers/mldsa/Ntt.java']=sha(overlay)
        assert expected==info['source_hashes']and hmap(expected)==info['source_identity']
        changed=[k for k in expected if expected[k]!=baseline[k]];assert changed==([]if variant=='baseline'else['core/src/main/java/org/bouncycastle/crypto/signers/mldsa/Ntt.java'])
        classes=Path(info['classes'])
        if classes.exists():assert {str(f.relative_to(classes)):sha(f)for f in classes.rglob('*.class')}==info['class_hashes']
        else:binary_available=False
        assert info['correctness']=={'operation_checks':432,'negative_checks':288,'inputs_preserved':True}
        assert info['arithmetic']['passed']and info['arithmetic']['sparse_products']==108 and info['arithmetic']['inverse_vectors']==516
        assert info['malformed']=={'cases':72,'checks':936,'ownership':True}
        for gate in ['arithmetic','correctness','malformed']:
            assert json.loads((base/'logs'/(variant+'-'+gate+'.stdout')).read_text())==info[gate]
            assert json.loads((base/'logs'/(variant+'-'+gate+'.status.json')).read_text())['exit_code']==0
    driver=Path(m['driver']['path'])
    if driver.exists():assert {str(f.relative_to(driver)):sha(f)for f in driver.rglob('*.class')}==m['driver']['class_hashes']
    else:binary_available=False
    runtime_available=True
    for name,expected in m['runtime_files'].items():
        path=Path(name)
        if path.exists():assert sha(path)==expected
        else:runtime_available=False
    root=Path(__file__).resolve().parents[4]
    for name,expected in plan['collector_inputs'].items():assert sha(root/name)==expected
    for name,expected in m['portable_hashes'].items():assert sha(base/name)==expected
    for label,info in m['corpora'].items():assert sha(base/'fixtures'/(label+'.bin'))==info['sha256']
    cases=read_corpus(base/'fixtures/measured.bin');warm=read_corpus(base/'fixtures/warmup.bin');assert len(cases)==384
    measured_seeds={d[0]for _,d in cases.values()};warm_seeds={d[0]for _,d in warm.values()};assert len(measured_seeds)==384 and not measured_seeds.intersection(warm_seeds)
    for pair in [0,2]:
        for mode in ['timing','allocation']:
            for param in plan['parameters']:
                for op in plan['operations']:
                    orders=[[j['variant']for j in plan['jobs']if j['round']==r and j['mode']==mode and j['parameter']==param and j['operation']==op]for r in [pair,pair+1]]
                    assert orders[0]==list(reversed(orders[1]))and set(orders[0])==set(plan['variants'])
    results={};runs_checked=0;rows_checked=0
    for mode,folder in [('timing',a.timing),('allocation',a.allocation)]:
        if not folder:continue
        folder=Path(folder);ex=json.loads((folder/'execution.json').read_text());assert ex['plan_sha256']==sha(pp)and ex['manifest_sha256']==sha(mp)and ex['provenance_after']and ex['completed_at']
        expected=[j for j in plan['jobs']if j['mode']==mode];assert len(ex['runs'])==len(expected)==144
        for run,job in zip(ex['runs'],expected):
            assert all(run[k]==v for k,v in job.items());assert run['exit_code']==0
            for stream in ['stdout','stderr']:assert sha(folder/run[stream])==run[stream+'_sha256']
            data=json.loads((folder/run['stdout']).read_text());assert all(data[k]==job[k]for k in ['mode','variant','parameter','operation']);assert data['warmup_calls']==1000 and data['warmup_keys']==2
            samples=data['samples'];assert len(samples)==128 and len({s['case_id']for s in samples})==128
            assert {s['case_id']for s in samples}=={k for k,(param,_)in cases.items()if param==job['parameter']}
            for s in samples:
                param,d=cases[s['case_id']];op=job['operation'];b=d[4]+d[5]if op=='keygen'else d[6]if op=='sign'else b'\1';assert s['output_sha256']==hashlib.sha256(b).hexdigest();assert s['checked']and s['inputs_unchanged']
                if mode=='timing':assert s['wall_ns']>0 and s['cpu_ns']>0 and 'allocated_bytes'not in s
                else:assert s['allocated_bytes']>=0 and 'wall_ns'not in s and 'cpu_ns'not in s
            results[(mode,job['round'],job['parameter'],job['operation'],job['variant'])]={s['case_id']:s for s in samples};runs_checked+=1;rows_checked+=128
    summary=[]
    for param in plan['parameters']:
        for op in plan['operations']:
            for variant in plan['variants'][1:]:
                row={'parameter':param,'operation':op,'variant':variant}
                for mode,fields in [('timing',['wall_ns','cpu_ns']),('allocation',['allocated_bytes'])]:
                    if (mode,0,param,op,variant)not in results:continue
                    for field in fields:
                        base_sum=changed_sum=losses=0;ratios=[]
                        for r in range(4):
                            b=results[(mode,r,param,op,'baseline')];c=results[(mode,r,param,op,variant)];assert set(b)==set(c)
                            bs=sum(x[field]for x in b.values());cs=sum(x[field]for x in c.values());base_sum+=bs;changed_sum+=cs;losses+=sum(c[k][field]>b[k][field]for k in b);ratios.append(bs/cs if cs else None)
                        row[field]={'original_sum':base_sum,'changed_sum':changed_sum,'original_mean':base_sum/512,'changed_mean':changed_sum/512,'original_over_changed':base_sum/changed_sum if changed_sum else None,'percent_change':100*(changed_sum/base_sum-1)if base_sum else None,'changed_larger_keys':losses,'round_original_over_changed':ratios,'paired_observations':512}
                summary.append(row)
    report={'schema':'bc-ntt-audit-v1','passed':True,'plan_sha256':sha(pp),'manifest_sha256':sha(mp),'portable_source_and_fixture_checks':True,'local_binary_checks':'passed'if binary_available else'unavailable; one or more local class trees absent','local_runtime_checks':'passed'if runtime_available else'unavailable; one or more pinned runtime files absent','processes_checked':runs_checked,'output_rows_checked':rows_checked,'summary':summary}
    with Path(a.out).open('x')as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in report.items()if k!='summary'},indent=2))
if __name__=='__main__':main()
