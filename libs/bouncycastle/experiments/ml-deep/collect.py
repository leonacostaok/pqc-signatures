#!/usr/bin/env python3
"""Serial fresh-JVM screen. Requires an explicit external exclusive timing grant."""
import argparse, datetime, hashlib, json, os, random, subprocess, statistics
from pathlib import Path
import sys
if sys.flags.optimize:
    raise RuntimeError("Python optimization disables required checks; run without -O")
from prepare import digest, tree, ROOT, HERE
VARIANTS=['baseline','matrix','gamma','combined']
PARAMETERS=['ml_dsa_44','ml_dsa_65','ml_dsa_87']
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def hmap(obj): return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',required=True);p.add_argument('--out',required=True);p.add_argument('--rounds',type=int,default=2);p.add_argument('--profile-only',action='store_true');p.add_argument('--sampler-only',action='store_true');a=p.parse_args()
    assert (a.rounds>=2 and a.rounds%2==0) or (a.sampler_only and a.rounds==1)
    assert not (a.profile_only and a.sampler_only)
    path=Path(a.manifest).resolve();m=json.loads(path.read_text())
    def verify_provenance():
        assert m['environment']=={k:os.environ.get(k,'') for k in m['environment']}
        assert digest(Path(m['java']).resolve())==m['java_sha256']
        for name,h in m['inputs'].items(): assert digest(ROOT/name)==h,name
        for info in [*m['variants'].values(),*m['profiles'].values()]:
            assert tree(Path(info['classes']),'*.class')==info['binaries']
            assert tree(Path(info['classes']).with_name(Path(info['classes']).name+'-src'),'*.java')==info['source']
        for info in m['corpora'].values(): assert digest(Path(info['path']))==info['sha256']
    verify_provenance()
    out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
    (out/'manifest.json').write_text(json.dumps(m,indent=2)+'\n')
    lock=HERE.parents[1]/'build/ml-deep/.timing-lock';lock.mkdir()
    execution={'schema':'bc-ml-deep-execution-v1','started_at':now(),'manifest_sha256':digest(path),'rounds':a.rounds,'profile_only':a.profile_only,'sampler_only':a.sampler_only,'python_version':sys.version,'python_optimization':sys.flags.optimize,'runs':[]}
    flags=['-Xmx512m','-XX:ActiveProcessorCount=2']
    try:
        jobs=[]
        if a.profile_only:
            for parameter in PARAMETERS:
                for operation in ['sign','verify']:
                    for variant in ['baseline','combined']: jobs.append((0,parameter,operation,variant))
        else:
            cells=[(p,o) for p in PARAMETERS for o in (['matrix_sample','gamma_sample'] if a.sampler_only else ['sign','verify'])];random.Random(384710).shuffle(cells)
            for rnd in range(a.rounds):
                for index,(parameter,operation) in enumerate(cells):
                    order=VARIANTS.copy();random.Random(384711+index+rnd//2).shuffle(order)
                    if rnd%2: order.reverse()
                    for variant in order: jobs.append((rnd,parameter,operation,variant))
        (out/'plan.json').write_text(json.dumps(jobs,indent=2)+'\n')
        for index,(rnd,parameter,operation,variant) in enumerate(jobs):
            info=(m['profiles'] if a.profile_only else m['variants'])[variant]
            command=[m['java'],*flags,'-cp',info['classes'],'org.bouncycastle.crypto.signers.mldsa.MLDeep']
            if a.profile_only: command+=['profile',m['corpora']['measured']['path'],parameter,operation]
            else: command+=['bench',m['corpora']['warmup']['path'],m['corpora']['measured']['path'],parameter,operation,str(92841+rnd)]
            record={'index':index,'round':rnd,'fork':rnd,'variant':variant,'parameter':parameter,'operation':operation,'argv':command,'started_at':now()}
            result=subprocess.run(command,capture_output=True,text=True)
            record.update(completed_at=now(),exit_code=result.returncode)
            stderr=out/(str(index).zfill(3)+'.stderr');stderr.write_text(result.stderr);record['stderr_sha256']=digest(stderr)
            stdout=out/(str(index).zfill(3)+'.stdout.json');stdout.write_text(result.stdout);record['stdout']=stdout.name;record['stdout_sha256']=digest(stdout)
            raw=out/(str(index).zfill(3)+'.json');record['raw']=raw.name
            execution['runs'].append(record);(out/'execution.json').write_text(json.dumps(execution,indent=2)+'\n')
            assert result.returncode==0,(record,result.stderr)
            data=json.loads(result.stdout)
            assert data['parameter']==parameter and data['operation']==operation
            if not a.profile_only:
                assert len(data['samples'])==128 and {s['case_id'] for s in data['samples']}=={'measured/'+parameter+'/'+str(i) for i in range(128)}
                assert data['warmup']['iterations']==1000 and all(s['checked'] and s['inputs_unchanged'] and s['wall_ns']>0 and s['cpu_ns']>0 and s['allocated_bytes']>=0 for s in data['samples'])
            data.update(variant=variant,fork=rnd,round=rnd,corpus_sha256=m['corpora']['measured']['sha256'],warmup_corpus_sha256=m['corpora']['warmup']['sha256'],source_sha256=hmap(info['source']),class_tree_sha256=hmap(info['binaries']),java_version=m['java_version'],jvm_args=flags)
            raw.write_text(json.dumps(data,indent=2)+'\n');record['raw_sha256']=digest(raw)
            (out/'execution.json').write_text(json.dumps(execution,indent=2)+'\n')
            print(f'{index+1}/{len(jobs)} {variant} {parameter} {operation}',flush=True)
        verify_provenance()
        execution['completed_at']=now();(out/'execution.json').write_text(json.dumps(execution,indent=2)+'\n')
    finally: lock.rmdir()
    print(out/'execution.json')
if __name__=='__main__':main()
