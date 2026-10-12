#!/usr/bin/env python3
"""Predeclare a balanced screen; collect only after a root-granted exclusive window."""
import argparse,datetime,hashlib,json,os,platform,random,subprocess,sys
from pathlib import Path
if sys.flags.optimize or os.environ.get('PYTHONOPTIMIZE'):
    raise RuntimeError('Python optimization is forbidden, including PYTHONOPTIMIZE')
from prepare import ROOT,HERE,VARIANTS,PARAMETERS,JVM,digest,tree,hmap,stamp,write

def verify(m,plan):
    assert m['environment']=={k:os.environ.get(k,'')for k in m['environment']},'environment changed'
    for p,h in m['runtime_files'].items():assert digest(p)==h,('runtime',p)
    for p,h in m['inputs'].items():assert digest(ROOT/p)==h,('preparation input',p)
    for p,h in plan['collector_inputs'].items():assert digest(ROOT/p)==h,('collector input',p)
    for v,info in m['variants'].items():
        assert tree(Path(info['source']),'.java')==info['source_hashes'],('sources',v)
        assert tree(Path(info['classes']),'.class')==info['class_hashes'],('classes',v)
    assert tree(Path(m['driver']['path']),'.class')==m['driver']['class_hashes']
    for info in m['corpora'].values():assert digest(info['path'])==info['sha256']
    assert digest(m['source_archive'])==m['source_archive_sha256']

def jobs(m):
    result=[];cells=[(p,o)for p in PARAMETERS for o in ['keygen','sign','verify']];random.Random(771204).shuffle(cells)
    for mode in ['timing','allocation']:
        for roundno in range(4):
            for ci,(param,op)in enumerate(cells):
                order=VARIANTS.copy();random.Random(771205+ci+100*(roundno//2)).shuffle(order)
                if roundno%2:order.reverse()
                for variant in order:
                    argv=[m['java'],*JVM,'-cp',os.pathsep.join([m['driver']['path'],m['variants'][variant]['classes']]),'org.bouncycastle.crypto.signers.mldsa.NTTBench',mode,m['corpora']['warmup']['path'],m['corpora']['measured']['path'],param,op,str(928410+roundno),variant]
                    result.append({'index':len(result),'mode':mode,'round':roundno,'parameter':param,'operation':op,'variant':variant,'argv':argv})
    return result

def make_plan(a):
    mp=Path(a.manifest).resolve();m=json.loads(mp.read_text());out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
    plan={'schema':'bc-ntt-plan-v1','created_at':stamp(),'manifest':str(mp),'manifest_sha256':digest(mp),'collector_inputs':{str(p.relative_to(ROOT)):digest(p)for p in sorted(HERE.glob('*'))if p.is_file()and p.suffix in ['.py','.java']},'rounds':4,'pairs':2,'variants':VARIANTS,'parameters':PARAMETERS,'operations':['keygen','sign','verify'],'warmup_calls':1000,'warmup_keys_per_parameter':2,'measured_keys_per_parameter':128,'measured_calls_per_key_per_process':1,'cohorts_separate':True,'timing_counters':['wall_ns','cpu_ns'],'allocation_counters':['allocated_bytes'],'boundary':'Fresh lightweight setup and operation. Expanded-key import, caller copies, keygen encoding, output checks, negative checks, and ownership checks excluded. No persistent key/matrix cache.','screen_promotion_rule':'Exploratory candidate for confirmation only if a cell improves aggregate wall and calling-thread CPU by at least 3%, all four wall rounds improve, and no other cell has both aggregate wall regression above 3% and all four wall rounds slower. Preserve every smaller loss and all allocations; no significance or universal win is established.','jobs':jobs(m)}
    verify(m,plan);write(out/'protocol.json',plan);print(out/'protocol.json');print(digest(out/'protocol.json'))

def collect(a):
    pp=Path(a.plan).resolve();plan=json.loads(pp.read_text());mp=Path(plan['manifest']);assert digest(mp)==plan['manifest_sha256'];m=json.loads(mp.read_text());assert plan['jobs']==jobs(m);verify(m,plan)
    out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
    lock=ROOT.parent.parent/'.bc-ntt-timing-lock';lock.mkdir()
    selected=[j for j in plan['jobs']if j['mode']==a.mode]
    ex={'schema':'bc-ntt-execution-v1','mode':a.mode,'started_at':stamp(),'plan_sha256':digest(pp),'manifest_sha256':digest(mp),'exclusive_window_grant':a.exclusive_window_grant,'python':sys.version,'python_optimization':sys.flags.optimize,'machine':platform.uname()._asdict(),'runs':[]}
    (out/'execution.json').write_text(json.dumps(ex,indent=2)+'\n')
    try:
        for j in selected:
            stem=str(j['index']).zfill(3);r={**j,'started_at':stamp(),'stdout':stem+'.stdout','stderr':stem+'.stderr'};ex['runs'].append(r)
            (out/'execution.json').write_text(json.dumps(ex,indent=2)+'\n')
            with (out/r['stdout']).open('x')as stdout,(out/r['stderr']).open('x')as stderr:p=subprocess.run(j['argv'],stdout=stdout,stderr=stderr)
            r.update(exit_code=p.returncode,completed_at=stamp(),stdout_sha256=digest(out/r['stdout']),stderr_sha256=digest(out/r['stderr']))
            (out/'execution.json').write_text(json.dumps(ex,indent=2)+'\n')
            assert p.returncode==0,('process failed',stem)
            data=json.loads((out/r['stdout']).read_text());assert all(data[k]==j[k]for k in ['mode','parameter','operation','variant'])
            assert data['warmup_calls']==1000 and data['warmup_keys']==2 and len(data['samples'])==128
            assert {s['case_id']for s in data['samples']}=={'measured/'+j['parameter']+'/'+str(i)for i in range(128)}
            assert all(s['checked']and s['inputs_unchanged']for s in data['samples'])
            if a.mode=='timing':assert all(s['wall_ns']>0 and s['cpu_ns']>0 and 'allocated_bytes'not in s for s in data['samples'])
            else:assert all(s['allocated_bytes']>=0 and 'wall_ns'not in s and 'cpu_ns'not in s for s in data['samples'])
            print(f"{len(ex['runs'])}/{len(selected)} {j['variant']} {j['parameter']} {j['operation']} round{j['round']}",flush=True)
        verify(m,plan);ex['completed_at']=stamp();ex['provenance_after']=True;(out/'execution.json').write_text(json.dumps(ex,indent=2)+'\n')
    finally:lock.rmdir()
    print(out/'execution.json')

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    s=sub.add_parser('plan');s.add_argument('--manifest',required=True);s.add_argument('--out',required=True)
    s=sub.add_parser('collect');s.add_argument('--plan',required=True);s.add_argument('--mode',choices=['timing','allocation'],required=True);s.add_argument('--out',required=True);s.add_argument('--exclusive-window-grant',required=True)
    a=p.parse_args();make_plan(a)if a.command=='plan'else collect(a)
if __name__=='__main__':main()
