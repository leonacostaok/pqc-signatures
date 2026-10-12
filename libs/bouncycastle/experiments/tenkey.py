#!/usr/bin/env python3
"""Sealed, one-pass ten-new-key sensitivity batches; final side order is coordinated externally."""
import argparse
import datetime
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys

if sys.flags.optimize:
    raise RuntimeError('run without optimized Python; assertions are required')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PROVIDER = HERE.parent.name
IS_RUST = PROVIDER == 'rustcrypto'
assert PROVIDER in ['rustcrypto', 'bouncycastle']
OLD = importlib.import_module('keygen' if IS_RUST else 'fors')
SOURCE = HERE / ('tenkey.rs' if IS_RUST else 'TenKeyBenchmark.java')
PARAMETERS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] if IS_RUST else [f'{a}_{b}{c}' for a in ['sha2','shake'] for b in [128,192,256] for c in ['f','s']]
OPERATIONS = ['keygen','sign','verify','keygen_sign'] if IS_RUST else ['keygen','sign','verify']
ENVIRONMENT = ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS']
JVM_ARGS = ['-Xmx512m','-XX:ActiveProcessorCount=2']


def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p): return json.loads(Path(p).read_text())
def write(p, value):
    with Path(p).open('x') as file: json.dump(value,file,indent=2); file.write('\n')


def persist(command, directory, stem, allowed=(0,), cwd=None, env=None):
    command=list(map(str,command))
    write(directory/(stem+'.command.json'),{'command':command,'cwd':str(cwd) if cwd else None,'started_at':stamp()})
    with (directory/(stem+'.stdout.txt')).open('x') as out, (directory/(stem+'.stderr.txt')).open('x') as err:
        p=subprocess.run(command,cwd=cwd,env=env,stdout=out,stderr=err)
    write(directory/(stem+'.status.json'),{'exit_code':p.returncode,'finished_at':stamp()})
    if p.returncode not in allowed: raise RuntimeError(f'{stem} exit {p.returncode}; logs retained in {directory}')
    return p.returncode,(directory/(stem+'.stdout.txt')).read_text()


def inputs():
    def derive(label,n):
        return b''.join(hashlib.sha256((label+'/'+str(i)).encode()).digest() for i in range((n+31)//32))[:n].hex()
    cases=[]
    for parameter in PARAMETERS:
        n=32 if IS_RUST else int(parameter.split('_')[1][:3])//8
        for phase,count in [('warmup',2),('measured',10)]:
            for i in range(count):
                prefix=f'pqc-tenkeys-v1/{PROVIDER}/{parameter}/{phase}/{i}'
                cases.append({'parameter':parameter,'phase':phase,'index':i,
                    'seed':derive(prefix+'/seed',32 if IS_RUST else 3*n),
                    'message':derive(prefix+'/message',[0,1,16,32,64,255,1024,4096,7,511][i]),
                    'context':derive(prefix+'/context',[0,1,31,255,0,255,1,31,32,7][i]),
                    'entropy':'00'*32 if IS_RUST else derive(prefix+'/entropy',n),
                    'pk':'','sk':'','signature':''})
    assert len({c['seed'] for c in cases})==len(cases)
    return {'version':'pqc-tenkeys-v1/'+PROVIDER,'cases':cases}


def input_file(directory, stem, corpus):
    path=directory/(stem+('.json' if IS_RUST else '.tsv'))
    if IS_RUST: write(path,corpus)
    else:
        fields=['phase','parameter','index','seed','message','context','entropy','pk','sk','signature']
        with path.open('x') as file:
            file.write(corpus['version']+'\n')
            for case in corpus['cases']: file.write('\t'.join(str(case[k]) for k in fields)+'\n')
    return path


def command(m, mode, source, parameter, side):
    if IS_RUST: return [m['binary'],mode,source,parameter,side]
    return [m['old']['java'],*JVM_ARGS,'-cp',os.pathsep.join([m['driver'],m['old'][side]]),
        'TenKeyBenchmark',mode,source,parameter,side]


def provenance(m):
    result={'collector':sha(__file__),'driver_source':sha(SOURCE),'original':OLD.provenance(m['old']),
        'corpus':sha(m['corpus']),'fixtures':sha(m['fixtures'])}
    if IS_RUST:
        result.update(binary=sha(m['binary']),cargo_manifest=sha(m['cargo_manifest']),cargo_lock=sha(m['cargo_lock']),
            driver_copy=sha(Path(m['cargo_manifest']).parent/'src/main.rs'))
    else: result.update(driver_classes=OLD.tree(m['driver']),java_binary=sha(m['old']['java']))
    return result


def validate(rows, corpus, parameter, side, measured, m):
    cases=[c for c in corpus['cases'] if c['parameter']==parameter and (not measured or c['phase']=='measured')]
    assert len(rows)==len(cases)==(10 if measured else 12)
    for row,case in zip(rows,cases):
        for key in ['parameter','phase','index','seed']: assert row[key]==case[key],key
        assert row['variant']==side and row['valid'] is True and row['tamper_rejected'] is True
        if not IS_RUST: assert row['class_source']==str(Path(m['old'][side]).resolve())
        for key in ['pk','sk','signature']:
            assert row[key] and bytes.fromhex(row[key])
            if case[key]: assert row[key]==case[key],key
        if measured:
            assert set(row['metrics'])==set(OPERATIONS)
            for metric in row['metrics'].values():
                assert type(metric['elapsed_ns']) is int and metric['elapsed_ns']>0
                assert type(metric['cpu_ns']) is int and metric['cpu_ns']>=0
                if not IS_RUST: assert type(metric['thread_cpu_ns']) is int and metric['thread_cpu_ns']>=0
        else: assert 'metrics' not in row


def prepare(args):
    old=read(args.original)
    assert old['provenance']==OLD.provenance(old)
    if IS_RUST: assert old['compiler_environment']==OLD.compiler_environment()
    else:
        assert old['jvm_environment']=={k:os.environ.get(k,'') for k in old['jvm_environment']}
        assert subprocess.run([old['java'],'-version'],capture_output=True,text=True,check=True).stderr==old['java_version']
    identity=sha(__file__)+sha(SOURCE)+json.dumps(old['provenance'],sort_keys=True)
    dest=OLD.BUILD/('tenkey-'+hashlib.sha256(identity.encode()).hexdigest()[:16]); dest.mkdir(exist_ok=False)
    checks=dest/'checks'; checks.mkdir()
    corpus=inputs()
    if IS_RUST:
        prior={c['seed'] for c in read(old['corpus'])['cases']}
        assert not prior.intersection(c['seed'] for c in corpus['cases'])
    else:
        prior=Path(old['fixtures']).read_bytes()
        assert all(bytes.fromhex(c['seed']) not in prior for c in corpus['cases'])
    source=input_file(dest,'corpus',corpus)
    m={'schema':'pqc-tenkey-prepared-v1','provider':PROVIDER,'old':old,'corpus':str(source),
        'parameters':PARAMETERS,'operations':OPERATIONS,'measured_keys':10,'warmup_keys':2,
        'entropy':'public deterministic signing with zero entropy' if IS_RUST else 'explicit per-key deterministic signing entropy',
        'environment':OLD.compiler_environment() if IS_RUST else {k:os.environ.get(k,'') for k in ENVIRONMENT},
        'jvm_args':None if IS_RUST else JVM_ARGS,'python':sys.version,'python_optimize':sys.flags.optimize,
        'scope':'one keygen, ordinary sign and verify per new key; verifier/key decoding outside verify/sign clocks; fresh signer/verifier initialization inside BC clocks; output encoding, equality, tamper checks and key drop outside clocks; Rust additional fresh-key-sign retains key until after clock',
        'warmup_policy':'exactly two complete disjoint key pipelines per parameter/variant; bounded warmup is not a steady-state guarantee',
        'cpu_clock':'getrusage process CPU, microsecond resolution' if IS_RUST else 'process CPU may quantize to zero for single calls; current-thread CPU retained separately'}
    if IS_RUST:
        cargo=dest/'Cargo.toml'
        cargo.write_text('[package]\nname="mldsa-keygen-experiment"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\n'+
            '\n'.join(f'{s} = {{ package = "ml-dsa-{s}", path = "{old[s+"_source"]}/ml-dsa", features = ["zeroize"] }}' for s in ['baseline','candidate'])+
            '\nserde={version="=1.0.228",features=["derive"]}\nserde_json="=1.0.150"\nhex="=0.4.3"\nlibc="=0.2.186"\n')
        (dest/'src').mkdir(); shutil.copyfile(SOURCE,dest/'src/main.rs'); shutil.copyfile(old['cargo_lock'],dest/'Cargo.lock')
        persist(['cargo','build','--release','--offline','--locked'],checks,'build',cwd=dest,env=dict(os.environ,CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0'))
        m.update(binary=str(dest/'target/release/mldsa-keygen-experiment'),cargo_manifest=str(cargo),cargo_lock=str(dest/'Cargo.lock'),
            compiler=subprocess.check_output(['rustc','-Vv'],text=True))
    else:
        classes=dest/'driver'; classes.mkdir()
        persist([Path(old['java']).with_name('javac'),'--release','8','-cp',old['baseline'],'-d',classes,SOURCE],checks,'build')
        m['driver']=str(classes)
    fixtures=json.loads(json.dumps(corpus))
    gate_rows=[]
    for parameter in PARAMETERS:
        matched={}
        for side in ['candidate','baseline']:
            print(f'Untimed correctness {parameter} {side}',flush=True)
            _,out=persist(command(m,'check',source,parameter,side),checks,parameter+'-'+side)
            rows=[json.loads(line) for line in out.splitlines()]; validate(rows,corpus,parameter,side,False,m); matched[side]=rows
        for changed,original in zip(matched['candidate'],matched['baseline']):
            for k in ['parameter','phase','index','seed','pk','sk','signature','valid','tamper_rejected']: assert changed[k]==original[k],k
            target=next(c for c in fixtures['cases'] if (c['parameter'],c['phase'],c['index'])==(parameter,original['phase'],original['index']))
            for k in ['pk','sk','signature']: target[k]=original[k]
        gate_rows.extend(matched['baseline'])
    fixture_path=input_file(dest,'fixtures',fixtures); m['fixtures']=str(fixture_path)
    bad=json.loads(json.dumps(fixtures)); first=bad['cases'][0]; first['pk']=('00' if first['pk'][:2]!='00' else '01')+first['pk'][2:]
    bad_path=input_file(dest,'negative-fixture',bad)
    code,out=persist(command(m,'bench',bad_path,PARAMETERS[0],'candidate'),checks,'reject-corrupt-warmup',allowed=(1,101))
    assert code!=0 and not out, 'corrupt warmup must fail before any measured output'
    invalid_command=command(m,'check',source,PARAMETERS[0],'candidate'); invalid_command[-1]='invalid'
    code,out=persist(invalid_command,checks,'reject-invalid-side',allowed=(1,101))
    assert code!=0 and not out
    m['correctness']={'parameters':len(PARAMETERS),'matched_cases':len(fixtures['cases']),
        'measured_seed_cases':10*len(PARAMETERS),'valid_per_variant':len(fixtures['cases']),
        'tamper_per_variant':len(fixtures['cases']),'exact_keys_and_signatures':True,
        'no_timing_metrics_in_checks':True,'corrupt_warmup_rejected_before_measurement':True,'invalid_side_rejected':True,
        'seeds_distinct_and_disjoint_from_old_corpus':True}
    m['provenance']=provenance(m)
    write(dest/'manifest.json',m)
    evidence=ROOT/'results'/PROVIDER/'experiments'/dest.name; evidence.mkdir(exist_ok=False)
    for p in checks.iterdir(): shutil.copyfile(p,evidence/p.name)
    for p in [source,fixture_path,dest/'manifest.json']: shutil.copyfile(p,evidence/p.name)
    if IS_RUST:
        shutil.copyfile(cargo,evidence/'Cargo.toml'); shutil.copyfile(dest/'Cargo.lock',evidence/'Cargo.lock')
    print(dest/'manifest.json')


def batch(args):
    m=read(args.manifest)
    assert m['schema']=='pqc-tenkey-prepared-v1' and m['provider']==PROVIDER
    assert m['parameters']==PARAMETERS and m['operations']==OPERATIONS and m['measured_keys']==10 and m['warmup_keys']==2
    assert m['correctness']['exact_keys_and_signatures'] and m['correctness']['corrupt_warmup_rejected_before_measurement']
    assert m['provenance']==provenance(m)
    assert m['environment']==(OLD.compiler_environment() if IS_RUST else {k:os.environ.get(k,'') for k in ENVIRONMENT})
    assert m['jvm_args']==(None if IS_RUST else JVM_ARGS) and m['python_optimize']==0
    if args.variant=='baseline':
        assert args.candidate, 'baseline requires its completed candidate result'
        candidate=read(args.candidate); assert candidate['variant']=='candidate' and candidate['manifest_sha256']==sha(args.manifest)
        assert len(candidate['rows'])==10*len(PARAMETERS)
    output=Path(args.out).resolve(); assert not output.exists()
    raw=Path(str(output)+'.raw'); raw.mkdir(parents=True,exist_ok=False)
    lock=OLD.BUILD/'.timing-lock'; lock.mkdir()
    rows=[]; started=stamp()
    try:
        write(raw/'plan.json',{'prepared':m,'variant':args.variant,'started_at':started,'manifest_sha256':sha(args.manifest),
            'policy':'one pass; all candidate side batches across providers precede every baseline batch; no exclusions; no control normalization'})
        corpus=inputs()
        # Expected exact bytes are derived in preparation, while the input corpus fixes seed ordering.
        for parameter in PARAMETERS:
            print(f'Fresh process {args.variant}: {parameter}, ten new keys',flush=True)
            _,out=persist(command(m,'bench',m['fixtures'],parameter,args.variant),raw,parameter)
            current=[json.loads(line) for line in out.splitlines()]
            validate(current,corpus,parameter,args.variant,True,m)
            rows.extend(current); write(raw/(parameter+'.rows.json'),current)
            assert m['provenance']==provenance(m)
        result={'schema':'pqc-tenkey-batch-v1','provider':PROVIDER,'variant':args.variant,'prepared':m,
            'manifest_sha256':sha(args.manifest),'started_at':started,'finished_at':stamp(),
            'host':platform.platform(),'arch':platform.machine(),'python_optimize':0,'raw_directory':str(raw),'rows':rows}
        write(output,result); print(output)
    finally: lock.rmdir()


def compare(args):
    a,b=read(args.candidate),read(args.baseline)
    assert a['variant']=='candidate' and b['variant']=='baseline' and a['provider']==b['provider']==PROVIDER
    assert a['manifest_sha256']==b['manifest_sha256'] and a['finished_at']<b['started_at']
    assert len(a['rows'])==len(b['rows'])==10*len(PARAMETERS)
    for x,y in zip(a['rows'],b['rows']):
        for k in ['parameter','phase','index','seed','pk','sk','signature','valid','tamper_rejected']: assert x[k]==y[k],k
    summaries=[]
    for p in PARAMETERS:
        changed=[x for x in a['rows'] if x['parameter']==p]; original=[x for x in b['rows'] if x['parameter']==p]
        assert [x['index'] for x in changed]==[x['index'] for x in original]==list(range(10))
        for op in OPERATIONS:
            ratios=[y['metrics'][op]['elapsed_ns']/x['metrics'][op]['elapsed_ns'] for x,y in zip(changed,original)]
            ct=sum(x['metrics'][op]['elapsed_ns'] for x in changed); bt=sum(x['metrics'][op]['elapsed_ns'] for x in original)
            cc=sum(x['metrics'][op]['cpu_ns'] for x in changed); bc=sum(x['metrics'][op]['cpu_ns'] for x in original)
            s={'parameter':p,'operation':op,'baseline_wall_total_ns':bt,'candidate_wall_total_ns':ct,'speedup':bt/ct,
                'key_ratios':ratios,'median_key_ratio':statistics.median(ratios),'min_key_ratio':min(ratios),'max_key_ratio':max(ratios),
                'losses':sum(r<1 for r in ratios),'baseline_cpu_total_ns':bc,'candidate_cpu_total_ns':cc,
                'cpu_speedup':bc/cc if cc else None,'zero_cpu_samples':sum(x['metrics'][op]['cpu_ns']==0 for x in changed+original)}
            if not IS_RUST:
                s['baseline_thread_cpu_total_ns']=sum(x['metrics'][op]['thread_cpu_ns'] for x in original)
                s['candidate_thread_cpu_total_ns']=sum(x['metrics'][op]['thread_cpu_ns'] for x in changed)
            summaries.append(s)
    write(args.out,{'schema':'pqc-tenkey-comparison-v1','provider':PROVIDER,'candidate_sha256':sha(args.candidate),
        'baseline_sha256':sha(args.baseline),'primary_statistic':'sum of original wall time for ten keys divided by sum of changed wall time for matching ten keys',
        'limitation':'one-pass, candidate-first sensitivity check; fixed order and limited warmup; no exclusions; not repeated throughput evidence',
        'candidate_started_at':a['started_at'],'candidate_finished_at':a['finished_at'],
        'baseline_started_at':b['started_at'],'baseline_finished_at':b['finished_at'],'summary':summaries})
    print(args.out)


def main():
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare'); p.add_argument('--original',required=True)
    p=sub.add_parser('batch'); p.add_argument('--manifest',required=True); p.add_argument('--variant',choices=['candidate','baseline'],required=True)
    p.add_argument('--out',required=True); p.add_argument('--candidate')
    p=sub.add_parser('compare'); p.add_argument('--candidate',required=True); p.add_argument('--baseline',required=True); p.add_argument('--out',required=True)
    args=parser.parse_args(); {'prepare':prepare,'batch':batch,'compare':compare}[args.command](args)

if __name__=='__main__': main()
