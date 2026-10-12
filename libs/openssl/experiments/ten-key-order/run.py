#!/usr/bin/env python3
"""Ten new keys per parameter; candidate batch must precede baseline batch."""
import argparse
import datetime
import hashlib
import json
import pathlib
import statistics
import subprocess
import sys

if sys.flags.optimize:
    raise SystemExit('Assertions must remain enabled')
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BUILD = ROOT / 'libs/openssl/build/ten-key-order'
RESULTS = ROOT / 'results/openssl/ten-key-order'
PARAMETERS = [f'SLH-DSA-SHA2-{n}{s}' for n in (128, 192, 256) for s in ('f', 's')] + ['SLH-DSA-SHAKE-128f']
PIN = '122db7eb076bf0625df87b91bcc2dccfaccc4900'
CANDIDATE = 'cb722554afced3c3232104b15693c203734864cf'

def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def save(path, obj):
    with path.open('x') as f:
        json.dump(obj, f, indent=2); f.write('\n')

def run(command):
    return subprocess.run(list(map(str, command)), check=True, text=True, capture_output=True)

def inputs(path, parameter, domain):
    n = int(parameter.split('-')[-1][:-1]) // 8
    lines = [parameter]
    seeds = []
    for index in range(-1, 10):
        label = 'warmup' if index == -1 else str(index)
        def derive(kind, length):
            return hashlib.shake_256(f'pqc-ten-key-order-v1/openssl/{domain}/{parameter}/{label}/{kind}'.encode()).digest(length).hex()
        seed = derive('seed', 3*n); seeds.append(seed)
        msglen = 64 if index == -1 else [0,1,32,64,256,4096,17,128,1024,65][index]
        ctxlen = 17 if index == -1 else [0,1,17,255,0,3,31,64,128,2][index]
        lines += [seed, derive('message', msglen), derive('context', ctxlen)]
    assert len(set(seeds)) == 11
    path.write_text('\n'.join(lines)+'\n')

def rows(text, side, parameter):
    data = [json.loads(line) for line in text.splitlines()]
    assert len(data) == 10 and {r['key_index'] for r in data} == set(range(10))
    assert len({r['pk_hex'] for r in data}) == len({r['sk_hex'] for r in data}) == 10
    for r in data:
        assert r['variant'] == side and r['parameter'] == parameter
        assert r['verified'] is True and r['tamper_rejected'] is True
        for op in ('keygen','sign','verify'):
            assert type(r[op+'_wall_ns']) is int and r[op+'_wall_ns'] > 0
            assert type(r[op+'_cpu_ns']) is int and r[op+'_cpu_ns'] >= 0
    return data

def compare(a,b):
    assert len(a) == len(b)
    for x,y in zip(a,b):
        for key in ('parameter','key_index','message_bytes','context_bytes','pk_hex','sk_hex','sig_hex'):
            assert x[key] == y[key], key

def check_manifest(m):
    for path, value in m['hashes'].items():
        assert sha(path) == value, path

def prepare(args):
    BUILD.mkdir(parents=True, exist_ok=False)
    RESULTS.mkdir(parents=True, exist_ok=False)
    inp = RESULTS/'inputs'; inp.mkdir()
    commands = {}; binaries = {}; hashes = {}
    old = json.loads((ROOT/'results/openssl/experiments/sha512-prefix-final-gate.json').read_text())
    for side, source, pin in [('baseline',args.baseline_source,PIN),('candidate',args.candidate_source,CANDIDATE)]:
        source=source.resolve(); assert run(['git','-C',source,'rev-parse','HEAD']).stdout.strip()==pin
        run(['git','-C',source,'diff','--quiet','HEAD'])
        obj=ROOT/'libs/openssl/build/sha512-prefix'/side
        archive=obj/'libcrypto.a'; assert sha(archive)==old['identities'][side]['libcrypto.a']
        binary=BUILD/side
        command=['cc','-O2','-Wall','-Wextra','-I'+str(obj/'include'),'-I'+str(source/'include'),HERE/'driver.c',archive,'-lpthread','-o',binary]
        result=run(command); commands[side]={'command':list(map(str,command)),'stdout':result.stdout,'stderr':result.stderr}
        binaries[side]=str(binary); hashes[str(archive)]=sha(archive);hashes[str(binary)]=sha(binary)
    assert hashes[binaries['baseline']] != hashes[binaries['candidate']]
    for parameter in PARAMETERS:
        path=inp/(parameter+'.txt'); inputs(path,parameter,'measured'); hashes[str(path)]=sha(path)
    smoke=BUILD/'smoke.txt';inputs(smoke,PARAMETERS[0],'smoke')
    samples={}
    for side in ['candidate','baseline']:
        result=run([binaries[side],side,smoke]);samples[side]=rows(result.stdout,side,PARAMETERS[0])
        (BUILD/(side+'-smoke.jsonl')).write_text(result.stdout)
    compare(samples['candidate'],samples['baseline'])
    for path in [HERE/'driver.c',HERE/'run.py',HERE.parent/'sha512-prefix-driver.c']:
        hashes[str(path)]=sha(path)
    m={'schema':'openssl-ten-key-prepared-v1','prepared_at':stamp(),'baseline_commit':PIN,'candidate_commit':CANDIDATE,'parameters':PARAMETERS,'keys_per_parameter':10,'warmup_keys_per_parameter':1,'binaries':binaries,'hashes':hashes,'build':commands,'smoke_exact_outputs_and_tamper_passed':True,'compiler':run(['cc','--version']).stdout,'python':sys.version,'python_optimize':sys.flags.optimize}
    save(RESULTS/'prepared.json',m);print(RESULTS/'prepared.json')

def completion(side):
    out=RESULTS/side
    value=json.loads((out/'complete.json').read_text())
    assert value['complete'] is True and value['variant']==side and value['keys']==70
    assert value['manifest_sha256']==sha(RESULTS/'prepared.json')
    expected={p+'.jsonl' for p in PARAMETERS}
    assert set(value['raw_sha256'])==expected
    assert {p.name for p in out.glob('*.jsonl')}==expected
    for name,digest in value['raw_sha256'].items():
        assert sha(out/name)==digest,name
    assert datetime.datetime.fromisoformat(value['started_at']) < datetime.datetime.fromisoformat(value['finished_at'])
    return value

def collect(args):
    assert args.exclusive_window_granted
    m=json.loads((RESULTS/'prepared.json').read_text());check_manifest(m)
    side=args.side;out=RESULTS/side;out.mkdir(exist_ok=False)
    if side=='baseline':
        completion('candidate')
    started=stamp();allrows=[]
    for parameter in PARAMETERS:
        command=[m['binaries'][side],side,RESULTS/'inputs'/(parameter+'.txt')]
        save(out/(parameter+'.command.json'),{'command':list(map(str,command)),'started_at':stamp()})
        with (out/(parameter+'.jsonl')).open('x') as stdout,(out/(parameter+'.stderr')).open('x') as stderr:
            p=subprocess.run(list(map(str,command)),stdout=stdout,stderr=stderr)
        save(out/(parameter+'.status.json'),{'exit_code':p.returncode,'finished_at':stamp()})
        assert p.returncode==0
        data=rows((out/(parameter+'.jsonl')).read_text(),side,parameter);allrows+=data
        if side=='baseline':
            compare(data,rows((RESULTS/'candidate'/(parameter+'.jsonl')).read_text(),'candidate',parameter))
        check_manifest(m);print(side,parameter,'10 keys PASS',flush=True)
    assert len(allrows)==70
    save(out/'complete.json',{'complete':True,'variant':side,'started_at':started,'finished_at':stamp(),'keys':len(allrows),'manifest_sha256':sha(RESULTS/'prepared.json'),'raw_sha256':{p.name:sha(p) for p in sorted(out.glob('*.jsonl'))}})

def summarize(args):
    m=json.loads((RESULTS/'prepared.json').read_text());check_manifest(m)
    completions={side:completion(side) for side in ['candidate','baseline']}
    assert all(x['complete'] is True for x in completions.values())
    assert completions['candidate']['finished_at'] < completions['baseline']['started_at']
    summaries=[];pairs=[]
    for parameter in PARAMETERS:
        data={side:rows((RESULTS/side/(parameter+'.jsonl')).read_text(),side,parameter) for side in completions}
        compare(data['candidate'],data['baseline'])
        for op in ['keygen','sign','verify']:
            ratios=[]
            for a,b in zip(data['candidate'],data['baseline']):
                ratio=b[op+'_wall_ns']/a[op+'_wall_ns'];ratios.append(ratio)
                pairs.append({'parameter':parameter,'operation':op,'key_index':a['key_index'],'candidate_wall_ns':a[op+'_wall_ns'],'baseline_wall_ns':b[op+'_wall_ns'],'candidate_cpu_ns':a[op+'_cpu_ns'],'baseline_cpu_ns':b[op+'_cpu_ns'],'speedup':ratio})
            total={side:sum(r[op+'_wall_ns'] for r in records) for side,records in data.items()}
            summaries.append({'parameter':parameter,'operation':op,'keys':10,'median_key_speedup':statistics.median(ratios),'total_time_speedup':total['baseline']/total['candidate'],'min_key_speedup':min(ratios),'max_key_speedup':max(ratios),'key_losses':sum(x<1 for x in ratios),'total_wall_ns':total})
    save(RESULTS/'summary.json',{'complete':True,'scope':'one ten-key batch per parameter, all candidate before baseline; sensitivity check, not a balanced repeated benchmark','exact_outputs_match':True,'completions':completions,'pairs':pairs,'summary':summaries})
    for r in summaries:print(r['parameter'],r['operation'],round(r['total_time_speedup'],4),flush=True)

p=argparse.ArgumentParser();subs=p.add_subparsers(dest='command',required=True)
f=subs.add_parser('prepare');f.add_argument('--baseline-source',type=pathlib.Path,required=True);f.add_argument('--candidate-source',type=pathlib.Path,required=True)
f=subs.add_parser('run');f.add_argument('--side',choices=['candidate','baseline'],required=True);f.add_argument('--exclusive-window-granted',action='store_true')
subs.add_parser('summarize')
a=p.parse_args();{'prepare':prepare,'run':collect,'summarize':summarize}[a.command](a)
