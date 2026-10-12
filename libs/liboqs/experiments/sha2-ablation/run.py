"""Build, validate, seal and measure four SHA-2 backend variants serially."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
E=HERE/'evidence'
BUILD=ROOT/'libs/liboqs/build/sha2-ablation'
REPO=ROOT/'libs/liboqs/deps/liboqs'
FULL='b14f1b616f938698ebc0bf8b75b3736c30e1502c'
BASE='fd44469daeffe6b28f031f54f9bb66cbae69a572'
VARIANTS=['original','sha256-only','sha512-only','full']
ORDERS=[['original','sha256-only','sha512-only','full'],['full','sha512-only','sha256-only','original'],['sha256-only','full','original','sha512-only'],['sha512-only','original','full','sha256-only'],['full','original','sha512-only','sha256-only'],['sha256-only','sha512-only','original','full']]
SPEC=importlib.util.spec_from_file_location('reviewed_ten_key_runner',HERE.parent/'ten-new-keys/run.py')
OLD=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(OLD)
PARAMS=OLD.PARAMETERS
DRIVER=HERE.parent/'ten-new-keys/driver.c'
SOURCES={'original':REPO,'full':REPO/'worktrees/sha2-performance',**{v:REPO/'worktrees'/('ablation-'+v) for v in VARIANTS[1:3]}}
BUILDS={'original':ROOT/'libs/liboqs/build/sha2-openssl/baseline','full':ROOT/'libs/liboqs/build/sha2-openssl/candidate',**{v:BUILD/v for v in VARIANTS[1:3]}}
DRIVERS={'original':ROOT/'libs/liboqs/build/ten-new-keys/baseline/driver','full':ROOT/'libs/liboqs/build/ten-new-keys/candidate/driver',**{v:BUILD/v/'driver' for v in VARIANTS[1:3]}}

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(p,v):
    with Path(p).open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def git(source,*args):return subprocess.check_output(['git','-C',str(source),*args])

def check_completed(entries,ready_sha,artifact_sha):
    need([(r['round'],r['variant']) for r in entries]==[(i+1,v) for i,o in enumerate(ORDERS) for v in o],'missing/duplicate/reordered batches')
    for r in entries:
        need(r['complete'] is True and r['returncode']==0,'failed batch')
        need(r['ready_sha256']==ready_sha and r['artifact_sha256']==artifact_sha,'changed evidence binding')

def check_command_status(variant,folder,command,status):
    need(command['command']==[str(DRIVERS[variant]),str(E/'inputs.bin'),str(folder/'outputs.bin'),'10'],'wrong executable/input/output/count')
    need(status['returncode']==0,'failed native invocation')
    start=datetime.datetime.fromisoformat(command['started_utc']);finish=datetime.datetime.fromisoformat(status['finished_utc'])
    need(start.tzinfo is not None and finish.tzinfo is not None and start<finish,'invalid invocation chronology')

def logged(cmd,path):
    cmd=list(map(str,cmd)); started=now()
    p=subprocess.run(cmd,capture_output=True,text=True)
    save(path,dict(command=cmd,started_utc=started,finished_utc=now(),returncode=p.returncode,stdout=p.stdout,stderr=p.stderr))
    need(p.returncode==0,'command failed: '+str(path))
    return p

def identities():
    prior=OLD.old_identities()
    ten_ready=HERE.parent/'ten-new-keys/evidence/ready.json'
    ten=json.loads(ten_ready.read_text());need(ten['complete'] is True,'prior ten-key seal incomplete')
    for v,old_v in [('original','baseline'),('full','candidate')]:need(sha(DRIVERS[v])==ten['identity']['drivers'][old_v],'reused driver differs from prior seal')
    need(sha(DRIVER)==ten['identity']['sources']['driver.c'] and sha(HERE.parent/'ten-new-keys/run.py')==ten['identity']['sources']['run.py'],'reviewed helper/driver differs from prior seal')
    oldseal=json.loads((HERE.parent/'sha2-openssl/evidence/final-paired/ready-manifest.json').read_text())
    source_maps={}
    for v in VARIANTS:
        expected_commit=BASE if v=='original' else FULL
        need(git(SOURCES[v],'rev-parse','HEAD').decode().strip()==expected_commit,'variant HEAD changed')
        if v in ('original','full'):
            need(git(SOURCES[v],'diff','HEAD')==b'','original/full tracked sources changed')
        else:
            need(git(SOURCES[v],'diff',BASE)==(HERE/(v+'.patch')).read_bytes(),'reduced source/patch mismatch')
        source_maps[v]={p:(sha(SOURCES[v]/p) if (SOURCES[v]/p).exists() else None) for p in oldseal['source_files']}
        need({p for p,h in source_maps[v].items() if h is None}==({'tests/test_slh_dsa_sha2.c','src/sig/slh_dsa/patches/sha2_openssl.patch'} if v=='original' else set()),'unexpected missing source')
    return dict(original=prior,variant_source_hashes=source_maps,
        sources={str(p):sha(p) for p in [DRIVER,HERE.parent/'ten-new-keys/run.py',HERE/'run.py',HERE/'check_runner.py',HERE/'check_hashes.py',HERE/'backend_probe.c',HERE/'README.md',*[HERE/(v+'.patch') for v in VARIANTS[1:3]],HERE/'minimal-runtime.patch']},
        build_files={v:{str(p):sha(p) for p in [BUILDS[v]/'lib/liboqs.a',BUILDS[v]/'CMakeCache.txt',BUILDS[v]/'src/sig/slh_dsa/CMakeFiles/slh_dsa_c.dir/flags.make',DRIVERS[v]]} for v in VARIANTS},
        input_sha256=sha(E/'inputs.bin'),input_metadata_sha256=sha(E/'inputs.json'),prior_ten_key_ready_sha256=sha(ten_ready),environment={k:os.environ.get(k) for k in OLD.ENV})

def load_cases(folder):
    rows=[json.loads(line) for line in (folder/'stdout.jsonl').read_text().splitlines()]
    OLD.check_records(rows,[(p,k) for p in PARAMS for k in range(10)],OLD.SIZES)
    sizes={(r['parameter'],r['key']):(r['message_bytes'],r['context_bytes']) for r in json.loads((E/'inputs.json').read_text())['cases'] if r['key']>=0}
    for r in rows:need((r['message_bytes'],r['context_bytes'])==sizes[r['parameter'],r['key']],'wrong message/context size')
    return rows,OLD.parse_outputs(folder/'outputs.bin',10)

def execute(v,folder):
    folder.mkdir(parents=True,exist_ok=False)
    cmd=[str(DRIVERS[v]),str(E/'inputs.bin'),str(folder/'outputs.bin'),'10']
    save(folder/'command.json',dict(command=cmd,started_utc=now()))
    with (folder/'stdout.jsonl').open('x') as out,(folder/'stderr.txt').open('x') as err:
        rc=subprocess.run(cmd,stdout=out,stderr=err).returncode
    save(folder/'status.json',dict(returncode=rc,finished_utc=now()))
    need(rc==0,'native driver failed: '+v)
    rows,digests=load_cases(folder)
    command=json.loads((folder/'command.json').read_text());status=json.loads((folder/'status.json').read_text());check_command_status(v,folder,command,status)
    return dict(variant=v,returncode=rc,rows=rows,output_hashes=digests,artifact_sha256=sha(folder/'outputs.bin'),raw_sha256=sha(folder/'stdout.jsonl'),command_sha256=sha(folder/'command.json'),status_sha256=sha(folder/'status.json'))

def prepare():
    BUILD.mkdir(parents=True,exist_ok=False)
    minimum=';'.join('SIG_slh_dsa_pure_sha2_'+p for p in ['128s','128f','192s','192f','256s','256f'])
    for v in VARIANTS[1:3]:
        logged(['cmake','-S',SOURCES[v],'-B',BUILDS[v],'-DCMAKE_BUILD_TYPE=Release','-DOQS_DIST_BUILD=ON','-DOQS_MINIMAL_BUILD='+minimum,'-DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3'],E/(v+'-configure.json'))
        logged(['cmake','--build',BUILDS[v],'--target','test_sig','test_slh_dsa_sha2','-j2'],E/(v+'-build.json'))
        logged([BUILDS[v]/'tests/test_slh_dsa_sha2'],E/(v+'-upstream-private-hash.json'))
        logged(['cc','-std=c11','-O3','-Wall','-Wextra','-Werror','-I'+str(BUILDS[v]/'include'),DRIVER,BUILDS[v]/'lib/liboqs.a','-L'+str(OLD.LIBCRYPTO.resolve().parent),'-lcrypto','-lpthread','-o',DRIVERS[v]],E/(v+'-driver-build.json'))
    for v in VARIANTS:
        bits=(int(v in ('full','sha256-only')),int(v in ('full','sha512-only')))
        logged([sys.executable,HERE/'check_hashes.py','--baseline',SOURCES['original'],'--candidate',SOURCES[v],'--build',BUILD/('hash-'+v),'--evidence',E/('hash-'+v),'--expect256',str(bits[0]),'--expect512',str(bits[1])],E/(v+'-hash-run.json'))
    data,meta=OLD.corpus('sha2-ablation-final-v1',10)
    need(len({m['seed_sha256'] for m in meta})==66,'non-distinct warmup/key seeds')
    old_seeds={m['seed_sha256'] for m in json.loads((HERE.parent/'ten-new-keys/evidence/inputs.json').read_text())['cases']}
    need(old_seeds.isdisjoint({m['seed_sha256'] for m in meta}),'reused prior seeds')
    with (E/'inputs.bin').open('xb') as f:f.write(data)
    save(E/'inputs.json',dict(domain='pqc-ten-new-keys-v1/liboqs/sha2-ablation-final-v1',cases=meta,sha256=sha(E/'inputs.bin')))
    preflight={}
    for v in VARIANTS:
        preflight[v]=execute(v,E/'preflight'/v)
        if v!='original':need((E/'preflight'/v/'outputs.bin').read_bytes()==(E/'preflight/original/outputs.bin').read_bytes(),'preflight key/signature mismatch')
    save(E/'preflight.json',dict(complete=True,role='Correctness only; not final performance evidence',results=preflight))
    seal()

def seal():
    compiled={}
    for v in VARIANTS:
        compiled[v]={}
        for bits in (256,512):
            obj=BUILDS[v]/f'src/sig/slh_dsa/CMakeFiles/slh_dsa_c.dir/slh_dsa_c/sha2_{bits}.c.o'
            output=subprocess.check_output(['nm','-u',str(obj)],text=True)
            enabled=v=='full' or v==f'sha{bits}-only'
            need((f'_SHA{bits}_Transform' in output)==enabled and ('_OPENSSL_cleanse' in output)==enabled,'compiled backend/cleanup selection mismatch')
            compiled[v][str(bits)]={'object_sha256':sha(obj),'undefined_symbols':output,'enabled':enabled}
    report=E/'compiled-backend.json'
    if report.exists():need(json.loads(report.read_text())==compiled,'compiled backend report changed')
    else:save(report,compiled)
    ready=dict(complete=True,identity=identities(),compiled_backend_sha256=sha(report),preflight_metadata_sha256={v:{name:sha(E/'preflight'/v/name) for name in ('command.json','status.json')} for v in VARIANTS},preflight_sha256=sha(E/'preflight.json'),reference_output_sha256=sha(E/'preflight/original/outputs.bin'),hash_report_sha256={v:sha(E/('hash-'+v)/'hash-checks.json') for v in VARIANTS},orders=ORDERS,screening_margin=0.03)
    save(E/'ready.json',ready);print('READY',E/'ready.json',flush=True)

def validate_ready():
    r=json.loads((E/'ready.json').read_text());need(r['complete'] is True and r['identity']==identities(),'changed/incomplete preparation seal')
    need(r['orders']==ORDERS and r['screening_margin']==0.03,'changed protocol')
    need(r['compiled_backend_sha256']==sha(E/'compiled-backend.json'),'changed compiled backend proof')
    compiled=json.loads((E/'compiled-backend.json').read_text())
    for v in VARIANTS:
        for bits in (256,512):need(sha(BUILDS[v]/f'src/sig/slh_dsa/CMakeFiles/slh_dsa_c.dir/slh_dsa_c/sha2_{bits}.c.o')==compiled[v][str(bits)]['object_sha256'],'compiled hash object changed')
    need(r['preflight_sha256']==sha(E/'preflight.json'),'changed preflight')
    pre=json.loads((E/'preflight.json').read_text());need(pre['complete'] is True and set(pre['results'])==set(VARIANTS),'incomplete preflight')
    for v in VARIANTS:
        need(r['hash_report_sha256'][v]==sha(E/('hash-'+v)/'hash-checks.json'),'changed hash check')
        report=json.loads((E/('hash-'+v)/'hash-checks.json').read_text());need(report['complete'] is True and set(report['results'])=={'openssl','portable','dlopen-fallback','no-deprecated-fallback'},'incomplete hash check')
        need(all(x['passed_checks']==5710 for x in report['results'].values()),'missing hash edges')
        folder=E/'preflight'/v;rows,digests=load_cases(folder);saved=pre['results'][v]
        for name in ('command.json','status.json'):need(sha(folder/name)==r['preflight_metadata_sha256'][v][name],'preflight invocation metadata changed')
        check_command_status(v,folder,json.loads((folder/'command.json').read_text()),json.loads((folder/'status.json').read_text()))
        need(rows==saved['rows'] and digests==saved['output_hashes'] and sha(folder/'stdout.jsonl')==saved['raw_sha256'],'preflight rows changed')
        need(sha(folder/'outputs.bin')==saved['artifact_sha256']==r['reference_output_sha256'],'preflight output changed')
    return r

def measure(granted):
    need(granted,'exclusive serial timing authorization required')
    ready=validate_ready();dest=E/'final';dest.mkdir(exist_ok=False)
    started=now();entries=[];loads=[]
    save(dest/'started.json',dict(started_utc=started,ready_sha256=sha(E/'ready.json'),orders=ORDERS))
    for i,order in enumerate(ORDERS):
        for v in order:
            validate_ready()
            folder=dest/f'{i+1:02d}-{v}'
            loads.append(dict(round=i+1,variant=v,started_utc=now(),load_average=os.getloadavg()))
            result=execute(v,folder)
            need((folder/'outputs.bin').read_bytes()==(E/'preflight/original/outputs.bin').read_bytes(),'timed key/signature mismatch')
            need(result['artifact_sha256']==ready['reference_output_sha256'],'timed artifact changed')
            validate_ready()
            result.update(round=i+1,complete=True,ready_sha256=sha(E/'ready.json'))
            save(folder/'result.json',result);entries.append(result)
            print('COMPLETE',i+1,v,flush=True)
    check_completed(entries,sha(E/'ready.json'),ready['reference_output_sha256'])
    save(dest/'host-load.json',loads)
    save(dest/'complete.json',dict(complete=True,started_utc=started,finished_utc=now(),ready_sha256=sha(E/'ready.json'),orders=ORDERS,host_load_sha256=sha(dest/'host-load.json'),result_sha256={f'{r["round"]:02d}-{r["variant"]}':sha(dest/f'{r["round"]:02d}-{r["variant"]}'/'result.json') for r in entries}))
    analyze()

def analyze():
    ready=validate_ready();dest=E/'final';complete=json.loads((dest/'complete.json').read_text());need(complete['complete'] is True and complete['ready_sha256']==sha(E/'ready.json') and complete['orders']==ORDERS,'incomplete final seal')
    need(sha(dest/'host-load.json')==complete['host_load_sha256'],'changed host diagnostics')
    entries=[];previous_finish=None
    for i,order in enumerate(ORDERS):
        for v in order:
            name=f'{i+1:02d}-{v}';folder=dest/name;result=json.loads((folder/'result.json').read_text())
            need(sha(folder/'result.json')==complete['result_sha256'][name],'changed result')
            rows,digests=load_cases(folder);need(rows==result['rows'] and digests==result['output_hashes'],'changed raw rows/output')
            need(sha(folder/'stdout.jsonl')==result['raw_sha256'] and sha(folder/'outputs.bin')==result['artifact_sha256'],'changed raw hashes')
            need(sha(folder/'command.json')==result['command_sha256'] and sha(folder/'status.json')==result['status_sha256'],'changed invocation metadata')
            command=json.loads((folder/'command.json').read_text());status=json.loads((folder/'status.json').read_text());check_command_status(v,folder,command,status)
            need(previous_finish is None or previous_finish<command['started_utc'],'overlapping/reordered invocations');previous_finish=status['finished_utc']
            entries.append(result)
    check_completed(entries,sha(E/'ready.json'),ready['reference_output_sha256'])
    lookup={(r['round'],r['variant']):r['rows'] for r in entries};summary=[]
    for v in VARIANTS[1:]:
        for p in PARAMS:
            for op in ('keygen','sign','verify'):
                row=dict(variant=v,parameter=p,operation=op)
                for clock in ('wall','cpu'):
                    field=op+'_'+clock+'_ns'
                    totals={s:[sum(r[field] for r in lookup[i,s] if r['parameter']==p) for i in range(1,7)] for s in ('original','full',v)}
                    speed=[b/c for b,c in zip(totals['original'],totals[v])]
                    ratio=[r/f for r,f in zip(totals[v],totals['full'])]
                    individual=[b[field]/c[field] for i in range(1,7) for b,c in zip(lookup[i,'original'],lookup[i,v]) if b['parameter']==p]
                    row[clock]=dict(round_total_ns=totals,speedup_vs_original=speed,median_speedup_vs_original=statistics.median(speed),min_speedup_vs_original=min(speed),max_speedup_vs_original=max(speed),slower_than_original_rounds=sum(x<1 for x in speed),individual_key_speedups_vs_original=individual,individual_key_losses_vs_original=sum(x<1 for x in individual),reduced_over_full_time=ratio,median_reduced_over_full_time=statistics.median(ratio),min_reduced_over_full_time=min(ratio),max_reduced_over_full_time=max(ratio),latency_penalty_vs_full=[x-1 for x in ratio],median_latency_penalty_vs_full=statistics.median(ratio)-1,speedup_fraction_of_full=[1/x for x in ratio],median_speedup_fraction_of_full=statistics.median(1/x for x in ratio),rounds_over_three_percent_slower_than_full=sum(x>1.03 for x in ratio),median_within_three_percent_of_full=statistics.median(ratio)<=1.03)
                summary.append(row)
    report=dict(complete=True,rounds=6,keys_per_parameter_per_round=10,orders=ORDERS,summary=summary,ready_sha256=sha(E/'ready.json'),complete_sha256=sha(dest/'complete.json'),criterion='Median reduced/full total time <=1.03 is a practical screening margin, not statistical equivalence; all six round ratios and losses retained.')
    output=dest/'summary.json'
    if output.exists():need(json.loads(output.read_text())==report,'saved summary differs')
    else:save(output,report)
    print('SUMMARY',output,flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['prepare','seal','measure','analyze']);parser.add_argument('--exclusive-window',action='store_true');a=parser.parse_args()
    if a.command=='prepare':prepare()
    elif a.command=='seal':seal()
    elif a.command=='measure':measure(a.exclusive_window)
    else:analyze()
