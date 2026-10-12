#!/usr/bin/env python3
"""Seal a fixed balanced screen, then collect only within an explicitly granted window."""
import sys
if sys.flags.optimize:
    raise RuntimeError('Run without Python optimization')
import argparse, datetime, hashlib, json, os, platform, random, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RESULTS = ROOT / 'results/bouncycastle/matrix-alternatives'
VARIANTS = ['baseline', 'lazy', 'stream', 'combined']
PARAMETERS = ['ml_dsa_44', 'ml_dsa_65', 'ml_dsa_87']
OPERATIONS = ['keygen', 'sign', 'verify']
FLAGS = ['-Xms512m', '-Xmx512m', '-XX:ActiveProcessorCount=2']
ENV_KEYS = ['JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS']

def require(ok, why):
    if not ok:
        raise ValueError(why)

def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def dump(p, value):
    p.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def files(p, pattern):
    return {str(f.relative_to(p)): digest(f) for f in sorted(p.rglob(pattern)) if f.is_file()}

def verify_prepared(m):
    require(digest(m['java']) == m['java_sha256'], 'runtime changed')
    for name, v in m['variants'].items():
        require(files(Path(v['classes']), '*.class') == v['binaries'], name + ' classes changed')
        require(files(Path(v['source_path']), '*.java') == v['source'], name + ' sources changed')
    for f, h in m['inputs'].items():
        require(digest(ROOT / f) == h, 'preparation input changed: ' + f)
    for v in m['corpora'].values():
        require(digest(v['path']) == v['sha256'], 'corpus changed')
    require(digest(RESULTS / 'baseline-source.tar.gz') == m['source_archive_sha256'], 'source archive changed')
    require(all(not os.environ.get(k) for k in ENV_KEYS), 'uncontrolled JVM environment')

def schedule():
    jobs = []
    for mode in ['timing', 'allocation']:
        for pair in range(2):
            cells = [(p, op) for p in PARAMETERS for op in OPERATIONS]
            random.Random(20371012 + pair).shuffle(cells)
            for cell, (parameter, operation) in enumerate(cells):
                order = VARIANTS[:]
                random.Random(773100 + pair * 9 + cell).shuffle(order)
                for side in range(2):
                    round_number = pair * 2 + side
                    for variant in (order if side == 0 else list(reversed(order))):
                        jobs.append({'index': len(jobs), 'mode': mode, 'pair': pair,
                                     'round': round_number, 'parameter': parameter,
                                     'operation': operation, 'variant': variant,
                                     'shuffle_seed': 421000 + pair * 2 + side})
    return jobs

def seal():
    plan_path = RESULTS / 'plan.json'
    require(not plan_path.exists(), 'plan already sealed')
    m = json.loads((RESULTS / 'prepared.json').read_text())
    verify_prepared(m)
    plan = {'schema': 'bc-matrix-plan-v1', 'sealed_at': now(),
            'prepared_sha256': digest(RESULTS / 'prepared.json'),
            'runner_sha256': digest(__file__), 'audit_sha256': digest(HERE / 'audit.py'),
            'jvm_flags': FLAGS, 'warmup_calls': 1000, 'warmup_distinct_keys': 2,
            'measured_distinct_keys_per_batch': 128, 'repetitions_per_measured_key': 1,
            'jobs': schedule(), 'platform': platform.platform(),
            'java_version_log': (RESULTS / 'java-version.log').read_text(),
            'primary_ratio': 'sum baseline / sum variant over all four rounds, wall and calling-thread CPU separately',
            'all_round_ratios_and_key_losses_retained': True,
            'allocation': 'separate JVM cohort; allocated bytes on calling thread, no inference about GC or peak/live memory',
            'scope': 'fresh public API generator or signer init/update/operation; predecoded key objects, caller copies and keygen result encoding outside measurement',
            'environment_limitation': 'Root observed fseventsd at approximately 80% CPU before collection; controlled jobs are exclusive but the host is not reserved.'}
    require(len(plan['jobs']) == 288, 'job count')
    dump(plan_path, plan)
    print(json.dumps({'plan': str(plan_path), 'sha256': digest(plan_path), 'jobs': 288}))

def collect(grant):
    require(grant.strip(), 'an explicit exclusive-window grant is required')
    plan_path = RESULTS / 'plan.json'
    plan = json.loads(plan_path.read_text())
    require(digest(__file__) == plan['runner_sha256'], 'runner differs from sealed plan')
    require(digest(HERE / 'audit.py') == plan['audit_sha256'], 'checker differs from sealed plan')
    require(digest(RESULTS / 'prepared.json') == plan['prepared_sha256'], 'preparation changed')
    require(plan['jobs'] == schedule() and plan['jvm_flags'] == FLAGS, 'schedule changed')
    m = json.loads((RESULTS / 'prepared.json').read_text())
    verify_prepared(m)
    out = RESULTS / 'collection'
    out.mkdir(exist_ok=False)
    record = {'schema': 'bc-matrix-collection-v1', 'plan_sha256': digest(plan_path),
              'started_at': now(), 'exclusive_grant': grant, 'jobs': [], 'status': 'running',
              'environment': {k: os.environ.get(k, '') for k in ENV_KEYS}}
    dump(out / 'collection.json', record)
    try:
        for job in plan['jobs']:
            name = f"{job['index']:03d}-{job['mode']}-{job['parameter']}-{job['operation']}-{job['variant']}-r{job['round']}"
            argv = [m['java'], *FLAGS, '-cp', m['variants'][job['variant']]['classes'],
                    'org.bouncycastle.crypto.signers.mldsa.MatrixBench', job['mode'],
                    m['corpora']['warmup']['path'], m['corpora']['measured']['path'],
                    job['parameter'], job['operation'], str(job['shuffle_seed']), job['variant']]
            entry = dict(job, argv=argv, started_at=now(), stdout=name + '.json', stderr=name + '.stderr')
            with (out / entry['stdout']).open('w') as stdout, (out / entry['stderr']).open('w') as stderr:
                result = subprocess.run(argv, stdout=stdout, stderr=stderr)
            entry.update(completed_at=now(), exit_code=result.returncode,
                         stdout_sha256=digest(out / entry['stdout']), stderr_sha256=digest(out / entry['stderr']))
            record['jobs'].append(entry)
            dump(out / 'collection.json', record)
            require(result.returncode == 0, 'JVM failed; raw evidence retained, no automatic retry')
            print(f"{job['index']+1}/288 {name}", flush=True)
        verify_prepared(m)
        record['status'] = 'complete'
    except BaseException as failure:
        record['status'] = 'failed'
        record['failure'] = repr(failure)
        raise
    finally:
        record['completed_at'] = now()
        dump(out / 'collection.json', record)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['seal', 'collect'])
    parser.add_argument('--exclusive-grant', default='')
    a = parser.parse_args()
    if a.action == 'seal':
        seal()
    else:
        collect(a.exclusive_grant)

if __name__ == '__main__':
    main()
