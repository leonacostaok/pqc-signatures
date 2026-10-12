#!/usr/bin/env python3
"""Build/check the pinned production patch, then collect explicitly requested paired timings."""
import argparse
import datetime
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = HERE.parent / 'build' / 'fors-base2b'
PIN = 'c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
PATCH = HERE.parent / 'patches' / 'fors-base2b.patch'
SOURCES = [HERE / n for n in ['ForsOperations.java', 'ForsBenchmark.java', 'ForsAllocationCheck.java', 'fors.py']]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(path):
    digest = hashlib.sha256()
    for file in sorted(Path(path).rglob('*.class')):
        digest.update(str(file.relative_to(path)).encode() + b'\0' + bytes.fromhex(sha(file)))
    return digest.hexdigest()


def run(command, *, cwd=None, logfile=None, allowed=(0,)):
    result = subprocess.run([str(v) for v in command], cwd=cwd, capture_output=True, text=True)
    if logfile:
        Path(logfile).write_text('$ ' + ' '.join(map(str, command)) + '\n' + result.stdout + result.stderr)
    if result.returncode not in allowed:
        raise RuntimeError(f'command exited {result.returncode}: {command}\n{result.stderr[-6000:]}')
    return result


def provenance(manifest):
    return {**{str(p.relative_to(ROOT)): sha(p) for p in SOURCES + [PATCH]},
            'fixture': sha(manifest['fixtures']),
            'baseline_classes': tree(manifest['baseline']),
            'candidate_classes': tree(manifest['candidate']),
            'driver_classes': tree(manifest['driver'])}


def prepare(args):
    upstream = Path(args.upstream).resolve()
    java_home = Path(args.java_home).resolve()
    java, javac = java_home / 'bin/java', java_home / 'bin/javac'
    run(['git', 'cat-file', '-e', PIN + '^{commit}'], cwd=upstream)
    fingerprint = hashlib.sha256((sha(PATCH) + ''.join(sha(p) for p in SOURCES)
        + run([java, '-version']).stderr + str(java)).encode()).hexdigest()[:16]
    dest = BUILD / ('prepared-' + fingerprint)
    dest.mkdir(parents=True, exist_ok=False)
    evidence = dest / 'checks'; evidence.mkdir()
    archive = subprocess.check_output(['git', '-C', str(upstream), 'archive', PIN, 'core/src/main/java'])
    for variant in ['baseline', 'candidate']:
        source = dest / (variant + '-src'); source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for member in tar.getmembers():
                parts = Path(member.name).parts
                assert not member.name.startswith('/') and '..' not in parts
                assert member.isdir() or member.isfile(), 'unexpected archive link'
            tar.extractall(source)
        if variant == 'candidate':
            run(['git', 'init', '-q'], cwd=source)
            run(['git', 'apply', '--check', PATCH], cwd=source)
            run(['git', 'apply', PATCH], cwd=source)
        classes = dest / variant; classes.mkdir()
        main = source / 'core/src/main/java'
        entries = [main / ('org/bouncycastle/' + p) for p in [
            'crypto/signers/SLHDSASigner.java', 'crypto/signers/HashSLHDSASigner.java',
            'crypto/generators/SLHDSAKeyPairGenerator.java']]
        # Match the upstream Java-8 base implementation; only the separate driver uses newer JDK APIs.
        run([javac, '--release', '8', '-sourcepath', main, '-d', classes, *entries], logfile=evidence / (variant + '-core-build.txt'))
        run([javac, '-cp', classes, '-d', classes, HERE / 'ForsOperations.java', HERE / 'ForsAllocationCheck.java'],
            logfile=evidence / (variant + '-harness-build.txt'))
        result = run([java, '-Xmx512m', '-XX:ActiveProcessorCount=2', '-cp', classes,
            'org.bouncycastle.crypto.signers.slhdsa.ForsAllocationCheck', 'require-bounded'],
            logfile=evidence / (variant + '-allocation.txt'), allowed=(0, 1) if variant == 'baseline' else (0,))
        if variant == 'baseline':
            assert result.returncode == 1 and 'base2B allocates more than 512 bytes per call' in result.stderr
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(rows) == 6
        (evidence / (variant + '-allocation.json')).write_text(json.dumps(rows, indent=2) + '\n')
    driver = dest / 'driver'; driver.mkdir()
    run([javac, '-d', driver, HERE / 'ForsBenchmark.java'], logfile=evidence / 'driver-build.txt')
    fixtures = dest / 'fixtures.bin'
    command = [java, '-Xmx512m', '-XX:ActiveProcessorCount=2', '-cp', driver, 'ForsBenchmark']
    if args.fixtures:
        shutil.copyfile(args.fixtures, fixtures)
    else:
        run(command + ['fixtures', dest / 'baseline', fixtures], logfile=evidence / 'fixtures.txt')
    print('Checking full keygen/sign/verify corpus...', flush=True)
    checked = run(command + ['check', dest / 'baseline', dest / 'candidate', fixtures], logfile=evidence / 'differential.txt')
    correctness = json.loads(checked.stdout)
    assert correctness['differential_cases'] == 48 and correctness['negative_parity_cases'] == 240
    manifest = {'schema': 'bc-fors-base2b-prepared-v1', 'upstream_commit': PIN,
        'java': str(java), 'java_version': run([java, '-version']).stderr,
        'baseline': str(dest / 'baseline'), 'candidate': str(dest / 'candidate'), 'driver': str(driver),
        'fixtures': str(fixtures), 'checks': str(evidence), 'correctness': correctness,
        'corpus': 'fors-base2b-v1/204', 'release': 8,
        'jvm_environment': {k: os.environ.get(k, '') for k in ['JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS']}}
    manifest['provenance'] = provenance(manifest)
    path = dest / 'manifest.json'; path.write_text(json.dumps(manifest, indent=2) + '\n')
    print(path)


def collect(args):
    path = Path(args.manifest).resolve()
    manifest = json.loads(path.read_text())
    assert manifest['schema'] == 'bc-fors-base2b-prepared-v1'
    assert 5 <= args.forks <= 30 and 2 <= args.rounds <= 100 and args.rounds % 2 == 0
    assert 100 <= args.budget_ms <= 10000 and 0 <= args.start < 1000000
    operations = args.operations.split(',')
    assert operations and len(operations) == len(set(operations)) and set(operations) <= {'base2B', 'verify', 'sign'}
    out = Path(args.out).resolve()
    if out.exists(): raise FileExistsError(out)
    expected = manifest['provenance']; assert provenance(manifest) == expected
    assert manifest['jvm_environment'] == {k: os.environ.get(k, '') for k in manifest['jvm_environment']}
    lock = BUILD / '.timing-lock'; lock.mkdir()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    rows = []
    try:
        for fork in range(args.start, args.start + args.forks):
            for op in operations:
                print(f'Fresh JVM fork {fork}: {op}', flush=True)
                command = [manifest['java'], '-Xmx512m', '-XX:ActiveProcessorCount=2', '-cp', manifest['driver'],
                    'ForsBenchmark', 'bench', manifest['baseline'], manifest['candidate'], manifest['fixtures'],
                    fork, args.rounds, args.budget_ms, op]
                result = run(command)
                current = [json.loads(line) for line in result.stdout.splitlines()]
                count = 6 if op == 'base2B' else 12
                assert len(current) == count * args.rounds
                assert len({(r['parameter'], r['round']) for r in current}) == len(current)
                for row in current:
                    assert row['fork'] == fork and row['operation'] == op
                    assert row['order'] == (['baseline', 'candidate'] if (fork + row['round']) % 2 == 0 else ['candidate', 'baseline'])
                    for side in ['baseline', 'candidate']:
                        value = row[side]
                        assert value['iterations'] > 0 and value['iterations'] % (8 if op == 'base2B' else 2) == 0
                        assert value['elapsed_ns'] >= args.budget_ms * 1000000
                        assert math.isfinite(value['ns_per_op']) and value['ns_per_op'] > 0
                    ratio = row['baseline']['ns_per_op'] / row['candidate']['ns_per_op']
                    assert math.isclose(row['speedup'], ratio, rel_tol=1e-12)
                rows.extend(current)
                assert provenance(manifest) == expected, 'prepared inputs changed'
        summary = []
        for operation, parameter in sorted({(r['operation'], r['parameter']) for r in rows}):
            forks = []
            for fork in range(args.start, args.start + args.forks):
                selected = [r for r in rows if (r['operation'], r['parameter'], r['fork']) == (operation, parameter, fork)]
                assert sorted(r['round'] for r in selected) == list(range(args.rounds))
                forks.append({'fork': fork, 'speedup': statistics.median(r['speedup'] for r in selected),
                    'baseline_ns': statistics.median(r['baseline']['ns_per_op'] for r in selected),
                    'candidate_ns': statistics.median(r['candidate']['ns_per_op'] for r in selected)})
            values = [f['speedup'] for f in forks]
            summary.append({'operation': operation, 'parameter': parameter, 'speedup': statistics.median(values),
                'fork_min': min(values), 'fork_max': max(values), 'forks': forks})
        result = {'schema': 'bc-fors-base2b-v1', 'started_at': started,
            'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'host': platform.platform(), 'arch': platform.machine(), 'java_version': manifest['java_version'],
            'jvm_args': ['-Xmx512m', '-XX:ActiveProcessorCount=2'], 'forks': args.forks,
            'start_fork': args.start, 'rounds': args.rounds, 'budget_ms': args.budget_ms, 'warmup_ms': 500,
            'statistic': 'median of within-fork median paired baseline/candidate latency ratios; ranges are descriptive, not confidence intervals',
            'prepared': manifest, 'summary': summary, 'rows': rows}
        out.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=out.parent, delete=False) as temp:
            json.dump(result, temp, indent=2); temp.write('\n'); temporary = temp.name
        try: os.link(temporary, out)
        finally: os.unlink(temporary)
        print(out)
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare'); p.add_argument('--upstream', required=True); p.add_argument('--java-home', required=True)
    p.add_argument('--fixtures')
    r = sub.add_parser('run'); r.add_argument('--manifest', required=True); r.add_argument('--out', required=True)
    r.add_argument('--forks', type=int, default=5); r.add_argument('--start', type=int, default=10)
    r.add_argument('--rounds', type=int, default=6); r.add_argument('--budget-ms', type=int, default=250)
    r.add_argument('--operations', default='base2B,verify')
    args = parser.parse_args()
    (prepare if args.command == 'prepare' else collect)(args)


if __name__ == '__main__':
    main()
