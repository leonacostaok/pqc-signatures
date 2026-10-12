#!/usr/bin/env python3
"""Follow up the original retained JVM comparison with separate processes per side and parameter."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import fors

if sys.flags.optimize != 0:
    raise RuntimeError('optimized Python disables required assertions; run without -O')

SOURCES = [Path(__file__).resolve(), fors.HERE / 'ForsIsolatedBenchmark.java']
PARAMETERS = [f'{family}_{size}{kind}' for family in ['sha2', 'shake']
    for size in [128, 192, 256] for kind in ['f', 's']]
ENVIRONMENT = ['JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS']
JVM_ARGS = ['-Xmx512m', '-XX:ActiveProcessorCount=2']


def persisted_run(invocation, directory, stem, metadata=None):
    """Retain commands and streaming output even if a later process or check fails."""
    invocation = list(map(str, invocation))
    record = {'command': invocation, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        **(metadata or {})}
    with (directory / (stem + '.command.json')).open('x') as file:
        json.dump(record, file, indent=2); file.write('\n')
    stdout, stderr = directory / (stem + '.stdout.txt'), directory / (stem + '.stderr.txt')
    with stdout.open('x') as out, stderr.open('x') as err:
        result = subprocess.run(invocation, stdout=out, stderr=err)
    with (directory / (stem + '.status.json')).open('x') as file:
        json.dump({'exit_code': result.returncode,
            'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}, file, indent=2)
        file.write('\n')
    if result.returncode:
        raise RuntimeError(f'process exited {result.returncode}; retained output: {stdout}, {stderr}')
    return subprocess.CompletedProcess(invocation, result.returncode, stdout.read_text(), stderr.read_text())


def provenance(m):
    return {'sources': {p.name: fors.sha(p) for p in SOURCES},
        'driver_classes': fors.tree(m['driver']), 'java_binary': fors.sha(m['prepared']['java']),
        'original_prepared': fors.provenance(m['prepared'])}


def command(m, side, *args):
    original = m['prepared']
    classpath = os.pathsep.join([m['driver'], original['driver'], original[side]])
    return [original['java'], *JVM_ARGS, '-cp', classpath, 'ForsIsolatedBenchmark',
        args[0], original['fixtures'], side, *args[1:]]


def prepare(args):
    original = json.loads(Path(args.manifest).read_text())
    assert original['upstream_commit'] == fors.PIN and original['provenance'] == fors.provenance(original)
    assert original['jvm_environment'] == {k: os.environ.get(k, '') for k in original['jvm_environment']}
    assert fors.run([original['java'], '-version']).stderr == original['java_version']
    identity = ''.join(fors.sha(p) for p in SOURCES) + json.dumps(original['provenance'], sort_keys=True)
    dest = fors.BUILD / ('isolated-' + hashlib.sha256(identity.encode()).hexdigest()[:16])
    dest.mkdir(parents=True, exist_ok=False)
    classes = dest / 'driver'; classes.mkdir()
    persisted_run([Path(original['java']).with_name('javac'), '-d', classes, SOURCES[1]], dest, 'compile')
    m = {'schema': 'bc-fors-isolated-prepared-v1', 'prepared': original, 'driver': str(classes),
        'jvm_args': JVM_ARGS, 'environment': {k: os.environ.get(k, '') for k in ENVIRONMENT},
        'parameters': PARAMETERS, 'python_optimize': sys.flags.optimize, 'checks': {}}
    for side in ['baseline', 'candidate']:
        result = persisted_run(command(m, side, 'check'), dest, side + '-check')
        checked = json.loads(result.stdout)
        assert checked == {'variant': side, 'valid_cases': 24, 'tamper_cases': 24,
            'class_source': str(Path(original[side]).resolve())}
        m['checks'][side] = checked
    m['provenance'] = provenance(m)
    output = dest / 'manifest.json'; output.write_text(json.dumps(m, indent=2) + '\n')
    print(output)


def collect(args):
    m = json.loads(Path(args.manifest).read_text())
    assert m['schema'] == 'bc-fors-isolated-prepared-v1' and m['parameters'] == PARAMETERS
    assert m['jvm_args'] == JVM_ARGS and m['python_optimize'] == 0
    for side in ['baseline', 'candidate']:
        assert m['checks'][side] == {'variant': side, 'valid_cases': 24, 'tamper_cases': 24,
            'class_source': str(Path(m['prepared'][side]).resolve())}
    assert m['provenance'] == provenance(m)
    assert m['environment'] == {k: os.environ.get(k, '') for k in ENVIRONMENT}
    assert 6 <= args.forks <= 30 and args.forks % 2 == 0
    assert 2 <= args.rounds <= 100 and 100 <= args.budget_ms <= 10000
    assert 1000 <= args.warmup_ms <= 10000 and 0 <= args.start < 1000000
    output = Path(args.out).resolve()
    if output.exists(): raise FileExistsError(output)
    lock = fors.BUILD / '.timing-lock'; lock.mkdir()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    pairs = []
    try:
        raw_directory = Path(str(output) + '.raw')
        raw_directory.mkdir(parents=True, exist_ok=False)
        with (raw_directory / 'plan.json').open('x') as file:
            json.dump({'prepared': m, 'started_at': started, 'forks': args.forks,
                'start_fork': args.start, 'rounds': args.rounds, 'budget_ms': args.budget_ms,
                'warmup_ms': args.warmup_ms, 'python': sys.version, 'python_optimize': sys.flags.optimize,
                'exclusion_policy': 'no exclusions or normalization by controls'}, file, indent=2)
            file.write('\n')
        for fork in range(args.start, args.start + args.forks):
            for index, parameter in enumerate(PARAMETERS):
                order = ['baseline', 'candidate'] if (fork + index) % 2 == 0 else ['candidate', 'baseline']
                print(f'Fresh JVM pair {fork}: {parameter} ({"/".join(order)})', flush=True)
                pair = {'fork': fork, 'parameter': parameter, 'order': order}
                for side in order:
                    invocation = command(m, side, 'bench', parameter, fork, args.rounds, args.budget_ms, args.warmup_ms)
                    stem = f'{fork:04d}-{parameter}-{side}'
                    result = persisted_run(invocation, raw_directory, stem,
                        {'fork': fork, 'parameter': parameter, 'variant': side, 'pair_order': order})
                    rows = [json.loads(line) for line in result.stdout.splitlines()]
                    assert len(rows) == args.rounds and [r['round'] for r in rows] == list(range(args.rounds))
                    for row in rows:
                        assert (row['variant'], row['parameter'], row['fork']) == (side, parameter, fork)
                        assert row['class_source'] == str(Path(m['prepared'][side]).resolve())
                        assert row['iterations'] > 0 and row['iterations'] % 2 == 0
                        assert row['elapsed_ns'] >= args.budget_ms * 1000000 and row['cpu_ns'] > 0
                    pair[side] = {'command': list(map(str, invocation)), 'rows': rows,
                        'median_ns': statistics.median(r['elapsed_ns'] / r['iterations'] for r in rows),
                        'median_cpu_ns': statistics.median(r['cpu_ns'] / r['iterations'] for r in rows)}
                    with (raw_directory / (stem + '.metrics.json')).open('x') as file:
                        json.dump(pair[side], file, indent=2); file.write('\n')
                pair['speedup'] = pair['baseline']['median_ns'] / pair['candidate']['median_ns']
                pair['cpu_speedup'] = pair['baseline']['median_cpu_ns'] / pair['candidate']['median_cpu_ns']
                pairs.append(pair)
                with (raw_directory / f'{fork:04d}-{parameter}.pair.json').open('x') as file:
                    json.dump(pair, file, indent=2); file.write('\n')
                assert m['provenance'] == provenance(m), 'frozen inputs changed'
        summary = []
        for parameter in PARAMETERS:
            selected = [p for p in pairs if p['parameter'] == parameter]
            assert len(selected) == args.forks
            assert sum(p['order'][0] == 'baseline' for p in selected) == args.forks // 2
            ratios = [p['speedup'] for p in selected]
            summary.append({'parameter': parameter, 'speedup': statistics.median(ratios),
                'fork_min': min(ratios), 'fork_max': max(ratios),
                'cpu_speedup': statistics.median(p['cpu_speedup'] for p in selected)})
        result = {'schema': 'bc-fors-isolated-verify-v1', 'prepared': m,
            'started_at': started, 'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'host': platform.platform(), 'arch': platform.machine(), 'forks': args.forks,
            'python': sys.version, 'python_optimize': sys.flags.optimize, 'raw_directory': str(raw_directory),
            'start_fork': args.start, 'rounds': args.rounds, 'budget_ms': args.budget_ms, 'warmup_ms': args.warmup_ms,
            'statistic': 'median across fresh process-pair ratios of within-process median latency; ranges are descriptive, not confidence intervals',
            'exclusion_policy': 'retain every completed process and sample; no exclusions or normalization by controls',
            'summary': summary, 'process_pairs': pairs}
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=output.parent, delete=False) as file:
            json.dump(result, file, indent=2); file.write('\n'); temporary = file.name
        try: os.link(temporary, output)
        finally: os.unlink(temporary)
        print(output)
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare'); p.add_argument('--manifest', required=True)
    r = commands.add_parser('run'); r.add_argument('--manifest', required=True); r.add_argument('--out', required=True)
    r.add_argument('--forks', type=int, default=6); r.add_argument('--start', type=int, default=20)
    r.add_argument('--rounds', type=int, default=6); r.add_argument('--budget-ms', type=int, default=250)
    r.add_argument('--warmup-ms', type=int, default=2000)
    args = parser.parse_args(); (prepare if args.command == 'prepare' else collect)(args)


if __name__ == '__main__': main()
