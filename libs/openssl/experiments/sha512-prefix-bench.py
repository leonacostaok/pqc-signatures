#!/usr/bin/env python3
"""Balanced fresh-process pairs; ordinary EVP calls include new context setup."""
import argparse
import hashlib
import json
import math
import pathlib
import platform
import random
import statistics
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(binary, operation, case, iterations):
    p = subprocess.run([str(binary), operation, str(case), str(iterations)],
                       check=True, capture_output=True, text=True)
    result = json.loads(p.stdout)
    if not result['ok'] or result['iterations'] != iterations or result['elapsed_ns'] <= 0 or result['cpu_ns'] <= 0:
        raise RuntimeError('Invalid measured operation')
    return {'wall': result['elapsed_ns'] / iterations,
            'cpu': result['cpu_ns'] / iterations}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', type=pathlib.Path, required=True)
    parser.add_argument('--candidate', type=pathlib.Path, required=True)
    parser.add_argument('--corpus', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--gate', type=pathlib.Path, required=True)
    parser.add_argument('--forks', type=int, default=5)
    parser.add_argument('--rounds', type=int, default=6)
    parser.add_argument('--budget-ms', type=int, default=300)
    parser.add_argument('--seed', type=int, default=20261012)
    parser.add_argument('--exclusive-window-granted', action='store_true')
    args = parser.parse_args()
    if args.forks < 5 or args.rounds < 2 or args.rounds % 2 or args.budget_ms < 100:
        parser.error('Use at least five forks, an even number of rounds, and a budget of at least 100 ms')
    if not args.exclusive_window_granted:
        parser.error('Obtain a quiet host window before timing')
    if args.out.exists():
        parser.error('Refusing to overwrite earlier measurements')
    bins = {'baseline': args.baseline.resolve(), 'candidate': args.candidate.resolve()}
    hashes = {k: digest(v) for k, v in bins.items()}
    if len(set(hashes.values())) != 2:
        raise RuntimeError('Baseline and candidate binaries are identical')
    gate = json.loads(args.gate.read_text())
    if not gate.get('complete') or any(gate['identities'][v]['prefix-driver'] != hashes[v] for v in bins):
        raise RuntimeError('Missing complete correctness gates for these binaries')
    reference_params = {f'SLH-DSA-SHA2-{level}{size}' for level in (128, 192, 256) for size in ('s', 'f')}
    for variant in bins:
        proof = gate['results'][variant]
        check = proof['validation']
        if (proof['resource'] != {'hash_cases': 768, 'redundant_prefix_bytes': 65536 if variant == 'baseline' else 0}
                or not check['complete'] or check['binary_sha256'] != hashes[variant]
                or len(check['cases']) != 216 or len({row['id'] for row in check['cases']}) != 216
                or not all(row['pass'] is True for row in check['cases'])
                or len(check['reference_corpus']) != 6
                or {row['param'] for row in check['reference_corpus']} != reference_params):
            raise RuntimeError(f'Incomplete {variant} correctness evidence')
    gate_hash = digest(args.gate)
    cases = sorted(args.corpus.glob('SLH-DSA-*.txt'))
    expected = {f'SLH-DSA-{family}-{level}-{sample}.txt'
                for family, level in [('SHA2', s) for s in ('128f', '128s', '192f', '192s', '256f', '256s')] + [('SHAKE', '128f')]
                for sample in range(3)}
    if {p.name for p in cases} != expected:
        raise RuntimeError('Incomplete validated corpus')
    corpus_hashes = {p.name: digest(p) for p in cases}
    manifest = json.loads((args.corpus / 'manifest.json').read_text())
    if ({r['file']: r['sha256'] for r in manifest['cases']} != corpus_hashes
            or set(manifest['binary_sha256'].values()) != set(hashes.values())):
        raise RuntimeError('Corpus was not validated against these binaries')
    experiment_files = sorted(pathlib.Path(__file__).parent.glob('sha512-prefix*'))
    experiment_hashes = {p.name: digest(p) for p in experiment_files if p.is_file()}
    result = {'platform': platform.platform(), 'machine': platform.machine(),
              'started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'binary_sha256': hashes, 'corpus_sha256': corpus_hashes,
              'experiment_sha256': experiment_hashes,
              'correctness_gate_sha256': gate_hash,
              'seed': args.seed, 'forks': args.forks, 'rounds': args.rounds,
              'budget_ms': args.budget_ms, 'pairs': [],
              'method': 'Each side is a fresh process; key import and one full warmup precede timing. Each measured operation creates/frees its EVP context. Deterministic signing. Pair order alternates; cases shuffle. No cold-start speed claim.'}
    cells = [(case, op) for case in cases for op in ('sign', 'verify')]
    iterations = {}
    for case, op in cells:
        elapsed = invoke(bins['baseline'], op, case, 1)['wall']
        iterations[(case.name, op)] = max(1, min(100000, math.ceil(args.budget_ms * 1e6 / elapsed)))
    for fork in range(args.forks):
        order = cells[:]
        random.Random(args.seed + fork).shuffle(order)
        for round_id in range(args.rounds):
            for case, op in order:
                variants = ['baseline', 'candidate'] if (fork + round_id) % 2 == 0 else ['candidate', 'baseline']
                count = iterations[(case.name, op)]
                samples = {v: invoke(bins[v], op, case, count) for v in variants}
                measured = {v: samples[v]['wall'] for v in variants}
                cpu = {v: samples[v]['cpu'] for v in variants}
                row = {'fork': fork, 'round': round_id, 'case': case.name,
                       'operation': op, 'order': variants, 'iterations': count,
                       'ns_per_op': measured, 'cpu_ns_per_op': cpu,
                       'speedup': measured['baseline'] / measured['candidate'],
                       'cpu_speedup': cpu['baseline'] / cpu['candidate']}
                result['pairs'].append(row)
                print(json.dumps(row), flush=True)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + '\n')
    for name, binary in bins.items():
        if digest(binary) != hashes[name]:
            raise RuntimeError('Binary changed during run')
    for case in cases:
        if digest(case) != corpus_hashes[case.name]:
            raise RuntimeError('Corpus changed during run')
    if experiment_hashes != {p.name: digest(p) for p in experiment_files if p.is_file()}:
        raise RuntimeError('Experiment source changed during run')
    if digest(args.gate) != gate_hash:
        raise RuntimeError('Correctness evidence changed during run')
    summary = []
    for case, op in cells:
        forks = [statistics.median(r['speedup'] for r in result['pairs']
                 if r['fork'] == f and r['case'] == case.name and r['operation'] == op)
                 for f in range(args.forks)]
        cpu_forks = [statistics.median(r['cpu_speedup'] for r in result['pairs']
                     if r['fork'] == f and r['case'] == case.name and r['operation'] == op)
                     for f in range(args.forks)]
        summary.append({'case': case.name, 'operation': op,
                        'median_fork_speedup': statistics.median(forks),
                        'min_fork_speedup': min(forks), 'max_fork_speedup': max(forks),
                        'median_fork_cpu_speedup': statistics.median(cpu_forks)})
    result['summary'] = summary
    result['complete'] = True
    args.out.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
