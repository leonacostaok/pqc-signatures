#!/usr/bin/env python3
"""Recompute the final paired report without importing its runner."""
import argparse
import collections
import hashlib
import json
import math
import pathlib
import statistics
import sys


def main():
    if sys.flags.optimize:
        raise SystemExit("Run without -O or PYTHONOPTIMIZE; assertions are required")
    parser = argparse.ArgumentParser()
    parser.add_argument('result', type=pathlib.Path)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.result.read_text())
    assert data['complete'] is True
    assert data['forks'] == 5 and data['rounds'] == 6
    cases = {f'SLH-DSA-{family}-{level}-{sample}.txt'
             for family, level in [('SHA2', x) for x in
                                  ('128f', '128s', '192f', '192s', '256f', '256s')]
             + [('SHAKE', '128f')] for sample in range(3)}
    cells = {(case, op) for case in cases for op in ('sign', 'verify')}
    expected = {(case, op, fork, rnd) for case, op in cells
                for fork in range(5) for rnd in range(6)}
    seen = set()
    groups = collections.defaultdict(list)
    for row in data['pairs']:
        key = (row['case'], row['operation'], row['fork'], row['round'])
        assert key in expected and key not in seen
        seen.add(key)
        assert row['iterations'] >= 1
        order = ['baseline', 'candidate'] if (row['fork'] + row['round']) % 2 == 0 else ['candidate', 'baseline']
        assert row['order'] == order
        for field, ratio in [('ns_per_op', 'speedup'), ('cpu_ns_per_op', 'cpu_speedup')]:
            assert all(math.isfinite(row[field][v]) and row[field][v] > 0
                       for v in ('baseline', 'candidate'))
            calculated = row[field]['baseline'] / row[field]['candidate']
            assert math.isclose(calculated, row[ratio], rel_tol=1e-12)
        groups[(row['case'], row['operation'])].append(row)
    assert seen == expected
    recorded = {(row['case'], row['operation']): row for row in data['summary']}
    assert len(data['summary']) == len(cells) and set(recorded) == cells
    summaries = []
    for case, op in sorted(cells):
        rows = groups[(case, op)]
        assert len({r['iterations'] for r in rows}) == 1
        wall = [statistics.median(r['ns_per_op']['baseline'] / r['ns_per_op']['candidate']
                                 for r in rows if r['fork'] == f) for f in range(5)]
        cpu = [statistics.median(r['cpu_ns_per_op']['baseline'] / r['cpu_ns_per_op']['candidate']
                                for r in rows if r['fork'] == f) for f in range(5)]
        calculated = {'median_fork_speedup': statistics.median(wall),
                      'min_fork_speedup': min(wall), 'max_fork_speedup': max(wall),
                      'median_fork_cpu_speedup': statistics.median(cpu)}
        assert all(math.isclose(value, recorded[(case, op)][name], rel_tol=1e-12)
                   for name, value in calculated.items())
        summaries.append({'case': case, 'operation': op, **calculated,
                          'wall_fork_ratios': wall, 'cpu_fork_ratios': cpu,
                          'wall_pair_losses': sum(r['speedup'] < 1 for r in rows)})
    parameters = sorted({case.rsplit('-', 1)[0] for case in cases})
    aggregates = []
    for parameter in parameters:
        for operation in ('sign', 'verify'):
            forks = []
            for fork in range(5):
                rounds = []
                for rnd in range(6):
                    selected = [r for r in data['pairs']
                                if r['case'].rsplit('-', 1)[0] == parameter
                                and r['operation'] == operation and r['fork'] == fork
                                and r['round'] == rnd]
                    assert len(selected) == 3
                    values = {}
                    for field, prefix in [('ns_per_op', 'wall'), ('cpu_ns_per_op', 'cpu')]:
                        means = {side: statistics.mean(r[field][side] for r in selected)
                                 for side in ('baseline', 'candidate')}
                        values[prefix + '_ratio'] = means['baseline'] / means['candidate']
                    rounds.append(values)
                forks.append({kind: statistics.median(r[kind] for r in rounds)
                              for kind in ('wall_ratio', 'cpu_ratio')})
            aggregates.append({'parameter': parameter, 'operation': operation,
                               'wall_speedup': statistics.median(f['wall_ratio'] for f in forks),
                               'cpu_speedup': statistics.median(f['cpu_ratio'] for f in forks),
                               'wall_fork_min': min(f['wall_ratio'] for f in forks),
                               'wall_fork_max': max(f['wall_ratio'] for f in forks),
                               'cpu_fork_min': min(f['cpu_ratio'] for f in forks),
                               'cpu_fork_max': max(f['cpu_ratio'] for f in forks),
                               'forks': forks})
    result = {'complete': True,
              'source_sha256': hashlib.sha256(args.result.read_bytes()).hexdigest(),
              'pairs_checked': len(seen), 'cells_checked': len(cells),
              'balanced_orders_per_fork': True, 'summaries': summaries,
              'parameter_statistic': 'Equal-weight mean latency over three cases per round and side; baseline/candidate ratio; median of six rounds within each fork, then median of five forks. No exclusions or control normalization.',
              'parameter_summaries': aggregates}
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ('summaries', 'parameter_summaries')}))


if __name__ == '__main__':
    main()
