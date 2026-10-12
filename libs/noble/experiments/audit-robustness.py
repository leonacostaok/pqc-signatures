#!/usr/bin/env python3
"""Independently recompute retained noble comparisons and check their raw samples."""
import hashlib
import json
from pathlib import Path
import statistics
import sys


def audit(path):
    report = json.loads(path.read_text())
    rows = report['rows']
    assert len(rows) == 600
    groups = {}
    for index, row in enumerate(rows):
        for variant in ('baseline', 'candidate'):
            raw = json.loads(Path(str(path) + '.raw', f'sample-{index:05d}-{variant}.json').read_text())
            assert raw['result'] == row[variant]
            for key in ('fork', 'level', 'op', 'mode', 'ordinal', 'index', 'reversal', 'order'):
                assert raw[key] == row[key]
        assert row['speedup'] == row['baseline']['ns_per_op'] / row['candidate']['ns_per_op']
        assert row['startup_inclusive_speedup'] == row['baseline']['process_total_ns'] / row['candidate']['process_total_ns']
        groups.setdefault((row['mode'], row['level'], row['op'], row['fork']), []).append(row)
    assert len(groups) == 120
    checks = []
    seen = set()
    for summary in report['summary']:
        key = (summary['mode'], summary['level'], summary['op'])
        assert key not in seen
        seen.add(key)
        ratios, startup = [], []
        for fork in summary['forks']:
            selected = groups[(*key, fork['fork'])]
            assert len(selected) == (4 if key[0] == 'warm' else 6)
            assert sum(row['order'] == ['baseline', 'candidate'] for row in selected) * 2 == len(selected)
            assert all(sorted(row['order']) == ['baseline', 'candidate'] for row in selected)
            ratio = statistics.median(row['speedup'] for row in selected)
            elapsed = statistics.median(row['startup_inclusive_speedup'] for row in selected)
            assert fork['speedup'] == ratio and fork['startup_inclusive_speedup'] == elapsed
            ratios.append(ratio)
            startup.append(elapsed)
        assert len(ratios) == 5
        assert summary['speedup'] == statistics.median(ratios)
        assert summary['fork_min'] == min(ratios) and summary['fork_max'] == max(ratios)
        if key[0] == 'single':
            assert summary['startup_inclusive_speedup'] == statistics.median(startup)
        checks.append({'mode': key[0], 'level': key[1], 'operation': key[2],
                       'speedup': statistics.median(ratios), 'minimum_fork_speedup': min(ratios)})
    assert seen == {(mode, level, op) for mode in ('warm', 'single') for level in (44, 65, 87)
                    for op in ('keygen', 'getPublicKey', 'sign', 'verify')}
    return {'file': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'pairs_checked': len(rows), 'raw_samples_checked': len(rows) * 2,
            'balanced_order': True, 'summaries': checks}


if __name__ == '__main__':
    if not sys.argv[1:]:
        raise SystemExit('usage: audit-robustness.py REPORT.json [...]')
    print(json.dumps({'reports': [audit(Path(p)) for p in sys.argv[1:]]}, indent=2))
