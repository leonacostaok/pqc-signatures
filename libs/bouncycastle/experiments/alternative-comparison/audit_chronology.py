#!/usr/bin/env python3
"""Check recorded benchmark intervals across all alternative campaigns."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path

if not __debug__:
    raise SystemExit('optimized Python is unsupported')
root = Path(__file__).resolve().parents[4]
p = argparse.ArgumentParser()
p.add_argument('--ntt-root', type=Path, default=root)
p.add_argument('--matrix-root', type=Path, default=root)
p.add_argument('--wots-root', type=Path, default=root)
p.add_argument('--initial-only', action='store_true')
a = p.parse_args()
def read(path):
    return json.loads(path.read_text())
def date(s):
    return datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
intervals = []
sources = {}
cohorts = {}
def add(label, index, mode, start, end):
    start, end = date(start), date(end)
    assert start <= end
    item = {'cohort': label, 'index': index, 'mode': mode, 'start': start.isoformat(), 'end': end.isoformat(), 'seconds': (end - start).total_seconds()}
    intervals.append(item)
    cohorts.setdefault(label, []).append(item)
ntt = a.ntt_root / 'results/bouncycastle/ntt-alternatives'
for prefix, count in [('screen', 144)] + ([] if a.initial_only else [('confirmation', 108)]):
    for mode in ['timing', 'allocation']:
        path = ntt / (prefix + '-' + mode) / 'execution.json'
        d = read(path)
        assert d['provenance_after'] and len(d['runs']) == count
        label = 'ntt-' + prefix + '-' + mode
        sources[label] = sha(path)
        for r in d['runs']:
            assert r['exit_code'] == 0
            add(label, r['index'], mode, r['started_at'], r['completed_at'])
matrix = a.matrix_root / 'results/bouncycastle/matrix-alternatives/collection/collection.json'
d = read(matrix)
assert d['status'] == 'complete' and len(d['jobs']) == 288
sources['matrix'] = sha(matrix)
for r in d['jobs']:
    assert r['exit_code'] == 0
    add('matrix-' + r['mode'], r['index'], r['mode'], r['started_at'], r['completed_at'])
wots = a.wots_root / 'results/bouncycastle/wots-alternatives'
for folder, label, count in [(wots, 'wots-screen', 288)] + ([] if a.initial_only else [(wots / 'confirmation', 'wots-followup', 384)]):
    path = folder / 'execution.json'
    d = read(path)
    assert d['passed'] and len(d['runs']) == count
    sources[label] = sha(path)
    for i, r in enumerate(d['runs']):
        stem = 'run-%03d' % i
        command = read(folder / (stem + '.command.json'))
        status = read(folder / (stem + '.status.json'))
        assert status['exit_code'] == 0
        add(label, i, r['job']['mode'], command['started_at'], status['finished_at'])
ordered = sorted(intervals, key=lambda x: date(x['start']))
assert len(ordered) == (864 if a.initial_only else 1464)
assert all(date(x['end']) <= date(y['start']) for x, y in zip(ordered, ordered[1:])), 'benchmark processes overlap'
native = root / 'results/bouncycastle/alternative-comparison/native'
labels = ['ntt-' + v for v in ['baseline', 'fused', 'companion', 'both']] + ['matrix-' + v for v in ['baseline', 'lazy', 'stream', 'combined']] + ['wots-' + v for v in ['baseline', 'object_hoist', 'field_rewrite', 'two_addresses', 'buffer', 'buffer_peeled']]
assert all(date(read(native / (label + '.json'))['end']) <= date(ordered[0]['start']) for label in labels)
report = {'passed': True, 'initial_only': a.initial_only, 'processes': len(ordered), 'no_recorded_benchmark_overlap': True, 'initial_native_gates_before_first_benchmark': True, 'source_execution_sha256': sources, 'cohorts': {k: {'processes': len(v), 'start': min(x['start'] for x in v), 'end': max(x['end'] for x in v), 'longest_process_seconds': max(x['seconds'] for x in v)} for k, v in cohorts.items()}, 'processes_over_10_seconds': [r for r in ordered if r['seconds'] > 10], 'limits': 'Recorded benchmark chronology only; does not establish host isolation or explain long durations. Allocation cohorts do not measure operation time.'}
print(json.dumps(report, indent=2))
