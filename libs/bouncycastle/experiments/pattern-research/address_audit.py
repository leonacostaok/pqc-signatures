#!/usr/bin/env python3
"""Read-only independent recomputation of the saved ADRS screen; runs no crypto.

Usage: python3 bc-address-audit.py [checkout-root]
The default checkout root is the current directory. Absolute manifest paths must
remain accessible. This checks recorded evidence, not machine exclusivity,
statistical confidence, all-parameter conformance, or fresh-key-every-call timing.
"""
import json, pathlib, hashlib, statistics, collections, tarfile, datetime, sys

if not __debug__:
    raise SystemExit("Assertions are required; do not use -O or PYTHONOPTIMIZE")

root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path.cwd()
p = root / 'results/bouncycastle/pattern-research/address'
sha = lambda x: hashlib.sha256(pathlib.Path(x).read_bytes()).hexdigest()
read = lambda n: json.loads((p / n).read_text())
m = read('manifest.json'); plan = read('plan.json'); e = read('execution.json'); s = read('summary.json')
parent = json.loads(pathlib.Path(m['parent_manifest']).read_text())
assert sha(m['parent_manifest']) == m['parent_manifest_sha256']
assert sha(p / 'manifest.json') == e['manifest_sha256']
assert sha(p / 'execution.json') == s['execution_sha256']
assert all(sha(k) == v for k, v in m['files'].items())
assert sha(m['java']) == m['java_sha256']
for kind, key in [('classes', 'class_hashes'), ('drivers', 'driver_hashes')]:
    for side, path in m[kind].items():
        folder = pathlib.Path(path)
        actual = {str(x.relative_to(folder)): sha(x) for x in sorted(folder.rglob('*.class'))}
        assert actual == m[key][side]
assert set(m['class_hashes']['baseline']) == set(m['class_hashes']['candidate'])
changed = [k for k, v in m['class_hashes']['baseline'].items() if m['class_hashes']['candidate'][k] != v]
assert changed == ['org/bouncycastle/crypto/signers/slhdsa/WotsPlus.class']
assert m['driver_hashes']['baseline'] == m['driver_hashes']['candidate']
assert not any(k.endswith('/WotsPlus.class') for k in m['driver_hashes']['baseline'])
oldpath = pathlib.Path(parent['classes']['baseline'])
oldmap = {str(x.relative_to(oldpath)): sha(x) for x in sorted(oldpath.rglob('*.class'))}
h = hashlib.sha256()
for k, v in oldmap.items():
    h.update(k.encode() + b'\0' + bytes.fromhex(v))
assert h.hexdigest() == parent['provenance']['classes']['baseline']
assert {k: v for k, v in oldmap.items() if k not in changed} == {k: v for k, v in m['class_hashes']['baseline'].items() if k not in changed}
assert sha(m['fixtures']) == parent['provenance']['files'][parent['fixtures']]
archive = pathlib.Path(m['parent_manifest']).parent / 'baseline-source.tar'
assert sha(archive) == parent['provenance']['files'][str(archive)]
with tarfile.open(archive) as t:
    assert t.extractfile('core/src/main/java/org/bouncycastle/crypto/signers/slhdsa/WotsPlus.java').read() == (p / 'preparation/baseline-WotsPlus.java').read_bytes()
traces = [[json.loads(x) for x in (p / ('trace-' + side + '.stdout.jsonl')).read_text().splitlines()] for side in ['baseline', 'candidate']]
assert traces[0] == traces[1] and len(traces[0]) == 24
for row in traces[0]:
    n = row['n']; case = row['case']
    msg = [0 if case % 3 == 0 else 255 if case % 3 == 1 else (i * 19 + case) & 255 for i in range(n)]
    digs = [d for b in msg for d in [b >> 4, b & 15]]
    cs = sum(15 - d for d in digs)
    digs.extend([cs >> 8, (cs >> 4) & 15, cs & 15]); length = 2 * n + 3
    assert row['calls'] == 2 * (17 * length + sum(digs) + 1) and row['ownership']
expected = {}
for parameter in ['sha2_128f', 'shake_128f']:
    stripped = []
    for side in ['baseline', 'candidate']:
        rows = [json.loads(x) for x in (p / ('check-' + parameter + '-' + side + '.stdout.jsonl')).read_text().splitlines()]
        assert len(rows) == 36 and {(r['phase'], r['case'], r['operation']) for r in rows} == {(phase, i, op) for phase, n in [('warmup', 2), ('measured', 10)] for i in range(n) for op in ['keygen.total', 'sign.total', 'verify.total']}
        assert all(r['checked'] and r['parameter'] == parameter and r['variant'] == side and r['class_source'] == m['classes'][side] for r in rows)
        for r in rows:
            expected[(parameter, r['phase'], r['case'], r['operation'])] = r['output_sha256']
        stripped.append([{k: v for k, v in r.items() if k not in ['variant', 'class_source']} for r in rows])
    assert stripped[0] == stripped[1]
assert len(e['runs']) == len(plan['jobs']) == 48
slots = {}; counts = collections.Counter(); starts = []; ends = []
for i, (record, job) in enumerate(zip(e['runs'], plan['jobs'])):
    assert record['job'] == job
    side = job['variant']; name = f'run-{i:03d}'; path = p / record['raw']
    assert sha(path) == record['sha256']
    command = read(name + '.command.json'); status = read(name + '.status.json')
    assert status['exit_code'] == 0
    assert command['command'] == [m['java'], *m['jvm_args'], '-cp', m['drivers'][side] + ':' + m['classes'][side], 'org.bouncycastle.crypto.signers.slhdsa.SlhDeepProbe', job['mode'], m['fixtures'], job['parameter'], side, job['operation'], str(job['fork']), str(job['rounds']), str(job['budget_ms']), str(job['warmup_cycles'])]
    starts.append(datetime.datetime.fromisoformat(command['started_at']))
    ends.append(datetime.datetime.fromisoformat(status['finished_at']))
    rows = [json.loads(x) for x in path.read_text().splitlines()]
    assert len(rows) == record['rows']; counts[job['mode']] += len(rows)
    for row in rows:
        assert all(row[k] == job[k] for k in ['parameter', 'operation', 'fork', 'variant'])
        assert row['checked'] and row['class_source'] == m['classes'][side] and row['warmup_calls'] == 80
        assert row['output_sha256'] == expected[(job['parameter'], 'measured', row['case'], job['operation'])]
        assert all(row[k] >= 0 for k in ['wall_ns', 'cpu_ns', 'thread_cpu_ns', 'allocated_bytes'])
    for rnd in [0, 1]:
        rr = [r for r in rows if r['round'] == rnd]; cycles = len(rr) // 4
        assert [(r['cycle'], r['case']) for r in rr] == [(c, k) for c in range(cycles) for k in [0, 3, 6, 9]]
        if job['mode'] == 'allocation':
            assert cycles == 1 and all(r['wall_ns'] == r['cpu_ns'] == r['thread_cpu_ns'] == 0 for r in rr)
        else:
            assert sum(r['wall_ns'] for r in rr) >= 100000000 and sum(r['wall_ns'] for r in rr[:-4]) < 100000000
    slots[(job['mode'], job['parameter'], job['operation'], job['fork'], side)] = {k: statistics.mean(r[k] for r in rows) for k in ['wall_ns', 'thread_cpu_ns', 'allocated_bytes']}
assert all(ends[i] <= starts[i + 1] for i in range(47))
for cell in s['cells']:
    key = (cell['mode'], cell['parameter'], cell['operation'])
    for metric, v in cell['metrics'].items():
        a = [slots[(*key, i, 'baseline')][metric] for i in range(2)]
        b = [slots[(*key, i, 'candidate')][metric] for i in range(2)]
        assert v['baseline_process_means'] == a and v['candidate_process_means'] == b
        assert v['change_percent'] == [100 * (y / x - 1) for x, y in zip(a, b)]
        assert v['aggregate_change_percent'] == 100 * (statistics.mean(b) / statistics.mean(a) - 1)
print(json.dumps({'audit': 'passed', 'processes': 48, 'rows': counts, 'changed_classes': changed, 'trace_cases': 24, 'check_rows_per_variant': 72, 'start': str(starts[0]), 'end': str(ends[-1]), 'no_overlapping_measured_processes': True, 'summary_cells': len(s['cells'])}, indent=2))
