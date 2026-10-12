#!/usr/bin/env python3
"""Count whole-verification allocation separately from the frozen timing runner."""
import argparse
import datetime
import json
import os
from pathlib import Path
import statistics
import tempfile
import fors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    output = Path(args.out).resolve()
    if output.exists(): raise FileExistsError(output)
    m = json.loads(Path(args.manifest).read_text())
    assert m['provenance'] == fors.provenance(m)
    assert m['jvm_environment'] == {k: os.environ.get(k, '') for k in m['jvm_environment']}
    source = fors.HERE / 'ForsVerifyAllocation.java'
    gate_sources = {'driver_source_sha256': fors.sha(source), 'collector_sha256': fors.sha(__file__)}
    directory = fors.BUILD / ('verify-allocation-' + fors.sha(source)[:16])
    directory.mkdir(parents=True, exist_ok=False)
    java = Path(m['java']); javac = java.with_name('javac')
    fors.run([javac, '-d', directory, source], logfile=directory / 'compile.txt')
    command = [java, '-Xmx1g', '-XX:ActiveProcessorCount=1', '-cp', str(directory) + ':' + m['driver'],
        'ForsVerifyAllocation', m['baseline'], m['candidate'], m['fixtures']]
    raw = fors.run(command, logfile=directory / 'raw.txt')
    rows = [json.loads(line) for line in raw.stdout.splitlines()]
    assert len(rows) == 48 and len({(r['parameter'], r['round']) for r in rows}) == 48
    expected_parameters = [f'{family}_{size}{kind}' for family in ['sha2', 'shake']
        for size in [128, 192, 256] for kind in ['f', 's']]
    assert {r['parameter'] for r in rows} == set(expected_parameters)
    summary = []
    for name in sorted({r['parameter'] for r in rows}):
        selected = [r for r in rows if r['parameter'] == name]
        assert sorted(r['round'] for r in selected) == list(range(4))
        assert all(r['calls_per_side'] == 128 and r['baseline_bytes'] > 0 and r['candidate_bytes'] > 0 for r in selected)
        assert all(r['order'] == ('AB' if (expected_parameters.index(name) + r['round']) % 2 == 0 else 'BA') for r in selected)
        before = statistics.median(r['baseline_bytes'] / r['calls_per_side'] for r in selected)
        after = statistics.median(r['candidate_bytes'] / r['calls_per_side'] for r in selected)
        summary.append({'parameter': name, 'baseline_bytes_per_verify': before,
            'candidate_bytes_per_verify': after, 'bytes_saved_per_verify': before - after,
            'allocation_reduction_fraction': (before - after) / before})
    assert len(summary) == 12 and m['provenance'] == fors.provenance(m)
    assert gate_sources == {'driver_source_sha256': fors.sha(source), 'collector_sha256': fors.sha(__file__)}
    result = {'schema': 'bc-fors-verify-allocation-v1', 'date': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'prepared': m, **gate_sources, 'driver_class_sha256': fors.tree(directory),
        'command': list(map(str, command)), 'warmup_calls_per_side_parameter': 256,
        'method': 'median of four fixed 128-call whole-corpus batches; current-thread allocation including identical reflective wrapper overhead; excludes key decoding and fixture parsing; not peak heap or a latency measurement',
        'summary': summary, 'rows': rows}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=output.parent, delete=False) as f:
        json.dump(result, f, indent=2); f.write('\n'); temporary = f.name
    try: os.link(temporary, output)
    finally: os.unlink(temporary)
    print(output)


if __name__ == '__main__': main()
