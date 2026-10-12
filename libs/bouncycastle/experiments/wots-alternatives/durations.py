#!/usr/bin/env python3
"""Report saved process durations and gaps; do not execute or exclude measurements."""
import argparse
import datetime
import hashlib
import json
import statistics
import sys
from pathlib import Path

if sys.flags.optimize:
    raise RuntimeError('Assertions required; do not use Python -O or PYTHONOPTIMIZE')

parser = argparse.ArgumentParser()
parser.add_argument('root', nargs='?', type=Path, default=Path(__file__).resolve().parents[4])
args = parser.parse_args()
folder = args.root.resolve() / 'results/bouncycastle/wots-alternatives/confirmation'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
execution = json.loads((folder / 'execution.json').read_text())
plan = json.loads((folder / 'plan.json').read_text())
assert execution['passed'] and execution['plan_sha256'] == sha(folder / 'plan.json')
assert len(execution['runs']) == len(plan['jobs']) == 384
rows, groups = [], {}
previous_end = None
for i, (record, job) in enumerate(zip(execution['runs'], plan['jobs'])):
    assert record['job'] == job
    prefix = folder / f'run-{i:03d}'
    command_file = Path(str(prefix) + '.command.json')
    status_file = Path(str(prefix) + '.status.json')
    command = json.loads(command_file.read_text())
    status = json.loads(status_file.read_text())
    start = datetime.datetime.fromisoformat(command['started_at'])
    end = datetime.datetime.fromisoformat(status['finished_at'])
    assert status['exit_code'] == 0 and end >= start
    seconds = (end - start).total_seconds()
    gap = None if previous_end is None else (start - previous_end).total_seconds()
    assert gap is None or gap >= 0
    row = dict(index=i, job=job, started_at=start.isoformat(), finished_at=end.isoformat(),
               seconds=seconds, preceding_gap_seconds=gap,
               command_sha256=sha(command_file), status_sha256=sha(status_file))
    rows.append(row)
    groups.setdefault((job['mode'], job['parameter'], job['operation']), []).append(row)
    previous_end = end

flags = []
for same_work in groups.values():
    median = statistics.median(r['seconds'] for r in same_work)
    assert len(same_work) == 16 and median > 0
    for row in same_work:
        row['same_work_median_seconds'] = median
        row['duration_over_same_work_median'] = row['seconds'] / median
        if row['seconds'] > 10 or row['seconds'] / median > 3:
            flags.append(row['index'])

gaps = [r['preceding_gap_seconds'] for r in rows[1:]]
report = dict(
    execution_sha256=sha(folder / 'execution.json'),
    plan_sha256=sha(folder / 'plan.json'),
    script_sha256=sha(Path(__file__)),
    processes=len(rows),
    recorded_span_seconds=(datetime.datetime.fromisoformat(rows[-1]['finished_at']) -
                           datetime.datetime.fromisoformat(rows[0]['started_at'])).total_seconds(),
    min_process_seconds=min(r['seconds'] for r in rows),
    median_process_seconds=statistics.median(r['seconds'] for r in rows),
    max_process_seconds=max(r['seconds'] for r in rows),
    max_preceding_gap_seconds=max(gaps),
    diagnostic_rule='Post-hoc descriptive flags: process >10 seconds OR >3 times the median of its mode/parameter/operation group; gap >1 second. This is not a sample exclusion rule.',
    flagged_process_indices=sorted(flags),
    flagged_gap_before_indices=[r['index'] for r in rows[1:] if r['preceding_gap_seconds'] > 1],
    limits='Timestamps cover complete JVM processes, including startup, warmup, checks and measured calls. Wall timestamps alone cannot prove or identify OS scheduling, sleep, GC, JIT, frequency or clock effects. All observations are retained; no process was rerun.',
    rows=rows,
)
print(json.dumps(report, indent=2))
