#!/usr/bin/env python3
"""Check integrated coverage, arithmetic, evidence hashes and collection chronology."""
import csv
import datetime as dt
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def require(ok, message):
    if not ok: raise ValueError(message)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def close(a, b): return math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-9)
def read(path): return json.loads((ROOT/path).read_text())

def main():
    coverage = read('results/measurement-completion/coverage.json')
    for p, digest in coverage['summaries'].items(): require(sha(ROOT/p)==digest, 'Changed summary '+p)
    for row in coverage['baseline_timings']:
        require(sha(ROOT/row['source'])==row['source_sha256'], 'Changed baseline evidence')
        require(row['candidate_wall_ns'] is None and row['time_saved_percent'] is None, 'Invented baseline gain')
    with (ROOT/'results/resource-regressions/complete-performance-comparison.csv').open() as f:
        cells = list(csv.DictReader(f))
    counts = Counter(r['status'] for r in cells)
    require(len(cells)==309 and counts==Counter(measured=117, baseline_only=174, not_provided=18), 'Incomplete or altered timing coverage: '+str(counts))
    require(len({(r['library'],r['parameter'],r['operation']) for r in cells})==309, 'Duplicate timing cell')
    for row in cells:
        if row['status']=='measured':
            a,b=float(row['baseline_ms']),float(row['candidate_ms'])
            require(a>0 and b>0 and close(float(row['time_saved_percent']),100*(1-b/a)), 'Incorrect timing percentage')
        else:
            require(row['candidate_ms']==row['time_saved_percent']=='', 'Unmeasured gain is not blank')
            require((float(row['baseline_ms'])>0) if row['status']=='baseline_only' else row['baseline_ms']=='', 'Wrong baseline availability')
    resources = read('results/measurement-completion/resource-observations.json')
    for p,digest in resources['sources'].items(): require(sha(ROOT/p)==digest, 'Changed resource evidence '+p)
    metric_keys=set()
    for row in resources['observations']:
        key=tuple(row[k] for k in ['library','parameter','operation','patch','settings','metric'])
        require(key not in metric_keys, 'Duplicate resource metric'); metric_keys.add(key)
        a,b=row['baseline'],row['candidate']
        require(all(type(v) in [int,float] and math.isfinite(v) for v in [a,b]), 'Nonfinite resource observation')
        require(close(row['absolute_change'],b-a), 'Wrong absolute resource change')
        require(row['change_percent'] is None if a==0 else close(row['change_percent'],100*(b/a-1)), 'Wrong resource percentage')
        require(row['source'] in resources['sources'] and row['scope'] and row['unit'] and row['statistic'], 'Missing metric provenance')
    for row in resources.get('baseline_only',[]):
        require(row['candidate'] is None and row['change_percent'] is None, 'Invented baseline resource gain')
        require(row['source'] in resources['sources'] and row['scope'], 'Missing baseline resource provenance')
        values=row['samples']
        require(values and all(type(v) in [int,float] and math.isfinite(v) and v>=0 for v in values), 'Invalid baseline resource sample')
        import statistics
        expected=statistics.median(values) if row['statistic'].startswith('median') else statistics.mean(values)
        require(close(row['baseline'],expected), 'Incorrect baseline resource aggregate')
    intervals=[]
    for lib in ['rustcrypto','bouncycastle']:
        d=read(f'results/{lib}/completion/result.json')
        intervals.append((d['started_at'],d['finished_at'],lib))
    for lib in ['liboqs','openssl']:
        for phase in ['baseline-timing','resources']:
            d=read(f'results/{lib}/complete-indicators/{phase}/execution.json')
            require(d['complete'] is True, 'Incomplete C collection')
            intervals.append((d['started_at'],d['finished_at'],lib+'/'+phase))
    for lib in ['noble','circl']:
        for phase in ['baseline','resource']:
            d=read(f'results/{lib}/resource-followup/{phase}/execution.json')
            require(d['passed'] is True, 'Incomplete managed-runtime collection')
            intervals.append((d['started_at'],d['completed_at'],lib+'/'+phase))
    parsed=sorted((dt.datetime.fromisoformat(a),dt.datetime.fromisoformat(b),label) for a,b,label in intervals)
    require(all(a<=b for a,b,label in parsed), 'Invalid collection interval')
    require(all(parsed[i-1][1]<=parsed[i][0] for i in range(1,len(parsed))), 'Overlapping measured collection batches')
    result=dict(schema='completion-report-audit-v1',passed=True,timing_cells=len(cells),statuses=dict(counts),paired_resource_metrics=len(metric_keys),baseline_resource_metrics=len(resources.get('baseline_only',[])),unavailable_resource_metrics=len(resources.get('unavailable',[])),serial_collection_batches=[label for a,b,label in parsed],scope='Integrated saved-evidence hashes, coverage, percentages and batch chronology; provider raw-result checks are separate; not an independent cryptographic audit')
    (ROOT/'results/measurement-completion/independent-check.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
