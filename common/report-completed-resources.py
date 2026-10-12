#!/usr/bin/env python3
"""Normalize scoped follow-up observations without pooling measurement protocols."""
import argparse
import csv
import hashlib
import json
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def percent(a, b):
    return 100 * (b / a - 1) if a else None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', type=Path, action='append', required=True)
    args = parser.parse_args()
    rows, sources, unavailable, baseline_rows = [], {}, [], []
    def baseline(lib, parameter, operation, metric, values, unit, statistic, source, scope):
        if not values or not all(type(v) in (int,float) and math.isfinite(v) and v >= 0 for v in values):
            raise ValueError('Invalid baseline resource observation')
        value = statistics.median(values) if statistic.startswith('median') else statistics.mean(values)
        baseline_rows.append(dict(library=lib, parameter=parameter, operation=operation, metric=metric,
                                  baseline=value, candidate=None, change_percent=None, unit=unit,
                                  statistic=statistic, samples=values, source=source, scope=scope))
    def add(lib, parameter, operation, patch, setting, metric, a, b, unit, statistic, source, scope, supplied=None):
        if not all(type(v) in (int, float) and math.isfinite(v) for v in (a, b)):
            raise ValueError(f'Invalid observation: {lib} {metric}')
        change = percent(a, b)
        if supplied is not None and (change is None or not math.isclose(change, supplied, abs_tol=1e-8)):
            raise ValueError(f'Incorrect percentage: {lib} {metric}')
        rows.append(dict(library=lib, parameter=parameter, operation=operation, patch=patch, settings=setting,
                         metric=metric, baseline=a, candidate=b, absolute_change=b-a, change_percent=change,
                         unit=unit, statistic=statistic, source=source, scope=scope))
    for p in args.summary:
        p = p.resolve(); source = str(p.relative_to(ROOT)); raw = p.read_bytes(); d = json.loads(raw)
        sources[source] = hashlib.sha256(raw).hexdigest()
        for cell in d['baseline_timings']:
            if 'process_highwater_rss_bytes' in cell:
                baseline(cell['library'], cell['parameter'], cell['operation'], 'process_highwater_rss_bytes',
                         cell['process_highwater_rss_bytes'], 'bytes', 'median of three fresh processes', source,
                         'High-water at end of measured phase; includes startup, warmup and earlier phases; no candidate')
        if d['schema'].startswith('bc-'):
            for run in d['runs']:
                if run['job']['mode'] != 'timing': continue
                native = run['job']['parameter']
                parameter = ('ML-DSA-' if native.startswith('ml_dsa') else 'Falcon-')+native.split('_')[-1]
                baseline('bouncycastle', parameter, 'whole process', 'process_highwater_rss_bytes', [run['max_rss_bytes']], 'bytes', 'one complete fresh process', source,
                         'Baseline timing process including all three actions, warmup, fixtures and checks; no candidate')
                for batch in run['batches']:
                    op = batch['operation']; samples = [r for r in run['samples'] if r['operation']==op]
                    baseline('bouncycastle', parameter, op, 'allocated_bytes', [r['allocated_bytes'] for r in samples], 'bytes/op', 'mean of ten distinct keys', source,
                             'Thread-accounted API allocation, includes fresh key decoding/objects or keygen encoding; baseline-only')
                    for metric in ['gc_count','gc_time_ms','heap_before_bytes','heap_after_bytes']:
                        baseline('bouncycastle', parameter, op, metric, [batch[metric]],
                                 'bytes' if 'bytes' in metric else 'ms/workload' if metric=='gc_time_ms' else 'events/workload',
                                 'one ten-key checked workload', source, 'Baseline checked batch; no requested-GC snapshot or candidate')
        if d['schema'].startswith('rust'):
            for r in d['allocation']:
                if r['variant']=='baseline' and r['parameter'].startswith('SLH-DSA'):
                    for metric in r['mean']:
                        baseline('rustcrypto', r['parameter'], r['operation'], metric,
                                 [x[metric] for x in r['all_samples']],
                                 'count/op' if metric in ['allocations','reallocations'] else 'bytes/op',
                                 'mean of ten distinct keys', source, 'Separate allocator probe, encoding/public-key extraction excluded; no candidate')
            for r in d['runs']:
                if r['mode']=='normal' and r['variant']=='baseline' and r['parameter'].startswith('SLH-DSA'):
                    baseline('rustcrypto', r['parameter'], 'whole process', 'process_highwater_rss_bytes', [r['rss_bytes']], 'bytes', 'one complete fresh process', source,
                             'Whole three-action process including startup, warmup and checks; no candidate')
            for r in d['paired_resources']:
                add('rustcrypto', r['parameter'], 'whole process', 'ML constructor', 'default+zeroize', r['metric'], r['original_median'], r['changed_median'], 'bytes', 'median of four processes', source, r['scope'], r['change_percent'])
            index = {(r['parameter'], r['operation'], r['variant']): r for r in d['allocation']}
            for (parameter, op, variant), r in index.items():
                if variant != 'candidate': continue
                b = index[(parameter, op, 'baseline')]
                for metric, value in r['mean'].items():
                    add('rustcrypto', parameter, op, 'ML constructor', 'default+zeroize', metric, b['mean'][metric], value,
                        'count/op' if metric in ['allocations', 'reallocations'] else 'bytes/op', 'mean of ten distinct keys', source,
                        'Separate allocator probe; API scope excludes encoding and public-key extraction; not the timing binary')
        else:
            for r in d.get('resource_records', d.get('paired_resources', [])):
                lib = r['library']; patch = r.get('patch', 'published patch'); setting = r.get('settings', 'G1; Xms64m; Xmx512m; ActiveProcessorCount=2' if lib == 'bouncycastle' else 'provider configuration')
                scope = r.get('scope', d.get('interpretation', r.get('measurement_kind', 'Provider-defined diagnostic')))
                if lib in ['liboqs', 'openssl']:
                    scope = ' '.join(r[k] for k in ['allocation_label', 'rss_label', 'stack_label'])
                for metric, m in r['metrics'].items():
                    a = m.get('baseline', m.get('original')); b = m.get('candidate', m.get('changed'))
                    if a is None or b is None:
                        unavailable.append(dict(library=lib, parameter=r['parameter'], operation=r['operation'], patch=patch, settings=setting, metric=metric, source=source, provider_record=m))
                        continue
                    unit = m.get('unit', 'bytes/op' if metric.endswith('bytes_per_op') else 'bytes' if 'bytes' in metric else 'ms/workload' if metric == 'gc_time_ms' else 'ns/op' if metric.endswith('ns_per_op') else 'events/workload')
                    stat = m.get('statistic', 'arithmetic mean of two fresh processes')
                    add(lib, r['parameter'], r['operation'], patch, setting, metric, a, b, unit, stat, source, scope,
                        m.get('change_percent', m.get('delta_percent')))
    seen = set()
    for r in rows:
        key = tuple(r[k] for k in ['library', 'parameter', 'operation', 'patch', 'settings', 'metric'])
        if key in seen: raise ValueError(f'Duplicate metric: {key}')
        seen.add(key)
    out = ROOT/'results/measurement-completion'; out.mkdir(parents=True, exist_ok=True)
    result = dict(schema='completed-resource-observations-v1', sources=sources, observations=rows, unavailable=unavailable, baseline_only=baseline_rows,
                  limits='Each row retains its own scope/statistic. Negative resource changes are smaller observations, not proof of a causal benefit. Zero baseline percentages are undefined. Diagnostic timing is not clean benchmark evidence.')
    (out/'resource-observations.json').write_text(json.dumps(result, indent=2, allow_nan=False)+'\n')
    with (out/'resource-observations.csv').open('w') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n"); w.writeheader(); w.writerows(rows)
    with (out/'baseline-resource-observations.csv').open('w') as f:
        w = csv.DictWriter(f, fieldnames=list(baseline_rows[0]), lineterminator="\n"); w.writeheader(); w.writerows(baseline_rows)
    print(f'Normalized {len(rows)} paired metric observations from {len(sources)} summaries')

if __name__ == '__main__':
    main()
