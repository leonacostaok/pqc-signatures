#!/usr/bin/env python3
"""Express audited resource observations as absolute and relative changes."""
import hashlib
import json
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {}
ROWS = []

def read(name, jsonl=False):
    path = ROOT / name
    raw = path.read_bytes()
    SOURCES[name] = hashlib.sha256(raw).hexdigest()
    return [json.loads(line) for line in raw.splitlines()] if jsonl else json.loads(raw)

def add(lib, param, operation, metric, baseline, candidate, unit, scope):
    if baseline < 0 or candidate < 0:
        raise ValueError('Only nonnegative cost metrics are accepted')
    ROWS.append(dict(library=lib, parameter=param, operation=operation, metric=metric,
                     baseline=baseline, candidate=candidate, delta=candidate-baseline,
                     change_percent=100*(candidate/baseline-1) if baseline else None,
                     unit=unit, scope=scope))

noble = read('results/noble/resource-audit/summary.json')
for row in noble['constructors']:
    b = mean(p['baseline_count'] for p in row['pairs']) * 1024
    c = mean(p['candidate_count'] for p in row['pairs']) * 1024
    add('noble', f"ML-DSA-{row['parameter']}", row['operation'], 'polynomial_payload_allocated', b, c, 'bytes', 'Counted numeric Int32Array payload, excludes total JS allocation/overhead/peak')
for row in noble['post_gc']:
    v = row['variants']
    for metric in ['heapUsed', 'arrayBuffers']:
        add('noble', f"ML-DSA-{row['parameter']}", row['operation'], 'post_gc_'+metric,
            v['baseline']['memory'][metric]['final_median'], v['candidate']['memory'][metric]['final_median'], 'bytes', 'Median final process snapshot; includes harness/runtime/JIT, not operation peak')

circl = read('results/circl/resource-audit/summary.json')
for row in circl['cells']:
    for metric, unit in [('allocated_bytes', 'bytes'), ('allocated_objects', 'objects')]:
        v = row[metric]
        add('circl', row['parameter'], row['operation'], metric, v['baseline_mean'], v['candidate_mean'], unit, 'Mean complete-call runtime accounting; caller setup excluded; automatic GC disabled')

openssl = {side: read(f'results/openssl/resource-audit/{side}.jsonl', True) for side in ['baseline', 'candidate']}
for b in openssl['baseline']:
    if b['action'] != 'new-use-free':
        continue
    c, = [r for r in openssl['candidate'] if r['parameter'] == b['parameter'] and r['action'] == b['action']]
    for metric, unit in [('requested_bytes', 'bytes'), ('allocations', 'objects')]:
        add('openssl', b['parameter'], 'hash_context_new', metric, b[metric], c[metric], unit, 'Focused hash context, synthetic key without HMAC; not full EVP operation')

liboqs = read('results/liboqs/resource-audit/provenance.json')
for row in liboqs['stack_frames']:
    add('liboqs', 'private SHA2', row['function'], 'local_frame_reserved', row['baseline_bytes'], row['candidate_bytes'], 'bytes', 'Compiler-specific function frame including inlining; not full-call peak')

rust = read('results/rustcrypto/resource-audit/constructor-frames.json')
for b in rust['rows']:
    if b['variant'] == 'baseline':
        c, = [r for r in rust['rows'] if r['parameter'] == b['parameter'] and r['variant'] == 'candidate']
        add('rustcrypto', b['parameter'], 'constructor', 'local_frame_reserved', b['reserved_frame_bytes'], c['reserved_frame_bytes'], 'bytes', 'Original uninstrumented binary, compiler-specific constructor frame; not full-call peak')

rust = read('results/rustcrypto/resource-audit/accounting.json')
for mode, cases in rust['modes'].items():
    for param in sorted({c['baseline']['parameter'] for c in cases}):
        rs = [c for c in cases if c['baseline']['parameter'] == param]
        for op in ['keygen', 'sign', 'verify', 'fresh_key_sign']:
            for metric, unit in [('allocated_bytes', 'bytes'), ('allocations', 'objects'), ('peak_live_above_entry_bytes', 'bytes')]:
                b = mean(c['baseline']['metrics'][op][metric] for c in rs)
                c = mean(c['candidate']['metrics'][op][metric] for c in rs)
                add('rustcrypto', param, op, metric, b, c, unit, f'Allocator probe {mode}; caller key clone excluded; peak only tracked requested heap above operation entry')

out = dict(schema='audited-resource-percentages-v1', definition='100*(candidate/baseline-1); negative means lower cost; null when baseline=0', sources=SOURCES, rows=ROWS)
(ROOT/'results/resource-regressions/resource-percentages.json').write_text(json.dumps(out, indent=2)+'\n')
lines = ['# Audited resource percentages', '', 'Resource change = 100 × (changed/original − 1). Negative means lower cost. Percentages with a zero baseline are undefined: inspect the absolute values. Large relative changes to small buffers are not large process-memory changes.', '', '| Library | Parameter | Operation | Metric | Original → changed | Change | Measurement scope |', '|---|---|---|---|---|---|---|']
for r in ROWS:
    delta = r['change_percent']
    direction = '⚪' if r['delta'] == 0 else '🟢' if r['delta'] < 0 else '🔴'
    pct = 'undefined (zero baseline)' if delta is None else f'{delta:+.2f}%'
    lines.append(f"| {r['library']} | {r['parameter']} | {r['operation']} | {r['metric']} | {r['baseline']:,.2f} → {r['candidate']:,.2f} {r['unit']} | {direction} {pct} | {r['scope']} |")
(ROOT/'docs/audit/resource-percentages.md').write_text('\n'.join(lines)+'\n')
print(f'Computed {len(ROWS)} scoped resource changes from {len(SOURCES)} source files')
