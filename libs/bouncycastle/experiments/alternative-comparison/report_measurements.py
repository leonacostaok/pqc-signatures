#!/usr/bin/env python3
"""Render all candidate comparisons from independently checked saved summaries."""
import hashlib
import json
import statistics
from pathlib import Path

if not __debug__:
    raise SystemExit('optimized Python is unsupported')
root = Path(__file__).resolve().parents[4]
out = root / 'results/bouncycastle/alternative-comparison'
rows = []
sources = {}
def read(relative):
    p = root / relative
    sources[relative] = hashlib.sha256(p.read_bytes()).hexdigest()
    return json.loads(p.read_text())
def row(campaign, param, reference, variant, operation, wall, cpu, allocation):
    record = dict(campaign=campaign, parameter=param, reference=reference, variant=variant, operation=operation)
    for name, pair in [('wall_ns', wall), ('thread_cpu_ns', cpu), ('allocated_bytes', allocation)]:
        baseline, candidate = pair
        assert baseline > 0 and candidate >= 0
        record[name] = {'baseline': baseline, 'candidate': candidate, 'percent_change': 100 * (candidate / baseline - 1)}
    rows.append(record)
for campaign, name in [('NTT Java 25 screen', 'ntt-independent-audit.json'), ('NTT Java 17 held-out confirmation', 'ntt-confirmation-independent-audit.json')]:
    data = read('results/bouncycastle/alternative-comparison/' + name)
    assert data['passed']
    for c in data['summary']:
        fields = [(c[k]['original_mean'], c[k]['changed_mean']) for k in ['wall_ns', 'cpu_ns', 'allocated_bytes']]
        row(campaign, c['parameter'], 'baseline', c['variant'], c['operation'], *fields)
matrix = read('results/bouncycastle/alternative-comparison/matrix-independent-audit.json')
assert matrix['preparation_passed'] and matrix['batches'] == 288
for c in matrix['comparisons']:
    fields = [(c['metrics'][k]['baseline_per_call'], c['metrics'][k]['variant_per_call']) for k in ['wall_ns', 'cpu_ns', 'allocated_bytes']]
    row('Matrix Java 25 screen', c['parameter'], 'baseline', c['variant'], c['operation'], *fields)
for campaign, suffix in [('WOTS Java 25 screen', ''), ('WOTS Java 25 selected higher-size followup', 'confirmation/')]:
    data = read('results/bouncycastle/wots-alternatives/' + suffix + 'summary.json')
    cells = {(c['mode'], c['parameter'], c['operation'], tuple(c['comparison'])): c for c in data['cells']}
    for key, c in cells.items():
        if key[0] != 'bench':
            continue
        memory = cells[('allocation', *key[1:])]
        fields = []
        for cell, metric in [(c, 'wall_ns'), (c, 'thread_cpu_ns'), (memory, 'allocated_bytes')]:
            m = cell['metrics'][metric]
            fields.append((statistics.mean(m['reference_process_means']), statistics.mean(m['candidate_process_means'])))
        row(campaign, c['parameter'], c['comparison'][0], c['comparison'][1], c['operation'].replace('.total', ''), *fields)
assert len(rows) == 156
assert len({(r['campaign'], r['parameter'], r['reference'], r['variant'], r['operation']) for r in rows}) == len(rows)
def change(value):
    if abs(value) < 0.005:
        return '⚪ 0.00%'
    return ('🟢 ' if value < 0 else '🔴 ') + ('%+.2f%%' % value)
text = ['# Bouncy Castle alternative measurements', '', 'All 156 candidate/action comparisons are retained. Green means the recorded value decreased; red means it increased. Color indicates direction, not statistical confidence or a recommendation. Negative time change means less elapsed time per operation, not the same percentage increase in throughput.', '', 'These campaigns use different corpora, runtime versions, warmup caps and heap settings. Compare each candidate only with its listed reference. CPU is calling-thread CPU. Allocated bytes come from separate JVM cohorts and exclude static initialization; the NTT companion table adds 1,024 bytes of static payload plus its header. Peak/live heap, RSS, stack and GC pauses are not measured here. Seven matrix allocation processes had unusually long durations; their counts are retained with that qualification.', '', 'See the [verdicts and limits](alternative-comparison.md) and each group report for pair/round variation, unchanged controls, correctness and promotion rules. All values below are arithmetic means; times are milliseconds and allocations are bytes per call.', '']
for campaign in dict.fromkeys(r['campaign'] for r in rows):
    text += ['## ' + campaign, '', '| Parameter | Reference → candidate | Action | Original ms | Changed ms | Time Δ | CPU Δ | Original B/op | Changed B/op | Allocation Δ |', '|---|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for r in rows:
        if r['campaign'] != campaign:
            continue
        w, c, m = (r[k] for k in ['wall_ns', 'thread_cpu_ns', 'allocated_bytes'])
        text.append('| %s | %s → %s | %s | %.4f | %.4f | %s | %s | %.1f | %.1f | %s |' % (r['parameter'], r['reference'], r['variant'], r['operation'], w['baseline'] / 1e6, w['candidate'] / 1e6, change(w['percent_change']), change(c['percent_change']), m['baseline'], m['candidate'], change(m['percent_change'])))
    text.append('')
(root / 'docs/bouncycastle/alternative-measurements.md').write_text('\n'.join(text) + '\n')
(out / 'measurements.json').write_text(json.dumps({'source_sha256': sources, 'comparisons': rows}, indent=2) + '\n')
print('Rendered all 156 comparisons with time, CPU and allocation changes.')
