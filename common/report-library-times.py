#!/usr/bin/env python3
"""Expose recorded absolute times without claiming a matched cross-library trial."""
import csv
import hashlib
import json
from pathlib import Path

if not __debug__:
    raise SystemExit('optimized Python is unsupported')
ROOT = Path(__file__).resolve().parents[1]
LIBS = {'noble': ('Noble', 'TypeScript/JavaScript'), 'liboqs': ('liboqs', 'C'), 'openssl': ('OpenSSL', 'C'), 'circl': ('CIRCL', 'Go'), 'rustcrypto': ('RustCrypto', 'Rust'), 'bouncycastle': ('Bouncy Castle', 'Java')}
PARAMS = ['ML-DSA-' + n for n in ['44', '65', '87']] + ['SLH-DSA-' + h + '-' + n for h in ['SHA2', 'SHAKE'] for n in ['128f', '128s', '192f', '192s', '256f', '256s']] + ['Falcon-512', 'Falcon-1024']
OPS = ['keygen', 'sign', 'verify']
def normalize(p):
    p = str(p)
    if p in ['44', '65', '87']:
        return 'ML-DSA-' + p
    if p.startswith('SLH_DSA_PURE_'):
        p = p.replace('SLH_DSA_PURE_', 'SLH-DSA-').replace('_', '-')
    if p.startswith(('sha2_', 'shake_')):
        p = 'SLH-DSA-' + p.replace('_', '-')
    if p.startswith('SLH-DSA-'):
        p = p.upper()[:-1] + p[-1].lower()
    return p
sources = {}
def read(rel):
    content = (ROOT / rel).read_bytes()
    sources[rel] = hashlib.sha256(content).hexdigest()
    return json.loads(content)
paired_path = 'results/ten-key-order/independent-check.json'
coverage_path = 'results/measurement-completion/coverage.json'
paired = read(paired_path)
coverage = read(coverage_path)
assert paired['complete'] and paired['exact_outputs_match']
for rel, digest in coverage['summaries'].items():
    read(rel)
    assert sources[rel] == digest, rel
pairs = {(r['provider'], normalize(r['parameter']), r['operation']): r for r in paired['summary'] if r['operation'] in OPS}
bases = {(r['library'], normalize(r['parameter']), r['operation']): r for r in coverage['baseline_timings']}
unsupported = {(r['library'], normalize(r['parameter']), r['operation']): r for r in coverage['unsupported']}
assert len(pairs) == 114
assert not set(unsupported).intersection(set(pairs) | set(bases))
rows = []
for p in PARAMS:
    for lib, (name, language) in LIBS.items():
        for op in OPS:
            k = (lib, p, op)
            for view in ['original', 'selected_patch']:
                r = dict(view=view, library=lib, name=name, language=language, parameter=p, operation=op)
                if k in pairs:
                    x = pairs[k]
                    r.update(status='original' if view == 'original' else 'measured_patch', wall_ns=x['baseline_wall_ns' if view == 'original' else 'candidate_wall_ns'] / x['keys'], statistic='arithmetic mean of ten distinct-key calls in one process', protocol='ten-key candidate-first sensitivity; provider-specific setup/import boundaries', source=paired_path)
                elif k in bases:
                    x = bases[k]
                    r.update(status='baseline_only', wall_ns=x['wall_ns'], statistic=x['statistic'], protocol=x.get('protocol', 'See linked provider summary'), source=x['summary'])
                elif k in unsupported:
                    x = unsupported[k]
                    r.update(status='unsupported', wall_ns=None, statistic='', protocol=x['reason'], source=x['summary'])
                else:
                    raise AssertionError('uncovered cell: ' + str(k))
                if r['wall_ns'] is not None:
                    assert r['wall_ns'] > 0
                r['milliseconds'] = r['wall_ns'] / 1e6 if r['wall_ns'] is not None else None
                rows.append(r)
assert len(rows) == 612
lookup = {(r['view'], r['library'], r['parameter'], r['operation']): r for r in rows}
minima = []
for view in ['original', 'selected_patch']:
    for p in PARAMS:
        for op in OPS:
            group = sorted([r for r in rows if (r['view'], r['parameter'], r['operation']) == (view, p, op) and r['wall_ns'] is not None], key=lambda x: x['wall_ns'])
            assert group
            low = group[0]['wall_ns']
            minima.append(dict(view=view, parameter=p, operation=op, library=group[0]['library'], milliseconds=low / 1e6, other_observations_within_5_percent=[r['library'] for r in group[1:] if r['wall_ns'] <= low * 1.05], supported_libraries=len(group)))
mins = {(r['view'], r['parameter'], r['operation']): r for r in minima}
def value(x):
    return f'{x:.4f}'
def best(view, p, op):
    m = mins[view, p, op]
    return LIBS[m['library']][0] + ' ' + value(m['milliseconds']) + (' †' if m['other_observations_within_5_percent'] else '')
lines = ['# Actual operation times by library', '',
'Compare the exact parameter set and action below: ML-DSA-44 is separate from ML-DSA-65/87; SLH-DSA SHA2 is separate from SHAKE, and fast (`f`) from small-signature (`s`) sets. All times are milliseconds per operation; lower is better. 0.1000 ms = 100 microseconds.', '',
'**These are observed times from different protocols, not a controlled cross-library ranking.** The tables make the existing absolute values easy to compare, but cannot establish which implementation is intrinsically faster. Fixtures, key representations, setup boundaries, warmup, sample counts and statistics differ. In particular, Rust ML-DSA keygen is construction from a seed; verification can use its existing expanded/cached key, unlike decoding a fresh serialized key. Short JVM warmup in the ten-key study is not steady-state Java throughput. Close values do not establish a winner.', '',
'Original uses the unpatched side of each selected study. Selected patch uses that study\'s candidate, even when slower, and retains baseline-only observations where no candidate was measured (marked B). It is not a best-of-all-experiments selection and does not imply the patch is merged or available in a release. The later Bouncy Castle NTT/WOTS experiments are [reported separately](bouncycastle/alternative-comparison.md); their different runtime/corpus results are not substituted here.', '',
'[Full source data and statistics](../results/library-times/comparison.csv) · [Source hashes and numerical minima](../results/library-times/comparison.json) · [Provider revisions and patches](provider-improvements.md) · [Measurement boundaries](ten-key-order.md) · [Memory tradeoffs](audit/complete-performance-comparison.md). This report reformats saved evidence; no new timing experiment was run.', '',
'## Lowest recorded times', '',
'Each cell gives the library and its lowest numerical observation for that exact action/parameter. † means another recorded value is within 5%; this is a proximity flag, not a confidence interval or tie test. No sample was removed. Falcon is shown only for supported selected implementations and is not interchangeable with ML-DSA/SLH-DSA.', '']
for view, title in [('original', 'Original implementations'), ('selected_patch', 'Selected patches, baseline where no patch was measured')]:
    lines += ['### ' + title, '', '| Exact signature | Keygen / construction (ms) | Sign (ms) | Verify (ms) |', '|---|---:|---:|---:|']
    for p in PARAMS:
        lines.append('| ' + p + ' | ' + ' | '.join(best(view, p, op) for op in OPS) + ' |')
    lines.append('')
lines += ['## All libraries and actions', '', '🟢 marks the lowest recorded number in that view/parameter/action, not a proven performance advantage. B = baseline-only value reused in both views; — = unsupported by the selected build. Each library name links to its saved source for that parameter. All languages, including interpreted/JIT/native runtime costs, are represented as measured.', '']
for p in PARAMS:
    lines += ['### ' + p, '', '| Library | Language | Original keygen | Original sign | Original verify | Selected keygen | Selected sign | Selected verify |', '|---|---|---:|---:|---:|---:|---:|---:|']
    for lib, (name, language) in LIBS.items():
        first = lookup['original', lib, p, 'keygen']
        fields = []
        for view in ['original', 'selected_patch']:
            for op in OPS:
                r = lookup[view, lib, p, op]
                if r['wall_ns'] is None:
                    fields.append('—')
                else:
                    is_min = r['milliseconds'] == mins[view, p, op]['milliseconds']
                    fields.append(('🟢 ' if is_min else '') + value(r['milliseconds']) + (' B' if r['status'] == 'baseline_only' else ''))
        lines.append('| [' + name + '](../' + first['source'] + ') | ' + language + ' | ' + ' | '.join(fields) + ' |')
    lines.append('')
lines += ['## What would establish a fair ranking?', '', 'Run one shared corpus and message/context/entropy policy on the same host, with pinned builds and equivalent operation boundaries. Report expanded-key operations separately from import-plus-operation and fresh-key construction. Balance provider order across fresh processes, use adequate runtime-specific warmup, and retain distributions and resource costs. Existing evidence supports optimization comparisons within its studies; this report does not replace that matched cross-provider experiment.', '']
out = ROOT / 'results/library-times'
out.mkdir(exist_ok=True)
(out / 'comparison.json').write_text(json.dumps(dict(source_sha256=sources, scope='descriptive cross-study observations; not a matched provider ranking', cells=rows, minima=minima), indent=2) + '\n')
with (out / 'comparison.csv').open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
(ROOT / 'docs/library-times.md').write_text('\n'.join(lines) + '\n')
print('Rendered 612 cells, 17 exact parameter sets, 6 libraries, both original and selected-patch views.')
