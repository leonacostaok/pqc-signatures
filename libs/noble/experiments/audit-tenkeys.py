#!/usr/bin/env python3
"""Recompute ten-key reports from raw outputs and verify their sealed sources."""
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[3]
OPS = ('keygen', 'sign', 'verify')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def encoded_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def tree(path, go=False):
    files = {str(p.relative_to(path)): digest(p) for p in sorted(path.rglob('*')) if p.is_file()
             and (not go or p.suffix in ('.go', '.s', '.h', '.c') or p.name in ('go.mod', 'go.sum'))}
    return {'sha256': encoded_hash(files), 'files': len(files)}


def audit(candidate_path, baseline_path):
    candidate = json.loads(candidate_path.read_text()); baseline = json.loads(baseline_path.read_text())
    assert candidate['variant'] == 'candidate' and baseline['variant'] == 'baseline'
    assert candidate['manifest'] == baseline['manifest'] and candidate['gate'] == baseline['gate']
    assert candidate['finished_at'] < baseline['started_at']
    assert baseline['candidate_report_sha256'] == digest(candidate_path)
    manifest = candidate['manifest']; frozen = manifest['fingerprint']; provider = candidate['provider']
    assert provider == baseline['provider'] == manifest['provider']
    params = ['44', '65', '87'] if provider == 'noble' else [f'SLH-DSA-SHA2-{n}{s}' for n in (128, 192, 256) for s in ('f', 's')] + ['SLH-DSA-SHAKE-128f']
    assert manifest['params'] == params and candidate['gate']['fingerprint'] == frozen
    assert candidate['gate']['matched_keys'] == len(params) * 10
    assert candidate['gate']['matched_operation_results'] == len(params) * 30
    assert candidate['gate']['final_corpus_never_executed']
    for name, expected in frozen['inputs'].items():
        assert digest(ROOT / name) == expected, name
    for kind in ('smoke', 'final'):
        assert digest(manifest['corpora'][kind]) == frozen['corpora'][kind]
    smoke_corpus = json.loads(Path(manifest['corpora']['smoke']).read_text())
    final_corpus = json.loads(Path(manifest['corpora']['final']).read_text())
    corpus_seeds = lambda c: {row['seed'] for groups in c['parameters'].values() for rows in groups.values() for row in rows}
    assert corpus_seeds(smoke_corpus).isdisjoint(corpus_seeds(final_corpus))
    source_checks = {}
    if provider == 'noble':
        prior = frozen['prior']
        assert prior == manifest['prior_provenance']
        assert digest(prior['node_path']) == frozen['node_sha256'] == prior['node_sha256']
        for variant, directory in manifest['variants'].items():
            package = Path(directory)
            assert digest(package / 'ml-dsa.js') == prior['source_js'][variant]
            assert tree(package.parents[2]) == prior['sources'][variant]
            source_checks[variant] = prior['source_js'][variant]
        old_gate = ROOT / f"results/noble/experiments/robustness/gate-0.7.1-{prior['node_sha256'][:12]}.json"
    else:
        for variant, directory in manifest['variants'].items():
            directory = Path(directory)
            assert tree(directory, go=True)['sha256'] == frozen['sources'][variant]
            assert digest(directory / 'tenkeys') == frozen['binaries'][variant]
            assert digest(directory / 'cmd/tenkeys/main.go') == frozen['inputs']['libs/circl/experiments/tenkeys/main.go']
            assert digest(directory / 'sign/slhdsa/state.go') == manifest['prior_provenance']['sources'][variant]
            source_checks[variant] = frozen['binaries'][variant]
        old_gate = ROOT / 'docs/performance/circl/evidence/validated-gate.json'
    assert len(set(source_checks.values())) == 2
    assert encoded_hash(json.loads(old_gate.read_text())) == manifest['prior_gate_sha256']
    corpora = []
    for path, report in [(candidate_path, candidate), (baseline_path, baseline)]:
        raw = Path(str(path) + '.raw'); corpus = json.loads((raw / 'corpus.json').read_text()); corpora.append(corpus)
        assert digest(raw / 'corpus.json') == frozen['corpora']['final']
        assert set(report['outputs']) == set(params)
        seeds = set()
        for param in params:
            output = report['outputs'][param]
            assert json.loads((raw / f'{param}.json').read_text()) == output
            assert output['param'] == param and output['corpus_id'] == corpus['id']
            assert output['measured_calls'] == {op: 10 for op in OPS}
            assert output['warmup_keys'] == 4 and output['warmup_cycles'] == manifest['warmup_cycles']
            assert len(output['rows']) == 10 and len({r['public_key'] for r in output['rows']}) == 10
            assert len(corpus['parameters'][param]['warmup']) == 4
            assert len(corpus['parameters'][param]['measured']) == 10
            for group in ('warmup', 'measured'):
                for c in corpus['parameters'][param][group]:
                    assert c['seed'] not in seeds
                    seeds.add(c['seed'])
            for row, c in zip(output['rows'], corpus['parameters'][param]['measured']):
                assert row['index'] == c['index'] and row['seed'] == c['seed']
                assert row['valid'] and row['tamper_rejected'] and row['inputs_preserved']
                for op in OPS:
                    assert row['timing'][op]['wall_ns'] > 0 and row['timing'][op]['cpu_ns'] >= 0
        assert len(seeds) == len(params) * 14
    assert corpora[0] == corpora[1]
    assert corpora[0]['id'] != candidate['gate']['smoke_corpus_id']
    comparisons = []
    for param in params:
        for a, b in zip(candidate['outputs'][param]['rows'], baseline['outputs'][param]['rows']):
            for key in ('index', 'seed', 'public_key', 'secret_key', 'signature', 'valid', 'tamper_rejected', 'inputs_preserved'):
                assert a[key] == b[key]
            for op in OPS:
                comparisons.append({'param': param, 'index': a['index'], 'op': op, 'candidate': a['timing'][op],
                                    'baseline': b['timing'][op], 'speedup': b['timing'][op]['wall_ns'] / a['timing'][op]['wall_ns']})
    assert comparisons == baseline['comparisons']
    summaries, cpu_ratios = [], []
    for param in params:
        for op in OPS:
            selected = [r for r in comparisons if r['param'] == param and r['op'] == op]
            ratios = [r['speedup'] for r in selected]
            totals = {v: {clock: sum(r[v][clock] for r in selected) for clock in ('wall_ns', 'cpu_ns')} for v in ('candidate', 'baseline')}
            summaries.append({'param': param, 'op': op, 'keys': 10,
                              'total_wall_speedup': totals['baseline']['wall_ns'] / totals['candidate']['wall_ns'],
                              'totals': totals, 'per_key_speedups': ratios, 'median_per_key_speedup': statistics.median(ratios),
                              'minimum_per_key_speedup': min(ratios), 'maximum_per_key_speedup': max(ratios),
                              'slower_keys': sum(r < 1 for r in ratios)})
            cpu_ratios.append({'param': param, 'op': op, 'total_cpu_speedup': totals['baseline']['cpu_ns'] / totals['candidate']['cpu_ns']})
    assert summaries == baseline['summary']
    return {'schema': 'fresh-ten-key-independent-check-v1', 'provider': provider,
            'candidate_report_sha256': digest(candidate_path), 'baseline_report_sha256': digest(baseline_path),
            'candidate_finished_at': candidate['finished_at'], 'baseline_started_at': baseline['started_at'],
            'local_candidate_finished_before_baseline': True, 'global_order_proof': 'recorded separately by the six-provider coordinator',
            'exact_key_signature_matches': len(params) * 10, 'per_key_operation_pairs': len(comparisons),
            'raw_parameter_outputs_checked': len(params) * 2, 'source_binary_and_corpus_bindings_checked': True,
            'smoke_and_measurement_seeds_disjoint': True,
            'summaries': summaries, 'cpu_ratios': cpu_ratios}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: audit-tenkeys.py CANDIDATE.json BASELINE.json')
    print(json.dumps(audit(Path(sys.argv[1]), Path(sys.argv[2])), indent=2))
