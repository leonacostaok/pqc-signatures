#!/usr/bin/env python3
"""Prepare/check fresh ten-key workers; collect candidate then baseline separately."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PROVIDER = HERE.parents[1].name
BUILD = ROOT / 'libs' / PROVIDER / 'build/tenkeys'
NODE = Path('/Users/dandelionlabs/.nvm/versions/node/v22.23.2/bin/node')
ENV = dict(os.environ, NODE_OPTIONS='', GOMAXPROCS='1', GOTOOLCHAIN='local')
OPS = ('keygen', 'sign', 'verify')
PARAMS = ['44', '65', '87'] if PROVIDER == 'noble' else [f'SLH-DSA-SHA2-{n}{s}' for n in (128, 192, 256) for s in ('f', 's')] + ['SLH-DSA-SHAKE-128f']
WARMUP = 16 if PROVIDER == 'noble' else 1


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(args, cwd=None):
    return subprocess.check_output([str(v) for v in args], cwd=cwd, env=ENV, text=True)


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False) as f:
        json.dump(value, f, indent=2); f.write('\n'); temporary = Path(f.name)
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink()


def inputs():
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(HERE.iterdir()) if p.suffix in ('.py', '.mjs', '.go')}


def prior():
    path = HERE.parent / ('robustness' if PROVIDER == 'noble' else 'sha2-prefix') / 'run.py'
    spec = importlib.util.spec_from_file_location('prior', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def source_tree(path):
    selected = {str(p.relative_to(path)): sha(p) for p in sorted(path.rglob('*')) if p.is_file()
                and (p.suffix in ('.go', '.s', '.c', '.h') or p.name in ('go.mod', 'go.sum'))}
    return hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()


def derive(label, size):
    result = b''; counter = 0
    while len(result) < size:
        result += hashlib.sha256(f'fresh-ten-key-v1/{PROVIDER}/{label}/{counter}'.encode()).digest(); counter += 1
    return result[:size].hex()


def corpus(kind):
    data = {'schema': 'fresh-ten-key-inputs-v1', 'id': f'{PROVIDER}-tenkeys-20261012-{kind}-v1', 'parameters': {}}
    all_seeds = set()
    for param in PARAMS:
        size = 32 if PROVIDER == 'noble' else 3 * int(param.split('-')[-1][:-1]) // 8
        groups = {}
        for group, count in [('warmup', 4), ('measured', 10)]:
            rows = []
            for index in range(count):
                label = f'{data["id"]}/{param}/{group}/{index}'
                seed = derive(label + '/seed', size)
                require(seed not in all_seeds, 'duplicate seed'); all_seeds.add(seed)
                rows.append({'index': index, 'seed': seed, 'message': derive(label + '/message', (0, 64, 1024, 4096)[index % 4]),
                             'context': derive(label + '/context', (0, 31, 255)[index % 3])})
            groups[group] = rows
        data['parameters'][param] = groups
    return data


def fingerprint(manifest):
    result = {'inputs': inputs(), 'corpora': {kind: sha(manifest['corpora'][kind]) for kind in ('smoke', 'final')}}
    if PROVIDER == 'noble':
        result['prior'] = prior().provenance(NODE, '0.7.1')
        result['node_sha256'] = sha(NODE)
    else:
        result['sources'] = {v: source_tree(Path(path)) for v, path in manifest['variants'].items()}
        result['binaries'] = {v: sha(Path(path) / 'tenkeys') for v, path in manifest['variants'].items()}
        require(len(set(result['binaries'].values())) == 2, 'identical candidate and baseline binaries')
    return result


def prepare():
    old = prior()
    if PROVIDER == 'noble':
        provenance = old.provenance(NODE, '0.7.1')
        gate = json.loads(old.gate_path(NODE, '0.7.1').read_text())
        variants = {v: str(p) for v, p in old.locations(provenance).items()}
    else:
        originals = old.layout(); provenance = old.provenance(originals)
        gate = json.loads((old.BUILD / 'gate.json').read_text())
        variants = {}
    require(gate['provenance'] == provenance, 'prior production gate is stale')
    identity = hashlib.sha256(json.dumps({'inputs': inputs(), 'prior': provenance}, sort_keys=True).encode()).hexdigest()[:16]
    dest = BUILD / identity; dest.mkdir()
    if PROVIDER == 'circl':
        for variant, original in originals.items():
            copy = dest / variant
            shutil.copytree(original, copy)
            require(source_tree(copy) == source_tree(original), 'copied source changed')
            driver = copy / 'cmd/tenkeys'; driver.mkdir()
            shutil.copyfile(HERE / 'main.go', driver / 'main.go')
            execute(['go', 'build', '-trimpath', '-pgo=off', '-buildvcs=false', '-o', copy / 'tenkeys', './cmd/tenkeys'], cwd=copy)
            variants[variant] = str(copy)
    paths = {}
    for kind in ('smoke', 'final'):
        path = dest / f'{kind}-corpus.json'; atomic(path, corpus(kind)); paths[kind] = str(path)
    manifest = {'schema': 'fresh-ten-key-manifest-v1', 'provider': PROVIDER, 'snapshot': identity, 'variants': variants,
                'corpora': paths, 'prior_provenance': provenance, 'prior_gate_sha256': hashlib.sha256(json.dumps(gate, sort_keys=True).encode()).hexdigest(),
                'warmup_cycles': WARMUP, 'params': PARAMS}
    manifest['fingerprint'] = fingerprint(manifest)
    atomic(dest / 'manifest.json', manifest)
    (BUILD / 'prepared.json').write_text(json.dumps({'manifest': str(dest / 'manifest.json')}) + '\n')
    print(json.dumps({'prepared': identity, 'params': PARAMS, 'warmup_cycles': WARMUP}))


def prepared():
    pointer = json.loads((BUILD / 'prepared.json').read_text()); path = Path(pointer['manifest'])
    manifest = json.loads(path.read_text())
    require(manifest['fingerprint'] == fingerprint(manifest), 'source, runtime, corpus or driver changed')
    return manifest, path.parent


def worker(manifest, variant, param, kind):
    if PROVIDER == 'noble':
        args = {'module': str(Path(manifest['variants'][variant]) / 'ml-dsa.js'), 'corpus': manifest['corpora'][kind],
                'param': param, 'warmupCycles': manifest['warmup_cycles']}
        return json.loads(execute([NODE, HERE / 'worker.mjs', json.dumps(args)]))
    return json.loads(execute([Path(manifest['variants'][variant]) / 'tenkeys', '-corpus', manifest['corpora'][kind],
                              '-param', param, '-warmup-cycles', str(manifest['warmup_cycles'])]))


def validate(result, param, corpus_data):
    expected = corpus_data['parameters'][param]['measured']
    require(result['param'] == param and result['corpus_id'] == corpus_data['id'], 'wrong parameter or corpus')
    require(result['measured_calls'] == {op: 10 for op in OPS} and len(result['rows']) == 10, 'wrong measured call count')
    require(result['warmup_keys'] == 4 and result['warmup_cycles'] == WARMUP, 'wrong warmup')
    require(len({x['public_key'] for x in result['rows']}) == 10, 'public keys are not distinct')
    for row, case in zip(result['rows'], expected):
        require(row['index'] == case['index'] and row['seed'] == case['seed'], 'wrong input case')
        require(row['valid'] and row['tamper_rejected'] and row['inputs_preserved'], 'correctness failure')
        for key in ('public_key', 'secret_key', 'signature'):
            require(len(bytes.fromhex(row[key])) > 0, 'missing output bytes')
        for op in OPS:
            require(math.isfinite(row['timing'][op]['wall_ns']) and row['timing'][op]['wall_ns'] > 0, 'invalid wall clock')
            require(row['timing'][op]['cpu_ns'] >= 0, 'invalid CPU clock')


def compare(candidate, baseline):
    require(set(candidate) == set(baseline) == set(PARAMS), 'incomplete parameter matrix')
    rows = []
    for param in PARAMS:
        for a, b in zip(candidate[param]['rows'], baseline[param]['rows']):
            for key in ('index', 'seed', 'public_key', 'secret_key', 'signature', 'valid', 'tamper_rejected', 'inputs_preserved'):
                require(a[key] == b[key], f'candidate/baseline mismatch: {param}/{key}')
            for op in OPS:
                rows.append({'param': param, 'index': a['index'], 'op': op, 'candidate': a['timing'][op], 'baseline': b['timing'][op],
                             'speedup': b['timing'][op]['wall_ns'] / a['timing'][op]['wall_ns']})
    return rows


def check():
    manifest, dest = prepared(); smoke = json.loads(Path(manifest['corpora']['smoke']).read_text())
    protocol = json.loads(execute([NODE, HERE / 'worker-test.mjs'])) if PROVIDER == 'noble' else {'fresh_key_objects': 'constructed anew before each API call'}
    output = {}
    for variant in ('candidate', 'baseline'):
        output[variant] = {}
        for param in PARAMS:
            result = worker(manifest, variant, param, 'smoke'); validate(result, param, smoke)
            atomic(dest / f'smoke-{variant}-{param}.json', result); output[variant][param] = result
            print(f'Checked {PROVIDER} {variant} {param}', file=sys.stderr)
    rows = compare(output['candidate'], output['baseline'])
    require(manifest['fingerprint'] == fingerprint(manifest), 'source changed during check')
    atomic(dest / 'gate.json', {'fingerprint': manifest['fingerprint'], 'protocol': protocol, 'matched_keys': len(PARAMS) * 10,
                               'matched_operation_results': len(rows), 'smoke_corpus_id': smoke['id'], 'final_corpus_never_executed': True})
    print(json.dumps({'correctness': 'passed', 'keys': len(PARAMS) * 10, 'matched_operations': len(rows)}))


def batch(args):
    manifest, dest = prepared(); gate = json.loads((dest / 'gate.json').read_text())
    require(gate['fingerprint'] == manifest['fingerprint'], 'no gate for exact measured sources')
    out = args.out.resolve(); require(not out.exists(), 'refuse to overwrite output')
    raw = Path(str(out) + '.raw'); raw.mkdir(parents=True)
    corpus_data = json.loads(Path(manifest['corpora']['final']).read_text()); atomic(raw / 'corpus.json', corpus_data)
    candidate = None
    if args.variant == 'baseline':
        require(args.candidate is not None, 'baseline requires completed candidate output')
        candidate = json.loads(args.candidate.read_text())
        require(candidate['variant'] == 'candidate' and candidate['manifest'] == manifest, 'candidate source/corpus mismatch')
    else:
        require(args.candidate is None, 'candidate batch must run independently first')
    began = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()); outputs = {}
    for param in PARAMS:
        result = worker(manifest, args.variant, param, 'final'); atomic(raw / f'{param}.json', result)
        validate(result, param, corpus_data); outputs[param] = result
        print(f'Completed {PROVIDER} {args.variant} {param}', file=sys.stderr)
    require(manifest['fingerprint'] == fingerprint(manifest), 'source changed during timing')
    report = {'schema': 'fresh-ten-key-batch-v1', 'provider': PROVIDER, 'variant': args.variant,
              'started_at': began, 'finished_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'manifest': manifest, 'gate': gate, 'outputs': outputs}
    if candidate is not None:
        rows = compare(candidate['outputs'], outputs)
        report['candidate_report_sha256'] = sha(args.candidate); report['comparisons'] = rows
        report['summary'] = []
        for param in PARAMS:
            for op in OPS:
                selected = [r for r in rows if r['param'] == param and r['op'] == op]
                ratios = [r['speedup'] for r in selected]
                totals = {v: {clock: sum(r[v][clock] for r in selected) for clock in ('wall_ns', 'cpu_ns')} for v in ('candidate', 'baseline')}
                report['summary'].append({'param': param, 'op': op, 'keys': len(selected),
                                          'total_wall_speedup': totals['baseline']['wall_ns'] / totals['candidate']['wall_ns'],
                                          'totals': totals, 'per_key_speedups': ratios,
                                          'median_per_key_speedup': statistics.median(ratios), 'minimum_per_key_speedup': min(ratios),
                                          'maximum_per_key_speedup': max(ratios), 'slower_keys': sum(r < 1 for r in ratios)})
        report['interpretation'] = 'Exactly ten new keys, one measured call per operation/key, candidate-first sensitivity check; not steady-state throughput or a general ranking.' 
    atomic(out, report); print(f'Saved {out}', file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='mode', required=True)
    commands.add_parser('prepare'); commands.add_parser('check')
    timing = commands.add_parser('batch'); timing.add_argument('--variant', choices=('candidate', 'baseline'), required=True)
    timing.add_argument('--out', type=Path, required=True); timing.add_argument('--candidate', type=Path)
    args = parser.parse_args(); BUILD.mkdir(parents=True, exist_ok=True); lock = BUILD / '.lock'; lock.mkdir()
    try:
        if args.mode == 'prepare': prepare()
        elif args.mode == 'check': check()
        else: batch(args)
    finally:
        lock.rmdir()


if __name__ == '__main__':
    main()
