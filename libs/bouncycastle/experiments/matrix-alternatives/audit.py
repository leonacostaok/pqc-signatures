#!/usr/bin/env python3
"""Check archived preparation and every raw sample; no JVM execution or regeneration."""
import sys
if sys.flags.optimize:
    raise RuntimeError('Run without Python optimization')
import argparse, datetime, hashlib, io, json, struct, tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RESULTS = ROOT / 'results/bouncycastle/matrix-alternatives'

def require(ok, why):
    if not ok:
        raise ValueError(why)

def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()

def read_json(path):
    return json.loads(path.read_text())

def tree(path, glob):
    return {str(p.relative_to(path)): digest(p) for p in sorted(path.rglob(glob)) if p.is_file()}

def fixtures(path):
    stream = io.BytesIO(path.read_bytes())
    def take(n):
        value = stream.read(n)
        require(len(value) == n, 'truncated corpus')
        return value
    def integer():
        return struct.unpack('>i', take(4))[0]
    def utf():
        n = struct.unpack('>H', take(2))[0]
        return take(n).decode('ascii')
    require(integer() == 0x4d4c4431, 'corpus magic')
    count = integer()
    require(0 < count <= 100000, 'corpus size')
    rows = []
    for _ in range(count):
        name, case = utf(), utf()
        data = []
        for _ in range(7):
            n = integer()
            require(0 <= n <= 100000, 'field size')
            data.append(take(n))
        rows.append({'parameter': name, 'case_id': case, 'data': data})
    require(stream.read() == b'', 'corpus trailing bytes')
    require(len({x['case_id'] for x in rows}) == count, 'corpus duplicate IDs')
    return rows

def preparation():
    m = read_json(RESULTS / 'prepared.json')
    require(m['upstream'] == 'c314b9cdffa3958a0eff5344f8fdcdb0181ed830', 'source pin')
    for name, h in m['inputs'].items():
        require(digest(ROOT / name) == h, 'changed preparation input: ' + name)
    archive = RESULTS / 'baseline-source.tar.gz'
    require(digest(archive) == m['source_archive_sha256'], 'upstream archive changed')
    with tarfile.open(archive) as tar:
        contents = {x.name: hash_bytes(tar.extractfile(x).read()) for x in tar.getmembers() if x.isfile() and x.name.endswith('.java')}
    require(contents == m['variants']['baseline']['source'], 'upstream archived sources mismatch')
    status = {}
    for name, v in m['variants'].items():
        for label, path_key, map_key, glob in [('classes', 'classes', 'binaries', '*.class'), ('sources', 'source_path', 'source', '*.java'), ('gate_classes', 'instrumented_gate_classes', 'instrumented_binaries', '*.class')]:
            path = Path(v[path_key])
            if not path.exists():
                status[name + '_' + label] = 'unavailable; archived hashes only, not verified locally'
            else:
                require(tree(path, glob) == v[map_key], name + ' ' + label + ' changed')
                status[name + '_' + label] = 'verified'
        require(v['gates']['correctness']['operation_checks'] == 432, 'correctness count')
        require(v['gates']['measured']['operation_checks'] == 2304, 'measured correctness count')
        require(v['gates']['malformed'] == {'cases': 72, 'checks': 936, 'ownership': True}, 'malformed gate')
        require(v['gates']['matrix']['arithmetic_coefficients'] == 18432 and v['gates']['matrix']['stream_cases'] == 6, 'matrix gate')
    for command in m['commands']:
        require(command['exit_code'] == 0, 'preparation command failed')
        require(digest(RESULTS / Path(command['log']).name) == command['log_sha256'], 'gate log changed')
    java = Path(m['java'])
    if java.exists():
        require(digest(java) == m['java_sha256'], 'runtime changed')
        status['runtime'] = 'verified'
    else:
        status['runtime'] = 'unavailable; recorded hash and version only'
    corpus = {}
    for label, c in m['corpora'].items():
        path = RESULTS / Path(c['path']).name
        require(digest(path) == c['sha256'], 'corpus changed')
        corpus[label] = fixtures(path)
    for parameter in ['ml_dsa_44', 'ml_dsa_65', 'ml_dsa_87']:
        warm = [x for x in corpus['warmup'] if x['parameter'] == parameter][:2]
        measured = [x for x in corpus['measured'] if x['parameter'] == parameter]
        require(len(warm) == 2 and len(measured) == 128, 'key counts')
        require(len({hash_bytes(x['data'][0]) for x in warm + measured}) == 130, 'seed overlap')
        require(len({hash_bytes(x['data'][4]) for x in warm + measured}) == 130, 'public key overlap')
    portable_path = RESULTS / 'portable.json'
    if portable_path.exists():
        portable = read_json(portable_path)
        for path, h in portable['files'].items():
            require(digest(RESULTS / path) == h, 'portable artifact changed: ' + path)
        with tarfile.open(RESULTS / 'selected-sources.tar.gz') as tar:
            source_files = {x.name: hash_bytes(tar.extractfile(x).read()) for x in tar.getmembers() if x.isfile()}
        require(source_files == portable['selected_sources'], 'portable selected source hashes')
        for name, v in m['variants'].items():
            for source in v['changed_files']:
                require(source_files[name + '/' + source] == v['source'][source], 'selected variant differs from sealed source')
    else:
        status['portable_selected_sources'] = 'unavailable'
    return m, corpus, status

def summarize(plan, record, corpus, prepared):
    from collect import schedule, FLAGS
    require(plan['jobs'] == schedule() and plan['jvm_flags'] == FLAGS, 'fixed plan changed')
    require(record['status'] == 'complete', 'collection incomplete; all attempted raw files remain available')
    require(record['exclusive_grant'].strip() and all(not v for v in record['environment'].values()), 'collection authorization/environment')
    require(len(record['jobs']) == len(plan['jobs']) == 288, 'collection count')
    measured = {x['case_id']: x for x in corpus['measured']}
    batches = {}
    previous_end = datetime.datetime.fromisoformat(record['started_at'])
    for expected, actual in zip(plan['jobs'], record['jobs']):
        require(all(actual[k] == v for k, v in expected.items()), 'job order changed')
        argv = [prepared['java'], *FLAGS, '-cp', prepared['variants'][actual['variant']]['classes'],
                'org.bouncycastle.crypto.signers.mldsa.MatrixBench', actual['mode'],
                prepared['corpora']['warmup']['path'], prepared['corpora']['measured']['path'],
                actual['parameter'], actual['operation'], str(actual['shuffle_seed']), actual['variant']]
        require(actual['argv'] == argv, 'recorded JVM command differs from seal')
        start, end = [datetime.datetime.fromisoformat(actual[k]) for k in ['started_at', 'completed_at']]
        require(previous_end <= start < end, 'overlapping or invalid process timestamps')
        previous_end = end
        require(actual['exit_code'] == 0, 'nonzero JVM exit')
        for side in ['stdout', 'stderr']:
            require(digest(RESULTS / 'collection' / actual[side]) == actual[side + '_sha256'], 'raw file changed')
        batch = read_json(RESULTS / 'collection' / actual['stdout'])
        # The reusable timing driver retains the NTT experiment's schema label.
        require(batch['schema'] == 'bc-ntt-batch-v1', 'batch schema')
        for key in ['mode', 'parameter', 'operation', 'variant']:
            require(batch[key] == actual[key], 'batch identity')
        require(batch['warmup_calls'] == 1000 and batch['warmup_keys'] == 2, 'warmup')
        for key in ['keydecode_included', 'keygen_encoding_included', 'caller_copies_included']:
            require(batch[key] is False, 'measurement scope')
        require(len(batch['samples']) == 128, 'sample count')
        expected_ids = {k for k, v in measured.items() if v['parameter'] == batch['parameter']}
        require({x['case_id'] for x in batch['samples']} == expected_ids, 'sample key set')
        fields = ['wall_ns', 'cpu_ns'] if batch['mode'] == 'timing' else ['allocated_bytes']
        for sample in batch['samples']:
            require(sample['checked'] is True and sample['inputs_unchanged'] is True, 'unchecked sample')
            require(set(sample) == {'case_id', 'output_sha256', 'checked', 'inputs_unchanged', *fields}, 'counter mode contamination')
            data = measured[sample['case_id']]['data']
            output = data[4] + data[5] if batch['operation'] == 'keygen' else data[6] if batch['operation'] == 'sign' else b'\x01'
            require(sample['output_sha256'] == hash_bytes(output), 'output mismatch')
            require(all(isinstance(sample[f], int) and sample[f] > 0 for f in fields), 'counter invalid')
        key = (batch['mode'], batch['parameter'], batch['operation'], batch['variant'], actual['round'])
        require(key not in batches, 'duplicate batch')
        batches[key] = batch['samples']
    comparisons = []
    for parameter in ['ml_dsa_44', 'ml_dsa_65', 'ml_dsa_87']:
        for operation in ['keygen', 'sign', 'verify']:
            for variant in ['lazy', 'stream', 'combined']:
                comparison = {'parameter': parameter, 'operation': operation, 'variant': variant, 'metrics': {}}
                for mode, fields in [('timing', ['wall_ns', 'cpu_ns']), ('allocation', ['allocated_bytes'])]:
                    for field in fields:
                        base_total = changed_total = losses = ties = 0
                        rounds = []
                        for round_number in range(4):
                            base = batches[mode, parameter, operation, 'baseline', round_number]
                            changed = batches[mode, parameter, operation, variant, round_number]
                            require([x['case_id'] for x in base] == [x['case_id'] for x in changed], 'paired order differs')
                            b, c = sum(x[field] for x in base), sum(x[field] for x in changed)
                            base_total += b
                            changed_total += c
                            losses += sum(y[field] > x[field] for x, y in zip(base, changed))
                            ties += sum(y[field] == x[field] for x, y in zip(base, changed))
                            rounds.append({'round': round_number, 'baseline_total': b, 'variant_total': c, 'ratio': b / c})
                        comparison['metrics'][field] = {'ratio': base_total / changed_total,
                            'baseline_per_call': base_total / 512, 'variant_per_call': changed_total / 512,
                            'losing_rounds': sum(x['ratio'] < 1 for x in rounds), 'losing_keys': losses,
                            'tied_keys': ties, 'paired_keys': 512, 'rounds': rounds}
                comparisons.append(comparison)
    return comparisons

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preparation-only', action='store_true')
    parser.add_argument('--output', type=Path)
    a = parser.parse_args()
    m, corpus, status = preparation()
    result = {'schema': 'bc-matrix-audit-v1', 'local_evidence': status, 'preparation_passed': True}
    if not a.preparation_only:
        plan = read_json(RESULTS / 'plan.json')
        require(digest(RESULTS / 'prepared.json') == plan['prepared_sha256'], 'preparation seal')
        require(digest(HERE / 'collect.py') == plan['runner_sha256'], 'runner seal')
        require(digest(__file__) == plan['audit_sha256'], 'audit seal')
        record = read_json(RESULTS / 'collection/collection.json')
        require(digest(RESULTS / 'plan.json') == record['plan_sha256'], 'plan seal')
        require((RESULTS / 'portable.json').exists(), 'portable source evidence unavailable')
        result['comparisons'] = summarize(plan, record, corpus, m)
        result['batches'] = 288
        result['measured_calls'] = 36864
    if a.output:
        a.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'preparation_passed': True, 'comparisons': len(result.get('comparisons', [])), 'local_evidence': status}))

if __name__ == '__main__':
    main()
