#!/usr/bin/env python3
"""Run shared SHA2-SLH vectors through an ordinary public-EVP driver."""
import argparse
import gzip
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
PARAMS = {f'SLH-DSA-SHA2-{level}{size}' for level in (128, 192, 256) for size in ('s', 'f')}


def write_case(path, case):
    fields = [case['param']] + [case.get(k, '') for k in
        ('seed_hex', 'sk_hex', 'pk_hex', 'msg_hex', 'ctx_hex', 'sig_hex')]
    path.write_text('\n'.join(fields) + '\n')


def run(binary, op, path):
    p = subprocess.run([str(binary), op, str(path)], check=True,
                       capture_output=True, text=True)
    return json.loads(p.stdout)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('binary', type=pathlib.Path)
    p.add_argument('output', type=pathlib.Path)
    p.add_argument('--work', required=True, type=pathlib.Path)
    args = p.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    with gzip.open(ROOT / 'common/validation/validation.json.gz') as f:
        cases = json.load(f)['cases']
    selected = [c for c in cases if c['param'] in PARAMS]
    if len(selected) != 216 or len({c['id'] for c in selected}) != 216 or {c['param'] for c in selected} != PARAMS:
        raise RuntimeError('Expected 216 unique shared cases across all six SHA2 parameter sets')
    rows = []
    for c in selected:
        path = args.work / 'case.txt'
        write_case(path, c)
        op = {'siggen': 'sign', 'sigver': 'verify', 'keygen': 'keygen'}[c['kind']]
        got = run(args.binary, op, path)
        if op == 'keygen':
            passed = got['ok'] and got['pk_hex'] == c['expect_pk_hex'] and got['sk_hex'] == c['expect_sk_hex']
        elif op == 'sign':
            passed = got['ok'] and got['sig_hex'] == c['expect_sig_hex']
        else:
            passed = got['ok'] == c['expect']
        rows.append({'id': c['id'], 'pass': passed})
        if not passed:
            raise AssertionError(f"Failed {c['id']}")
        print(c['id'], 'PASS', flush=True)
    vectors = json.loads((ROOT / 'common/vectors.json').read_text())
    reference = json.loads((ROOT / 'common/reference.json').read_text())
    selected_params = [p for p in vectors['params'] if p['name'] in PARAMS]
    if len(selected_params) != 6 or {p['name'] for p in selected_params} != PARAMS:
        raise RuntimeError('Expected all six unique SHA2 reference parameter sets')
    corpus = []
    for param in selected_params:
        c = dict(param, param=param['name'], msg_hex=vectors['message_hex'], ctx_hex=vectors['context_hex'])
        path = args.work / (c['param'] + '.txt')
        write_case(path, c)
        key = run(args.binary, 'keygen', path)
        assert key['ok']
        c.update(sk_hex=key['sk_hex'], pk_hex=key['pk_hex'])
        write_case(path, c)
        sig = run(args.binary, 'sign', path)
        assert sig['ok']
        c['sig_hex'] = sig['sig_hex']
        write_case(path, c)
        assert run(args.binary, 'verify', path)['ok']
        for field in ('pk', 'sk', 'sig'):
            digest = hashlib.sha256(bytes.fromhex(c[field + '_hex'])).hexdigest()
            assert digest == reference[c['param']][field + '_sha256']
        corpus.append({'param': c['param'], 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    result = {'complete': True, 'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'validation_sha256': hashlib.sha256((ROOT / 'common/validation/validation.json.gz').read_bytes()).hexdigest(),
              'cases': rows, 'reference_corpus': corpus}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
