#!/usr/bin/env python3
"""Generate baseline fixtures, then require exact candidate outputs before timing."""
import argparse
import hashlib
import importlib.util
import json
import pathlib

spec = importlib.util.spec_from_file_location('prefix_check', pathlib.Path(__file__).with_name('sha512-prefix-check.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--baseline', type=pathlib.Path, required=True)
    p.add_argument('--candidate', type=pathlib.Path, required=True)
    p.add_argument('--out', type=pathlib.Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    vectors = json.loads((check.ROOT / 'common/vectors.json').read_text())
    rows = []
    for param in vectors['params']:
        name = param['name']
        if not (name.startswith('SLH-DSA-SHA2-') or name == 'SLH-DSA-SHAKE-128f'):
            continue
        n = len(bytes.fromhex(param['seed_hex'])) // 3
        for sample in range(3):
            def derive(label, length):
                return hashlib.shake_256(f'openssl-prefix/{name}/{sample}/{label}'.encode()).digest(length).hex()
            case = {'param': name,
                    'seed_hex': param['seed_hex'] if sample == 0 else derive('seed', 3 * n),
                    'msg_hex': vectors['message_hex'] if sample == 0 else derive('message', [0, 0, 4096][sample]),
                    'ctx_hex': '' if sample == 0 else derive('context', [0, 255, 17][sample])}
            path = args.out / f'{name}-{sample}.txt'
            check.write_case(path, case)
            a = check.run(args.baseline, 'keygen', path)
            b = check.run(args.candidate, 'keygen', path)
            assert a['ok'] and b['ok'] and a['pk_hex'] == b['pk_hex'] and a['sk_hex'] == b['sk_hex']
            case.update(pk_hex=a['pk_hex'], sk_hex=a['sk_hex'])
            check.write_case(path, case)
            a = check.run(args.baseline, 'sign', path)
            b = check.run(args.candidate, 'sign', path)
            assert a['ok'] and b['ok'] and a['sig_hex'] == b['sig_hex']
            case['sig_hex'] = a['sig_hex']
            check.write_case(path, case)
            for binary in (args.baseline, args.candidate):
                assert check.run(binary, 'verify', path)['ok']
                mutated = dict(case)
                sig = bytearray.fromhex(case['sig_hex'])
                sig[len(sig) // 2] ^= 1
                mutated['sig_hex'] = sig.hex()
                negative = args.out / 'negative.txt'
                check.write_case(negative, mutated)
                assert not check.run(binary, 'verify', negative)['ok']
            rows.append({'file': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                         'message_bytes': len(bytes.fromhex(case['msg_hex'])),
                         'context_bytes': len(bytes.fromhex(case['ctx_hex']))})
            print(path.name, 'PASS', flush=True)
    result = {'cases': rows, 'binary_sha256': {str(b): hashlib.sha256(b.read_bytes()).hexdigest()
                                              for b in (args.baseline, args.candidate)}}
    (args.out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
