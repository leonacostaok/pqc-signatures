#!/usr/bin/env python3
"""Execute complete correctness gates and bind them to the timed binaries."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--build', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    if args.out.exists():
        p.error('Use a new evidence path')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    evidence = args.out.with_suffix('.evidence')
    evidence.mkdir()
    identities, results = {}, {}
    for variant in ('baseline', 'candidate'):
        directory = args.build.resolve() / variant
        identities[variant] = {name: sha(directory / name) for name in ('prefix-driver', 'prefix-check', 'libcrypto.a')}
        resource = subprocess.run([str(directory / 'prefix-check'), '--require-cache'], capture_output=True, text=True)
        (evidence / f'{variant}-resource.txt').write_text(resource.stdout + resource.stderr)
        expected = {'hash_cases': 768, 'redundant_prefix_bytes': 65536 if variant == 'baseline' else 0}
        if resource.returncode != (1 if variant == 'baseline' else 0) or json.loads(resource.stdout) != expected:
            raise RuntimeError(f'{variant} resource gate failed')
        validation = evidence / f'{variant}-validation.json'
        with (evidence / f'{variant}-validation.txt').open('w') as log:
            subprocess.run([sys.executable, str(HERE / 'sha512-prefix-check.py'), str(directory / 'prefix-driver'),
                            str(validation), '--work', str(args.build / f'final-{variant}-corpus')],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        check = json.loads(validation.read_text())
        if not check['complete'] or len(check['cases']) != 216 or not all(row['pass'] is True for row in check['cases']):
            raise RuntimeError(f'{variant} validation incomplete')
        if check['binary_sha256'] != identities[variant]['prefix-driver'] or len(check['reference_corpus']) != 6:
            raise RuntimeError(f'{variant} validation identity mismatch')
        for name, digest in identities[variant].items():
            if sha(directory / name) != digest:
                raise RuntimeError(f'{variant} build changed during validation')
        results[variant] = {'resource': expected, 'validation': check}
    if identities['baseline']['prefix-driver'] == identities['candidate']['prefix-driver']:
        raise RuntimeError('Identical measured binaries')
    args.out.write_text(json.dumps({'complete': True, 'identities': identities, 'results': results}, indent=2) + '\n')


if __name__ == '__main__':
    main()
