#!/usr/bin/env python3
"""Regression checks: missing correctness evidence must fail before timing."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
BUILD = HERE.parent / 'build' / 'sha512-prefix'
spec = importlib.util.spec_from_file_location('gate_check', HERE / 'sha512-prefix-check.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
passed = []

with tempfile.TemporaryDirectory(dir=BUILD, prefix='gate-regression-') as temporary:
    root = Path(temporary)
    check.ROOT = root
    suite = root / 'common/validation/validation.json.gz'
    suite.parent.mkdir(parents=True)
    original_argv = sys.argv
    try:
        for name, cases in [('empty', []), ('duplicates', [{'id': 'duplicate', 'param': 'SLH-DSA-SHA2-128f'}] * 216)]:
            with gzip.open(suite, 'wt') as f:
                json.dump({'cases': cases}, f)
            sys.argv = ['check', str(root / 'never-run'), str(root / 'never-written.json'), '--work', str(root / 'work')]
            try:
                check.main()
            except RuntimeError as error:
                if '216 unique' not in str(error):
                    raise
            else:
                raise AssertionError(f'{name} validation was accepted')
            passed.append(f'reject-{name}-suite')
    finally:
        sys.argv = original_argv
    identities = {}
    for variant in ('baseline', 'candidate'):
        path = root / variant
        path.write_text(variant)
        identities[variant] = {'prefix-driver': hashlib.sha256(path.read_bytes()).hexdigest()}
    for name, proof, expected in [
        ('incomplete', {'complete': False}, 'Missing complete correctness gates'),
        ('empty', {'complete': True, 'identities': identities, 'results': {
            'baseline': {'resource': {'hash_cases': 768, 'redundant_prefix_bytes': 65536},
                         'validation': {'complete': True, 'binary_sha256': identities['baseline']['prefix-driver'],
                                        'cases': [], 'reference_corpus': []}}}}, 'Incomplete baseline correctness evidence'),
    ]:
        gate = root / f'{name}.json'
        gate.write_text(json.dumps(proof))
        result = subprocess.run([sys.executable, str(HERE / 'sha512-prefix-bench.py'),
            '--baseline', str(root / 'baseline'), '--candidate', str(root / 'candidate'),
            '--corpus', str(root / 'no-corpus'), '--gate', str(gate), '--out', str(root / 'never-measured.json'),
            '--exclusive-window-granted'], capture_output=True, text=True)
        if result.returncode == 0 or expected not in result.stderr:
            raise AssertionError(f'{name} gate was not rejected as expected: {result.stderr}')
        passed.append(f'reject-{name}-gate')
print(json.dumps({'passed': passed, 'timed_processes_started': 0}))
