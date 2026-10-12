#!/usr/bin/env python3
"""Check saved native evidence without claiming to rerun cryptography or binaries."""
import hashlib
import json
import sys
import argparse
from pathlib import Path

if not __debug__:
    raise SystemExit('optimized Python is unsupported')
root = Path(__file__).resolve().parents[4]
parser = argparse.ArgumentParser()
parser.add_argument('--ntt-root', type=Path, default=root)
parser.add_argument('--matrix-root', type=Path, default=root)
parser.add_argument('--wots-root', type=Path, default=root)
args = parser.parse_args()
out = root / 'results/bouncycastle/alternative-comparison/native'
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
m_path = out / 'manifest.json'
m = json.loads(m_path.read_text())
assert m['pin'] == 'c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
ml_data = json.loads((out / 'test-data.json').read_text())
slh_data = json.loads((root / 'results/bouncycastle/experiments/upstream-test-data.json').read_text())
assert ml_data['revision'] == slh_data['revision'] == '3c385e9f4c0b12ce5a86d2b29a17fb3b68dd4e1a'
expected = {'ntt': ['baseline', 'fused', 'companion', 'both'], 'matrix': ['baseline', 'lazy', 'stream', 'combined'], 'wots': ['baseline', 'object_hoist', 'field_rewrite', 'two_addresses', 'buffer', 'buffer_peeled']}
plans = {
    'ntt': args.ntt_root / 'results/bouncycastle/ntt-alternatives/prepared-v1/manifest.json',
    'matrix': args.matrix_root / 'results/bouncycastle/matrix-alternatives/prepared.json',
    'wots': args.wots_root / 'results/bouncycastle/wots-alternatives/manifest.json',
}
prepared = {k: json.loads(p.read_text()) for k, p in plans.items()}
bindings = json.loads((out / 'experiment-bindings.json').read_text())
assert all(sha(path) == bindings[group]['sha256'] for group, path in plans.items())
checked = []
for group, variants in expected.items():
    for variant in variants:
        label = group + '-' + variant
        record = json.loads((out / (label + '.json')).read_text())
        log = (out / (label + '.txt')).read_text()
        assert record['returncode'] == 0
        classes = prepared[group]['class_hashes'][variant] if group == 'wots' else prepared[group]['variants'][variant]['class_hashes' if group == 'ntt' else 'binaries']
        assert record['class_hashes'] == classes, 'native-tested binaries differ from experiment preparation'
        assert record['manifest_sha256'] == sha(m_path)
        assert record['output_sha256'] == sha(out / (label + '.txt'))
        assert record['runner_sha256'] == sha(Path(__file__).with_name('run_native.py'))
        assert record['driver_source_sha256'] == sha(Path(__file__).with_name('NativeMethods.java'))
        assert record['start'] <= record['end']
        assert '-Dtest.full=true' in record['command']
        methods = 4 if group == 'wots' else 17
        assert log.rstrip().endswith('PASS native methods=' + str(methods))
        lines = [line for line in log.splitlines() if line.startswith('TEST ')]
        assert len(lines) == (4 if group == 'wots' else 2)
        assert all('ignored=0 failures=0' in line for line in lines)
        data = slh_data if group == 'wots' else ml_data
        assert record['test_data_hashes'] == {f['path']: f['sha256'] for f in data['files']}
        origins = [line for line in log.splitlines() if line.startswith('ORIGIN ')]
        assert len(origins) == (3 if group == 'wots' else 4)
        checked.append({'label': label, 'native_methods': methods, 'record_sha256': sha(out / (label + '.json'))})
print(json.dumps({'passed': True, 'variants': checked, 'scope': 'Saved native test evidence and pinned vector identities; no local binary or cryptographic rerun.'}, indent=2))
