#!/usr/bin/env python3
"""Add a predeclared two-variant confirmation protocol to the existing source seal."""
import hashlib
import json
from pathlib import Path
import random
import sys

if sys.flags.optimize:
    raise RuntimeError('Run without Python optimization')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PREVIOUS = ROOT / 'libs/bouncycastle/build/ml-deep/prepared-v6/manifest-screen-v7.json'
OUTPUT = ROOT / 'results/bouncycastle/ml-deep/confirmation-plan'
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    assert digest(PREVIOUS) == '5ec5e4e10eba45cf77729f1960f1ea2bdd5806a58ff110ca5f6d3148fafb6bf7'
    manifest = json.loads(PREVIOUS.read_text())
    for name, expected in manifest['inputs'].items():
        assert digest(ROOT / name) == expected
    cells = [(p, o) for p in ['ml_dsa_44', 'ml_dsa_65', 'ml_dsa_87'] for o in ['sign', 'verify']]
    random.Random(384710).shuffle(cells)
    jobs = []
    for rnd in range(6):
        for index, (parameter, operation) in enumerate(cells):
            order = ['baseline', 'combined']
            random.Random(384711 + index + rnd // 2).shuffle(order)
            if rnd % 2:
                order.reverse()
            jobs.extend([rnd, parameter, operation, variant] for variant in order)
    protocol = {
        'schema': 'bc-ml-deep-confirm-protocol-v1',
        'variants': ['baseline', 'combined'], 'rounds': 6, 'fresh_jvms': 72,
        'measured_keys_per_batch': 128, 'warmup_calls_per_batch': 1000,
        'warmup_keys_per_parameter': 32, 'warmup_measurement_seed_overlap': False,
        'keydecode_included': False, 'caller_copies_included': False,
        'timed_scope': 'fresh signer/init/message update and sign or verify; same frozen MLDeep.java',
        'primary_resource': 'mean allocated bytes per call, paired identical keys and rounds',
        'primary_wall_ratio': 'sum baseline wall ns / sum combined wall ns',
        'resource_target': 'at least 20% mean allocation reduction in each parameter/operation cell',
        'latency_review_trigger': 'aggregate wall ratio below 0.97 and at least four of six round ratios below 0.97',
        'claims': 'resource confirmation only; retain every loss and round; no broad speed claim',
        'jobs': jobs,
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    protocol_path = OUTPUT / 'protocol.json'
    with protocol_path.open('x') as f:
        json.dump(protocol, f, indent=2); f.write('\n')
    manifest['measurement_variants'] = protocol['variants']
    manifest['measurement_rounds'] = 6
    manifest['measurement_protocol'] = {'path': str(protocol_path), 'sha256': digest(protocol_path)}
    manifest['confirmation_parent_manifest_sha256'] = digest(PREVIOUS)
    for path in [*sorted(HERE.glob('*.py')), protocol_path]:
        manifest['inputs'][str(path.relative_to(ROOT))] = digest(path)
    target = OUTPUT / 'manifest.json'
    with target.open('x') as f:
        json.dump(manifest, f, indent=2); f.write('\n')
    print(target)
    print(digest(target))

if __name__ == '__main__':
    main()
