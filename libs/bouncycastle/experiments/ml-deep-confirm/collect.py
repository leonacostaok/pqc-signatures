#!/usr/bin/env python3
"""Fixed, predeclared resource confirmation using the sealed screen collector."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

if sys.flags.optimize:
    raise RuntimeError('Run without Python optimization')

HERE = Path(__file__).resolve().parent
FROZEN = HERE.with_name('ml-deep')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text())
    assert manifest['measurement_variants'] == ['baseline', 'combined']
    assert manifest['measurement_rounds'] == 6
    protocol = Path(manifest['measurement_protocol']['path'])
    assert hashlib.sha256(protocol.read_bytes()).hexdigest() == manifest['measurement_protocol']['sha256']
    declared = json.loads(protocol.read_text())
    assert declared['variants'] == manifest['measurement_variants'] and declared['rounds'] == 6
    sys.path.insert(0, str(FROZEN))
    spec = importlib.util.spec_from_file_location('sealed_ml_collector', FROZEN / 'collect.py')
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    collector.VARIANTS = manifest['measurement_variants']
    sys.argv = [str(Path(__file__)), '--manifest', args.manifest, '--out', args.out, '--rounds', '6']
    collector.main()
    out = Path(args.out)
    assert json.loads((out / 'plan.json').read_text()) == declared['jobs']
    original = (out / 'execution.json').read_bytes()
    with (out / 'collector-execution.json').open('xb') as f:
        f.write(original)
    execution = json.loads(original)
    assert len(execution['runs']) == 72 and execution.get('completed_at')
    execution['measurement_variants'] = manifest['measurement_variants']
    execution['measurement_protocol_sha256'] = manifest['measurement_protocol']['sha256']
    execution['collector_execution_sha256'] = hashlib.sha256(original).hexdigest()
    (out / 'execution.json').write_text(json.dumps(execution, indent=2) + '\n')

if __name__ == '__main__':
    main()
