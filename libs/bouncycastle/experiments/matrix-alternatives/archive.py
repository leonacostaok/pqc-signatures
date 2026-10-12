#!/usr/bin/env python3
"""Archive portable selected sources and bind the existing evidence files."""
import sys
if sys.flags.optimize:
    raise RuntimeError('Run without Python optimization')
import gzip, hashlib, io, json, tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RESULTS = ROOT / 'results/bouncycastle/matrix-alternatives'

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    manifest = RESULTS / 'portable.json'
    if manifest.exists():
        raise ValueError('portable evidence already archived')
    prepared = json.loads((RESULTS / 'prepared.json').read_text())
    selected = {}
    package = 'core/src/main/java/org/bouncycastle/crypto/signers/mldsa/'
    for name, variant in prepared['variants'].items():
        files = variant['changed_files'] if name != 'baseline' else [package + f for f in ['MLDSAEngine.java', 'Poly.java', 'PolyVec.java', 'PolyVecMatrix.java', 'Reduce.java', 'Ntt.java', 'Symmetric.java', 'Packing.java']]
        for file in files:
            path = Path(variant['source_path']) / file
            if digest(path) != variant['source'][file]:
                raise ValueError('source changed: ' + str(path))
            selected[name + '/' + file] = path.read_bytes()
    for path in sorted(HERE.glob('*')):
        if path.is_file() and path.suffix in ['.py', '.java']:
            selected['experiment/' + path.name] = path.read_bytes()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, data in sorted(selected.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            member.mtime = 0
            archive.addfile(member, io.BytesIO(data))
    (RESULTS / 'selected-sources.tar.gz').write_bytes(gzip.compress(buffer.getvalue(), mtime=0))
    result = {'schema': 'bc-matrix-portable-v1',
              'selected_sources': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(selected.items())},
              'files': {p.name: digest(p) for p in sorted(RESULTS.iterdir()) if p.is_file() and p != manifest},
              'not_redistributed': ['JDK runtime binaries', 'compiled local class trees'],
              'fixture_warning': 'Public synthetic deterministic test keys only; never use them as real keys.'}
    manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'manifest': str(manifest), 'sha256': digest(manifest), 'selected_source_files': len(selected)}))

if __name__ == '__main__':
    main()
