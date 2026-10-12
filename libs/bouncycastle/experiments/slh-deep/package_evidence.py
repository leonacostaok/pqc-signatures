#!/usr/bin/env python3
"""Archive exact completed evidence bytes without altering local originals."""
import argparse
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    manifest = Path(args.manifest).resolve()
    prepared = json.loads(manifest.read_text())
    result_dir = root / 'results/bouncycastle/slh-deep'
    archive = Path(args.out).resolve()
    inventory = archive.with_name(archive.name + '.inventory.json')
    if archive.exists() or inventory.exists():
        raise ValueError('refusing to overwrite an artifact')
    members = set()
    for name in ['pilot-totals', 'pilot-stages', 'pilot-allocation']:
        result = result_dir / (name + '.json')
        if not result.is_file():
            raise ValueError('all three completed results are required')
        members.add(result)
        raw = result_dir / (name + '.json.raw')
        members.update(path for path in raw.rglob('*') if path.is_file())
    members.update(path for path in (result_dir / manifest.parent.name).rglob('*') if path.is_file())
    members.update(result_dir.glob('prepared-*-interrupted.json'))
    for name in ['manifest.json', 'fixtures.tsv', 'baseline-source.tar']:
        members.add(manifest.parent / name)
    members.update((manifest.parent / 'native-tests').glob('*.java'))
    for field, suffix in [('classes', '.class'), ('drivers', '.class'), ('tests', '.class'), ('sources', '.java')]:
        for directory in prepared[field].values():
            members.update(Path(directory).rglob('*' + suffix))
    entries = []
    with archive.open('xb') as raw_output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw_output, mtime=0, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as packed:
                for path in sorted(members):
                    if path.is_symlink() or not path.is_file():
                        raise ValueError('only regular evidence files are accepted')
                    name = str(path.relative_to(root))
                    data = path.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = 0
                    packed.addfile(info, io.BytesIO(data))
                    entries.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    document = {'schema': 'bc-slh-deep-archive-v1', 'archive': archive.name,
                'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                'archive_bytes': archive.stat().st_size, 'uncompressed_bytes': sum(item['bytes'] for item in entries),
                'original_root': str(root), 'members': entries,
                'packaging': 'Sorted paths; unchanged file bytes; tar metadata normalized; gzip mtime zero. Local originals remain intact.',
                'external_requirements': 'The exact JDK runtime and upstream/dependency repositories remain external. Prepared Java source trees, source tar and compiled implementation/driver/test classes are included.'}
    with inventory.open('x') as stream:
        json.dump(document, stream, indent=2)
        stream.write('\n')
    print(archive)
    print(inventory)


if __name__ == '__main__':
    main()
