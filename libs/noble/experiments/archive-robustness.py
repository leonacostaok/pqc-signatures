#!/usr/bin/env python3
"""Archive every retained raw file deterministically; keep original directories."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    found = {}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(), 'unexpected symlink'
        if path.is_file():
            found[str(path.relative_to(root))] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    assert found, 'empty raw directory'
    return found


def tree_hash(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def archive(report):
    raw = Path(str(report) + '.raw')
    output = Path(str(raw) + '.tar.gz')
    assert not output.exists(), f'refuse to overwrite {output}'
    original = inventory(raw)
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix=output.name + '.', delete=False) as f:
        temporary = Path(f.name)
        with gzip.GzipFile(fileobj=f, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                for name, data in original.items():
                    info = tarfile.TarInfo(raw.name + '/' + name)
                    info.size = data['bytes']
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mode = 0o644
                    with (raw / name).open('rb') as source:
                        tar.addfile(info, source)
    try:
        recovered = {}
        with tarfile.open(temporary, 'r:gz') as tar:
            for member in tar:
                assert member.isfile() and member.name.startswith(raw.name + '/')
                name = member.name[len(raw.name) + 1:]
                assert name not in recovered and not Path(name).is_absolute() and '..' not in Path(name).parts
                payload = tar.extractfile(member).read()
                recovered[name] = {'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': len(payload)}
        assert recovered == original, 'archive omitted or changed raw evidence'
        assert inventory(raw) == original, 'raw evidence changed during archiving'
        os.link(temporary, output)
    finally:
        temporary.unlink()
    return {'report': report.name, 'report_sha256': sha(report), 'archive': output.name, 'archive_sha256': sha(output),
            'raw_directory': raw.name, 'raw_files': len(original), 'raw_bytes': sum(v['bytes'] for v in original.values()),
            'content_tree_sha256': tree_hash(original), 'verified_every_file': True, 'original_directory_retained': raw.is_dir()}


if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise SystemExit('usage: archive-robustness.py MANIFEST.json REPORT.json [...]')
    manifest = Path(sys.argv[1]); assert not manifest.exists(), 'manifest must be new'
    reports = [Path(x) for x in sys.argv[2:]]
    results = [archive(path) for path in reports]
    with manifest.open('x') as f:
        json.dump({'schema': 'noble-robustness-raw-archives-v1', 'tree_hash': 'sha256 of sorted-key JSON mapping relative file names to sha256/byte-size objects',
                   'tar_metadata': 'sorted files; uid/gid/mtime zero, empty owner names, mode0644; gzip filename empty and mtime zero',
                   'archives': results}, f, indent=2)
        f.write('\n')
    print(json.dumps({'archives': len(results), 'raw_files_preserved': sum(x['raw_files'] for x in results), 'manifest': str(manifest)}))
