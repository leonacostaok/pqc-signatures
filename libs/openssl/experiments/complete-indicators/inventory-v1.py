#!/usr/bin/env python3
"""Archive hash-bound text inputs; list compiled artifacts unavailable to fresh readers."""
import argparse, hashlib, json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--provider',choices=['liboqs','openssl'],required=True);a=p.parse_args()
    base=ROOT/'results'/a.provider/'complete-indicators';ready=base/'ready.json';j=json.loads(ready.read_text())
    out=base/'artifact-inventory.json';
    if out.exists():raise ValueError('inventory already exists')
    archive=base/'source-snapshot';archive.mkdir(exist_ok=False);entries=[]
    for original,digest in j['sha256'].items():
        path=Path(original)
        if sha(path)!=digest:raise ValueError('changed sealed artifact: '+original)
        relative=None
        try:
            candidate=path.relative_to(ROOT)
            if not any(part in ['build','deps'] for part in candidate.parts):relative=candidate
        except ValueError:pass
        kind='repository artifact'
        if relative is None and path.suffix in ['.c','.h','.json','.txt','.py','.md','.cmake','.log']:
            copy=archive/(digest+path.suffix)
            if not copy.exists():copy.write_bytes(path.read_bytes())
            relative=copy.relative_to(ROOT);kind='archived source/configuration'
        entries.append(dict(original_path=original,sha256=digest,repository_path=str(relative) if relative else None,kind=kind if relative else 'local compiled artifact',availability='saved' if relative else 'local-build-only',unavailable_reason=None if relative else 'Compiled binary/library not committed; its recorded digest is bound, but file bytes require the original local build'))
    out.write_text(json.dumps(dict(schema='c-indicators-artifact-inventory-v1',ready_sha256=sha(ready),entries=entries),indent=2)+'\n');print(out)
if __name__=='__main__':main()
