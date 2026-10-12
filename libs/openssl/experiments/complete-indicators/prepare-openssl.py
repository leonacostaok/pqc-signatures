#!/usr/bin/env python3
"""Supply OpenSSL's source headers in addition to its generated build headers."""
import hashlib, json, sys
from pathlib import Path
import prepare

original=prepare.run
source=prepare.ROOT.parents[2]/'openssl/worktrees/slh-sha512-baseline'
def run(command,path):
    if command[0]=='cc' and '-o' in command:
        command=list(command);command.insert(5,'-I'+str(source/'include'))
    return original(command,path)
prepare.run=run
if __name__=='__main__':
    prepare.main()
    out=Path(sys.argv[sys.argv.index('--out')+1]).resolve()
    manifest=json.loads((out/'manifest.json').read_text())
    manifest['parent_manifest_sha256']=prepare.sha(out/'manifest.json')
    manifest['sha256'][str(Path(__file__).resolve())]=prepare.sha(__file__)
    manifest['source_header_checkout']=str(source)
    for p in (source/'include').rglob('*.h'):
        manifest['sha256'][str(p)]=prepare.sha(p)
    manifest['sha256'][str(out/'compiler.json')]=prepare.sha(out/'compiler.json')
    prepare.dump(out/'manifest-ready.json',manifest)
    print(out/'manifest-ready.json')
