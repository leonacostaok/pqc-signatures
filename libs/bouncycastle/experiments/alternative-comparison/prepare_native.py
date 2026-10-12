#!/usr/bin/env python3
"""Prepare pinned native correctness tests; no performance measurements."""
import hashlib
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

if not __debug__:
    raise SystemExit('optimized Python is unsupported')

ROOT = Path(__file__).resolve().parents[4]
BUILD = ROOT / 'libs/bouncycastle/build/alternative-comparison/native'
OUT = ROOT / 'results/bouncycastle/alternative-comparison/native'
PIN = 'c314b9cdffa3958a0eff5344f8fdcdb0181ed830'
DATA_PIN = '3c385e9f4c0b12ce5a86d2b29a17fb3b68dd4e1a'
UPSTREAM = Path(sys.argv[1]).resolve()
JAVA = Path(sys.argv[2]).resolve()
BUILD.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)

def sha(b):
    return hashlib.sha256(b).hexdigest()

tree = json.load(urllib.request.urlopen('https://api.github.com/repos/bcgit/bc-test-data/git/trees/' + DATA_PIN + '?recursive=1'))
assert not tree.get('truncated')
records = []
for entry in tree['tree']:
    path = entry['path']
    if entry['type'] != 'blob' or not path.startswith(('pqc/crypto/mldsa/', 'pqc/crypto/dilithium/acvp/', 'crypto/wycheproof/mldsa_')):
        continue
    target = BUILD / 'test-data' / path
    if not target.exists():
        data = urllib.request.urlopen('https://raw.githubusercontent.com/bcgit/bc-test-data/' + DATA_PIN + '/' + path).read()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    data = target.read_bytes()
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == entry['sha']
    records.append({'path': path, 'git_blob': entry['sha'], 'bytes': len(data), 'sha256': sha(data)})
(OUT / 'test-data.json').write_text(json.dumps({'revision': DATA_PIN, 'upstream': 'https://github.com/bcgit/bc-test-data', 'files': records}, indent=2) + '\n')

# Export the exact pin rather than compile the canonical checkout's working tree.
archive = subprocess.check_output(['git', '-C', str(UPSTREAM), 'archive', PIN, 'core/src/main/java', 'core/src/test/java'])
(BUILD / 'source.tar').write_bytes(archive)
source = BUILD / 'source'
source.mkdir(exist_ok=True)
subprocess.run(['tar', '-xf', str(BUILD / 'source.tar'), '-C', str(source)], check=True)
classes = BUILD / 'classes'
classes.mkdir(exist_ok=True)
junit = UPSTREAM / 'libs/junit-4.13.2.jar'
hamcrest = Path(sys.argv[3]).resolve()
tests = source / 'core/src/test/java'
cmd = [str(JAVA.with_name('javac')), '-J-XX:ActiveProcessorCount=2', '--release', '8', '-cp', str(junit), '-sourcepath', str(source / 'core/src/main/java') + ':' + str(tests), '-d', str(classes)]
cmd += [str(tests / ('org/bouncycastle/pqc/crypto/test/' + name + '.java')) for name in ['MLDSATest', 'MLDSAWycheproofTest', 'SLHDSATest']]
p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
(OUT / 'compile.txt').write_text(p.stdout)
(OUT / 'compile-command.json').write_text(json.dumps(cmd, indent=2) + '\n')
if p.returncode:
    raise SystemExit(p.returncode)
manifest = {'pin': PIN, 'source_archive_sha256': sha(archive), 'java': str(JAVA), 'java_sha256': sha(JAVA.read_bytes()), 'classes': str(classes), 'test_data': str(BUILD / 'test-data'), 'junit': str(junit), 'hamcrest': str(hamcrest), 'dependencies': {str(p): sha(p.read_bytes()) for p in [junit, hamcrest]}, 'class_hashes': {str(p.relative_to(classes)): sha(p.read_bytes()) for p in sorted(classes.rglob('*.class'))}, 'test_source_hashes': {str(p.relative_to(tests)): sha(p.read_bytes()) for p in sorted(tests.rglob('*.java'))}}
(OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print('Prepared native suites and', len(records), 'test-data files')
