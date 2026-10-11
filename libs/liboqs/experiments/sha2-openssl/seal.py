#!/usr/bin/env python3
"""Seal tested inputs and binaries so the timing runner rejects stale builds."""
import argparse, hashlib, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--baseline',type=Path,required=True)
p.add_argument('--candidate',type=Path,required=True)
p.add_argument('--build',type=Path,required=True)
p.add_argument('--evidence',type=Path,required=True)
a=p.parse_args()
def run(args,cwd=None): return subprocess.check_output(args,cwd=cwd,text=True).strip()
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
assert run(['git','rev-parse','HEAD'],a.baseline)=='fd44469daeffe6b28f031f54f9bb66cbae69a572'
assert not run(['git','status','--porcelain','--untracked-files=no'],a.baseline)
subprocess.run(['git','merge-base','--is-ancestor',run(['git','rev-parse','HEAD'],a.baseline),'HEAD'],cwd=a.candidate,check=True)
files={}
for label in ('baseline','candidate'):
 for rel in ('corpus','lib/liboqs.a','CMakeCache.txt','src/sig/slh_dsa/CMakeFiles/slh_dsa_c.dir/flags.make'):
  files[label+'/'+rel]=digest(a.build/label/rel)
 (a.evidence/f'{label}-sha2-compiler-flags.txt').write_text((a.build/label/'src/sig/slh_dsa/CMakeFiles/slh_dsa_c.dir/flags.make').read_text())
source_files={}
for rel in run(['git','ls-files','src/sig/slh_dsa','src/common','CMakeLists.txt','.CMake'],a.candidate).splitlines():
 source_files[rel]=digest(a.candidate/rel)
# Record the upstream regression test and patch used by the importer as well.
for rel in ('tests/test_slh_dsa_sha2.c','tests/test_hash.py','tests/CMakeLists.txt','src/sig/slh_dsa/patches/sha2_openssl.patch'):
 source_files[rel]=digest(a.candidate/rel)
openssl=Path(run(['pkg-config','--variable=prefix','openssl']))
crypto=openssl/'lib/libcrypto.3.dylib'
experiment_files={str(f):digest(f) for f in sorted(Path(__file__).parent.glob('*')) if f.is_file() and f.suffix in ('.c','.py','.patch')}
manifest={'experiment_files':experiment_files,'baseline_commit':run(['git','rev-parse','HEAD'],a.baseline),'candidate_source':str(a.candidate),'candidate_commit':run(['git','rev-parse','HEAD'],a.candidate),'files':files,'source_files':source_files,'crypto_library':str(crypto),'crypto_sha256':digest(crypto),'openssl':run([str(openssl/'bin/openssl'),'version','-a']),'compiler':run(['cc','--version']),'host':run(['sysctl','machdep.cpu.brand_string','hw.physicalcpu','hw.memsize','kern.osversion'])}
(a.evidence/'ready-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('sealed',len(files),'build artifacts and',len(source_files),'source files')
