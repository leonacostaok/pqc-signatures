#!/usr/bin/env python3
"""Build and exercise each documented fallback; stop at the first failure."""
import argparse, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--source',type=Path,required=True)
p.add_argument('--build',type=Path,required=True)
p.add_argument('--evidence',type=Path,required=True)
p.add_argument('--only',choices=['no-openssl','sha2-disabled','dlopen','no-deprecated'])
a=p.parse_args()
a.evidence.mkdir(parents=True,exist_ok=True)
configs={
 'no-openssl':['-DOQS_USE_OPENSSL=OFF'],
 'sha2-disabled':['-DOQS_USE_OPENSSL=ON','-DOQS_USE_SHA2_OPENSSL=OFF','-DOQS_USE_AES_OPENSSL=ON'],
 'dlopen':['-DOQS_DLOPEN_OPENSSL=ON'],
 'no-deprecated':['-DCMAKE_C_FLAGS=-DOPENSSL_NO_DEPRECATED'],
}
results=[]
for name,flags in configs.items():
 if a.only and name != a.only: continue
 build=a.build/name
 commands=[['cmake','-S',str(a.source),'-B',str(build),'-DCMAKE_BUILD_TYPE=Release','-DOQS_MINIMAL_BUILD=SIG_slh_dsa_pure_sha2_128f','-DOPENSSL_ROOT_DIR='+subprocess.check_output(['pkg-config','--variable=prefix','openssl'],text=True).strip()]+flags,
 ['cmake','--build',str(build),'--target','test_slh_dsa_sha2','test_sig','-j2'],
 [str(build/'tests/test_slh_dsa_sha2')],
 [str(build/'tests/test_sig'),'SLH_DSA_PURE_SHA2_128F']]
 for i,command in enumerate(commands):
  r=subprocess.run(command,capture_output=True,text=True)
  log=f'config-{name}-{i}.log'
  (a.evidence/log).write_text(r.stdout+r.stderr)
  results.append({'configuration':name,'command':command,'returncode':r.returncode,'log':log})
  (a.evidence/('config-checks'+('-'+a.only if a.only else '')+'.json')).write_text(json.dumps(results,indent=2)+'\n')
  if r.returncode: raise SystemExit(r.returncode)
 print(name+' passed',flush=True)
