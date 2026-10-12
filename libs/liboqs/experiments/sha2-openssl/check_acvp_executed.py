#!/usr/bin/env python3
"""Run upstream vectors_sig against every enabled pure SHA2 NIST ACVP case.

The argument mapping follows upstream tests/test_acvp_vectors.py at the pinned
liboqs revision. External verification uses a public-API adapter because the
upstream executable skips that path without ML-DSA enabled. Every subprocess
must emit a marker proving execution. No algorithm or RNG code is modified.
"""
import argparse, hashlib, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--vectors',type=Path,required=True)
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--public-verify',type=Path,required=True)
p.add_argument('--evidence',type=Path,required=True)
a=p.parse_args()
results=[]
counts={}
for kind in ('keyGen','sigGen','sigVer'):
 source=a.vectors/(kind+'.json')
 expected=next(v for v in json.loads((a.evidence/'acvp-vectors.json').read_text()) if v['kind']==kind)
 assert hashlib.sha256(source.read_bytes()).hexdigest()==expected['sha256']
 data=json.loads(source.read_text())
 for group in data['testGroups']:
  parameter=group['parameterSet']
  if not parameter.startswith('SLH-DSA-SHA2-'): continue
  if kind!='keyGen' and group['preHash']=='preHash': continue
  name=parameter.replace('-','_').upper().replace('SLH_DSA_','SLH_DSA_PURE_')
  for case in group['tests']:
   if kind=='keyGen':
    args=['keyGen',case['skSeed'],case['skPrf'],case['pkSeed'],case['pk'],case['sk']]
   elif kind=='sigGen':
    rnd=case['additionalRandomness'] if not group['deterministic'] else ''
    if group['signatureInterface']=='internal': args=['sigGen_int',case['sk'],case['message'],case['signature'],rnd]
    else: args=['sigGen_ext',case['sk'],case['message'],case['signature'],case['context'],rnd]
   else:
    passed='1' if case['testPassed'] else '0'
    if group['signatureInterface']=='internal': args=['sigVer_int',case['pk'],case['message'],case['signature'],passed]
    else: args=['sigVer_ext',case['pk'],case['message'],case['signature'],case['context'],passed]
   external_verify=kind=='sigVer' and group['signatureInterface']=='external'
   command=([str(a.public_verify),name]+args[1:]) if external_verify else [str(a.binary),name]+args
   marker='public_verify_executed: ' if external_verify else {'keyGen':'pk: ','sigGen':'signature: ','sigVer':'testPassed: '}[kind]
   r=subprocess.run(command,capture_output=True,text=True)
   executed=any(line.startswith(marker) for line in r.stdout.splitlines())
   results.append({'kind':kind,'parameter':parameter,'tgId':group['tgId'],'tcId':case['tcId'],'returncode':r.returncode,'execution_marker':executed,'interface':group.get('signatureInterface'),'adapter':'public_verify' if external_verify else 'upstream vectors_sig'})
   if r.returncode or not executed:
    (a.evidence/'acvp-failure.log').write_text(r.stdout+r.stderr)
    (a.evidence/'acvp-checked-execution.json').write_text(json.dumps({'complete':False,'cases':results},indent=2)+'\n')
    raise SystemExit(f'{kind} {parameter} tcId {case["tcId"]} failed')
   key=kind+' '+parameter;counts[key]=counts.get(key,0)+1
  print(kind,parameter,'group',group['tgId'],'passed',flush=True)
expected_keys={kind+' SLH-DSA-SHA2-'+param for kind in ('keyGen','sigGen','sigVer') for param in ('128f','128s','192f','192s','256f','256s')}
assert set(counts)==expected_keys and all(v>0 for v in counts.values())
assert len(results)==396 and len({(r['kind'],r['tgId'],r['tcId']) for r in results})==396
assert sum(r['adapter']=='public_verify' for r in results)==84
report={'complete':True,'command_binary':str(a.binary),'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'public_verify_binary':str(a.public_verify),'public_verify_sha256':hashlib.sha256(a.public_verify.read_bytes()).hexdigest(),'counts':counts,'total_cases':len(results),'cases':results}
(a.evidence/'acvp-checked-execution.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(counts,indent=2));print('total cases:',len(results))
