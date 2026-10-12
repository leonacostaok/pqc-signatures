#!/usr/bin/env python3
"""Run all shared SHA2 SLH cases through native APIs with execution markers."""
import argparse, gzip, hashlib, json, subprocess
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--validation',type=Path,required=True)
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--public-verify',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
raw=a.validation.read_bytes();data=json.loads(gzip.decompress(raw))
selected=[case for case in data['cases'] if case['param'].startswith('SLH-DSA-SHA2-')]
assert selected
expected_params={'SLH-DSA-SHA2-'+param for param in ('128f','128s','192f','192s','256f','256s')}
assert {case['param'] for case in selected}==expected_params
assert len(selected)==216 and len({case['id'] for case in selected})==216
results=[];counts={}
for case in selected:
 name=case['param'].replace('-','_').upper().replace('SLH_DSA_','SLH_DSA_PURE_')
 if case['kind']=='keygen':
  seed=case['seed_hex']; n=len(seed)//3
  assert n in (32,48,64) and len(seed)==3*n
  args=['keyGen',seed[:n],seed[n:2*n],seed[2*n:],case['expect_pk_hex'],case['expect_sk_hex']]
 elif case['kind']=='siggen':
  args=['sigGen_ext',case['sk_hex'],case['msg_hex'],case['expect_sig_hex'],case.get('ctx_hex',''),'']
 elif case['kind']=='sigver':
  args=['sigVer_ext',case['pk_hex'],case['msg_hex'],case['sig_hex'],case.get('ctx_hex',''),'1' if case['expect'] else '0']
 else: raise ValueError('unsupported case kind: '+case['kind'])
 external_verify=case['kind']=='sigver'
 command=([str(a.public_verify),name]+args[1:]) if external_verify else [str(a.binary),name]+args
 marker='public_verify_executed: ' if external_verify else {'keygen':'pk: ','siggen':'signature: '}[case['kind']]
 result=subprocess.run(command,capture_output=True,text=True)
 executed=any(line.startswith(marker) for line in result.stdout.splitlines())
 results.append({'id':case['id'],'parameter':case['param'],'kind':case['kind'],'source':case['source'],'reason':case.get('reason'),'returncode':result.returncode,'execution_marker':executed})
 counts[case['param']+'/'+case['kind']]=counts.get(case['param']+'/'+case['kind'],0)+1
 if result.returncode or not executed:
  a.output.with_suffix('.failure.log').write_text(result.stdout+result.stderr)
  a.output.write_text(json.dumps({'complete':False,'cases':results},indent=2)+'\n')
  raise SystemExit('shared case failed: '+case['id'])
report={'complete':True,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'public_verify_sha256':hashlib.sha256(a.public_verify.read_bytes()).hexdigest(),'validation_sha256':hashlib.sha256(raw).hexdigest(),'validation_path':str(a.validation),'selected_cases':len(selected),'total_shared_cases':len(data['cases']),'scope':'All six pure SHA2 SLH parameter sets; other algorithms outside this change are not selected.','counts':counts,'cases':results}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(counts,indent=2));print('all selected shared cases passed:',len(selected))
