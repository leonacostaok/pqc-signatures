#!/usr/bin/env python3
"""Build two untimed lifecycle probes against existing sealed static libraries."""
import argparse, hashlib, json, subprocess
from pathlib import Path

PARAMETERS=['SLH-DSA-'+kind+'-'+bits+'f' for kind in ['SHA2','SHAKE'] for bits in ['128','192','256']]
def need(value,message):
    if not value: raise ValueError(message)
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def validate(rows,candidate):
    expected=[]
    for parameter in PARAMETERS:
        n=int(parameter.split('-')[-1][:3])//8
        count=4 if 'SHAKE' in parameter or (candidate and n>16) else 3
        for action in ['new-use-free','dup-use-after-source-free']:
            expected.append((parameter,action,0))
            expected.extend((parameter,'new-oom' if action=='new-use-free' else 'dup-oom',i) for i in range(1,count+1))
    need([(r['parameter'],r['action'],r['fail_at']) for r in rows]==expected,'missing/duplicate/reordered lifecycle cases')
    for row in rows:
        for key,value in row.items():
            if key not in ['parameter','action','output_hex']:need(type(value)is int and value>=0,'invalid counter '+key)
        need(row['net_live_bytes']==0 and row['allocations']==row['frees'],'allocation leak')
        need(row['failures']==(1 if row['fail_at'] else 0),'failure injection not exercised')
        if row['fail_at']:
            # Some existing SHAKE paths try a second allocation before checking
            # the first result; all successful later allocations must be freed.
            need(row['attempts']>=row['fail_at'] and row['allocations']==row['attempts']-1,'wrong injected failure ordinal')
            need(row['output_hex']=='' and row['retained_bytes']==0,'unexpected failed-operation output')
        else:
            n=int(row['parameter'].split('-')[-1][:3])//8
            count=4 if 'SHAKE' in row['parameter'] or (candidate and n>16) else 3
            need(row['attempts']==row['allocations']==count,'unexpected successful allocation count')
            need(len(row['output_hex'])==6*n,'output size')
            need(len(bytes.fromhex(row['output_hex']))==3*n,'invalid output encoding')
            need(row['cleared_allocations']==row['allocations']-1,'uncleared cache/scratch success path')
            need(row['peak_live_bytes']==row['retained_bytes']==row['requested_bytes'],'unexpected lifecycle retained accounting')
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['baseline-source','candidate-source','sealed-build','out']:p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    probe=Path(__file__).with_name('ctx-lifecycle.c').resolve();report={'probe_sha256':sha(probe),'variants':{}}
    for side,source in [('baseline',args.baseline_source),('candidate',args.candidate_source)]:
        build=args.sealed_build/side;binary=args.out/(side+'-probe')
        command=['cc','-O2','-Wall','-Wextra']+(['-DCACHED_SHA512'] if side=='candidate' else [])+['-I'+str(build/'include'),'-I'+str(source/'include'),'-I'+str(source),str(probe),str(build/'libcrypto.a'),'-lpthread','-o',str(binary)]
        compiled=subprocess.run(command,capture_output=True,text=True)
        (args.out/(side+'-build.json')).write_text(json.dumps(dict(command=command,returncode=compiled.returncode,stdout=compiled.stdout,stderr=compiled.stderr),indent=2)+'\n');need(compiled.returncode==0,'compile failed')
        result=subprocess.run([str(binary)],capture_output=True,text=True)
        (args.out/(side+'.jsonl')).write_text(result.stdout)
        (args.out/(side+'-run.json')).write_text(json.dumps(dict(command=[str(binary)],returncode=result.returncode,stderr=result.stderr),indent=2)+'\n');need(result.returncode==0,'probe failed')
        rows=validate([json.loads(line) for line in result.stdout.splitlines()],side=='candidate')
        report['variants'][side]=dict(binary_sha256=sha(binary),libcrypto_sha256=sha(build/'libcrypto.a'),rows=len(rows),outputs={(r['parameter']+'/'+r['action']):r['output_hex'] for r in rows if not r['fail_at']})
    need(report['variants']['baseline']['outputs']==report['variants']['candidate']['outputs'],'baseline/candidate output mismatch')
    report['complete']=True;(args.out/'verified.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
