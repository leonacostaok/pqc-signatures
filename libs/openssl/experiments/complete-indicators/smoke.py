#!/usr/bin/env python3
"""Exercise every diagnostic mode before collection; these are not final results."""
import argparse, datetime, json, subprocess
from pathlib import Path
import collect

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    j=collect.checked_manifest(a.manifest.resolve());a.out.mkdir(parents=True,exist_ok=False)
    spec=next(s for s in j['parameters'] if s['parameter']=='SLH-DSA-SHA2-128f')
    report=dict(complete=False,kind='precollection diagnostic-mode smoke; not benchmark evidence',manifest_sha256=collect.sha(a.manifest),source_sha256=collect.sha(__file__),executed=[])
    for side in ['baseline','candidate']:
        for mode,op in [(m,o) for m in ['allocation','rss','stack-a5'] for o in range(3)]+[(m,2) for m in ['stack-5a','stack-control-a5','stack-control-5a']]:
            job=dict(parameter=spec['parameter'],op=op,side=side,mode=mode,key=1,fork=0)
            cmd=[j['binaries'][side],mode,spec['native_parameter'],spec['input'],spec['corpus'],str(op),'1']
            start=datetime.datetime.now(datetime.timezone.utc).isoformat();r=subprocess.run(cmd,capture_output=True,text=True)
            raw=a.out/(f'{len(report["executed"]):03d}.jsonl');raw.write_text(r.stdout);err=raw.with_suffix('.stderr');err.write_text(r.stderr)
            report['executed'].append(dict(job=job,command=cmd,started_at=start,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),returncode=r.returncode,raw_file=raw.name,raw_sha256=collect.sha(raw),stderr_file=err.name,stderr_sha256=collect.sha(err)))
            collect.write(a.out/'report.json',report);collect.need(r.returncode==0,'smoke process failed; raw retained')
            collect.validate([json.loads(line) for line in r.stdout.splitlines()],job,spec)
    collect.checked_manifest(a.manifest.resolve());report['complete']=True;collect.write(a.out/'report.json',report);print(a.out/'report.json')
if __name__=='__main__':main()
