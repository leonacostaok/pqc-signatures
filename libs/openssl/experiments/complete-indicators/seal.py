#!/usr/bin/env python3
"""Bind checked drivers to original builds, published source and collection code."""
import argparse, json, subprocess
from pathlib import Path
import collect

ROOT=Path(__file__).resolve().parents[4]
def git(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args],text=True).strip()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    manifest=args.manifest.resolve();j=collect.checked_manifest(manifest);collect.need(not args.out.exists(),'ready output already exists')
    j['preparation_manifest']=str(manifest);j['preparation_manifest_sha256']=collect.sha(manifest);j['sha256'][str(manifest)]=collect.sha(manifest)
    provider=j['provider']
    if provider=='openssl':
        repo=ROOT.parents[2]/'openssl';proof=ROOT/'results/openssl/experiments/sha512-prefix-final-gate.json';old=json.loads(proof.read_text())
        for side in ['baseline','candidate']:
            matches=[(path,h) for path,h in j['sha256'].items() if path.endswith('/'+side+'/libcrypto.a')]
            collect.need(len(matches)==1 and matches[0][1]==old['identities'][side]['libcrypto.a'],'changed frozen OpenSSL library')
        measured='cb722554afced3c3232104b15693c203734864cf'
        collect.need(git(repo,'rev-parse',j['published_commit']+'^{tree}')==git(repo,'rev-parse',measured+'^{tree}'),'signed OpenSSL differs from measured tree')
        runtime=['crypto/slh_dsa/slh_hash.c','crypto/slh_dsa/slh_dsa_hash_ctx.c','crypto/slh_dsa/slh_dsa_local.h']
    else:
        repo=ROOT.parent/'liboqs-performance/libs/liboqs/deps/liboqs';proof=ROOT/'libs/liboqs/experiments/sha2-openssl/evidence/final-paired/ready-manifest.json';old=json.loads(proof.read_text())
        for side in ['baseline','candidate']:
            matches=[(path,h) for path,h in j['sha256'].items() if path.endswith('/'+side+'/lib/liboqs.a')]
            collect.need(len(matches)==1 and old['files'].get(side+'/lib/liboqs.a')==matches[0][1],'changed frozen liboqs library')
        collect.need(git(repo,'rev-parse','HEAD')==j['baseline_commit'] and git(repo,'status','--porcelain','--untracked-files=no')=='','extended baseline source changed')
        measured='b14f1b616f938698ebc0bf8b75b3736c30e1502c'
        runtime=['src/sig/slh_dsa/slh_dsa_c/sha2_256.c','src/sig/slh_dsa/slh_dsa_c/sha2_512.c']
        for path in runtime:collect.need(git(repo,'rev-parse',measured+':'+path)==git(repo,'rev-parse',j['published_commit']+':'+path),'signed liboqs runtime differs from measured runtime')
        for suffix in ['configure','build']:
            path=ROOT/'results/liboqs/complete-indicators'/('baseline-extended-'+suffix+'.json')
            collect.need(json.loads(path.read_text())['returncode']==0,'extended build failed');j['sha256'][str(path)]=collect.sha(path)
    source=repo/'worktrees/signoff-20261012'
    collect.need(git(source,'rev-parse','HEAD')==j['published_commit'] and git(source,'status','--porcelain','--untracked-files=no')=='','signed source checkout changed')
    for path in runtime:j['sha256'][str(source/path)]=collect.sha(source/path)
    j['sha256'][str(proof)]=collect.sha(proof)
    smoke=ROOT/'results'/provider/'complete-indicators/resource-smoke/report.json'
    smoke_report=json.loads(smoke.read_text())
    collect.need(smoke_report['complete'] is True and len(smoke_report['executed'])==24,'incomplete resource-mode smoke')
    for record in smoke_report['executed']:
        collect.need(record['returncode']==0,'failed resource-mode smoke')
        for field in ['raw','stderr']:
            path=smoke.parent/record[field+'_file'];collect.need(collect.sha(path)==record[field+'_sha256'],'changed smoke evidence');j['sha256'][str(path)]=collect.sha(path)
    j['sha256'][str(smoke)]=collect.sha(smoke)
    j['sha256'][str(Path(__file__).with_name('smoke.py').resolve())]=collect.sha(Path(__file__).with_name('smoke.py'))
    for path in [Path(__file__).resolve(),Path(__file__).with_name('collect.py').resolve()]:j['sha256'][str(path)]=collect.sha(path)
    j['source_binding']=dict(baseline=j['baseline_commit'],published=j['published_commit'],measured_candidate=measured,frozen_proof=str(proof),published_runtime_matches_measured=True)
    j['protocol']=dict(baseline_timing='3 fresh processes per cell; 10 distinct fixture keys repeated across processes; one disjoint warmup; mean of all 30 calls; no changed algorithm path and no candidate timing.',resources='4 matched distinct keys, fresh process per side/cell/key. Side order AB,BA,BA,AB. Allocation warmed; RSS cold and isolated from painted stack; a5 stack diagnostic warmed plus separate no-op/5a checks.',wall_unit='ns/op',rss_unit='bytes: Darwin getrusage ru_maxrss',allocation_unit='requested bytes/call through OpenSSL/OQS allocator hooks',stack_unit='bytes of observed overwritten dedicated-thread stack, including startup/exit; not reserved frame or exact peak',caveats=['Input fixture loading/key import/caller-owned output buffers outside operation.','OQS_SIG_new/free inside core; OpenSSL EVP operation context creation/free inside core.','Returned OpenSSL key retained at operation return, then freed for net-live accounting.','Unmeasured raw zero fields must become null in summaries.','Resource diagnostics provide no timing comparison.'])
    collect.write(args.out,j);print(args.out)
if __name__=='__main__':main()
