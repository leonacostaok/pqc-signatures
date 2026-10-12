"""Independently validate the archived ten-key measurements without importing run.py."""
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct
import subprocess

HERE = Path(__file__).resolve().parent
E = HERE/'evidence'
ROOT = HERE.parents[3]
PARAMS = ['SLH_DSA_PURE_SHA2_'+s for s in ['128F','128S','192F','192S','256F','256S']]
N = dict(zip(PARAMS,[16,16,24,24,32,32]))
SIGLEN = dict(zip(PARAMS,[17088,7856,35664,16224,49856,29792]))


def need(ok, why):
    if not ok: raise RuntimeError(why)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ready=json.loads((E/'ready.json').read_text()); identity=ready['identity']
    need(ready['complete'] is True,'incomplete preparation')
    for name,digest in identity['sources'].items(): need(sha(HERE/name)==digest,'experiment source changed')
    for side,digest in identity['drivers'].items(): need(sha(ROOT/'libs/liboqs/build/ten-new-keys'/side/'driver')==digest,'driver changed')
    oldpath=HERE.parent/'sha2-openssl/evidence/final-paired/ready-manifest.json'
    need(sha(oldpath)==identity['original_seal_sha256'],'original seal changed')
    old=json.loads(oldpath.read_text()); checked=0
    need(old['files']==identity['original_build_hashes'],'original build hash mapping')
    for name,digest in old['files'].items():
        need(sha(ROOT/'libs/liboqs/build/sha2-openssl'/name)==digest,'original build changed');checked+=1
    for name,digest in old['experiment_files'].items(): need(sha(name)==digest,'original experiment changed');checked+=1
    for name,digest in old['source_files'].items():
        need(sha(Path(old['candidate_source'])/name)==digest,'production source changed');checked+=1
    need(checked==identity['original_sealed_files_verified']==303,'original manifest entry coverage')
    need(sha(identity['libcrypto_path'])==identity['libcrypto_sha256'],'OpenSSL backend changed')
    need(str(Path('/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib').resolve())==identity['libcrypto_path'],'linked backend path changed')
    upstream=Path(old['candidate_source'])
    need(subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip()==identity['candidate_commit'],'production commit changed')
    subprocess.run(['git','-C',str(upstream),'diff','--quiet','HEAD'],check=True)
    need(sha(E/'inputs.bin')==identity['input_sha256'],'input corpus changed')
    need(sha(E/'smoke.json')==ready['smoke_sha256'],'smoke proof changed')
    metadata=json.loads((E/'inputs.json').read_text())
    need(metadata['sha256']==identity['input_sha256'],'input metadata binding')
    need(len(metadata['cases'])==66 and len({r['seed_sha256'] for r in metadata['cases']})==66,'seed coverage')
    corpus=bytearray(b'OQSTENK1'); seeds={}; meta_index=0
    for p in PARAMS:
        for key in range(-1,10):
            m=metadata['cases'][meta_index];meta_index+=1
            need((m['parameter'],m['key'])==(p,key),'input order')
            label='final/'+p+'/'+('warmup' if key==-1 else str(key))
            need(m['label']==label,'unexpected seed domain')
            lengths=(31,3) if key==-1 else ([0,32,256,4096,64,1024,7,513,2048,8192][key],[0,1,17,255,0,1,17,255,32,128][key])
            need((m['message_bytes'],m['context_bytes'])==lengths,'unexpected input sizes')
            def derive(kind,length):
                prefix=('pqc-ten-new-keys-v1/liboqs/'+label+'/'+kind+'/').encode()
                return b''.join(hashlib.sha256(prefix+str(i).encode()).digest() for i in range((length+31)//32))[:length]
            seed=derive('seed',3*N[p]);rnd=derive('sign-entropy',N[p]);seeds[p,key]=seed
            need(hashlib.sha256(seed).hexdigest()==m['seed_sha256'],'seed mismatch')
            need(hashlib.sha256(rnd).hexdigest()==m['signing_entropy_sha256'],'signing entropy mismatch')
            corpus.extend(struct.pack('<II',m['message_bytes'],m['context_bytes'])+seed+rnd+derive('message',m['message_bytes'])+derive('context',m['context_bytes']))
    need(bytes(corpus)==(E/'inputs.bin').read_bytes(),'input derivation mismatch')
    expected=[(p,k) for p in PARAMS for k in range(10)]; variants={}; all_artifacts=[]
    for side in ('candidate','baseline'):
        folder=E/('final-'+side); result=json.loads((folder/'result.json').read_text())
        need(result['complete'] is True and result['variant']==side,'incomplete/wrong side')
        need(result['ready_sha256']==sha(E/'ready.json'),'ready binding')
        need(result['raw_sha256']==sha(folder/'stdout.jsonl'),'raw output binding')
        need(result['artifact_sha256']==sha(folder/'outputs.bin'),'artifact binding')
        rows=[json.loads(x) for x in (folder/'stdout.jsonl').read_text().splitlines()]
        need(rows==result['rows'] and [(r['parameter'],r['key']) for r in rows]==expected,'raw row coverage')
        command=json.loads((folder/'command.json').read_text()); status=json.loads((folder/'status.json').read_text())
        need(status['returncode']==0,'child failed')
        need(command['command']==[str(ROOT/'libs/liboqs/build/ten-new-keys'/side/'driver'),str(E/'inputs.bin'),str(folder/'outputs.bin'),'10'],'executed command binding')
        need(command['started_utc']==result['started_utc'] and status['finished_utc']==result['finished_utc'],'phase timestamp binding')
        artifacts=(folder/'outputs.bin').read_bytes();all_artifacts.append(artifacts)
        need(artifacts[:8]==b'OQSTENO1','artifact header');offset=8;pk_set=set();digests=[]
        for r in rows:
            p,k=r['parameter'],r['key'];n=N[p]
            need((r['message_bytes'],r['context_bytes'])==([0,32,256,4096,64,1024,7,513,2048,8192][k],[0,1,17,255,0,1,17,255,32,128][k]),'raw workload size')
            need(r['valid'] is True and r['tamper_rejected'] is True,'failed crypto check')
            need(r['rng_keygen_bytes']==3*n and r['rng_sign_bytes']==n,'wrong entropy work')
            for op in ('keygen','sign','verify'):
                for clock in ('wall','cpu'):
                    value=r[op+'_'+clock+'_ns'];need(type(value) is int and value>0,'invalid time')
            lengths=struct.unpack_from('<III',artifacts,offset);offset+=12
            need(lengths==(2*n,4*n,SIGLEN[p]),'artifact length')
            output={};rowhash={'parameter':p,'key':k}
            for field,length in zip(('pk','sk','signature'),lengths):
                output[field]=artifacts[offset:offset+length];offset+=length
                need(len(output[field])==length,'truncated artifact')
                rowhash[field+'_sha256']=hashlib.sha256(output[field]).hexdigest()
            need(output['sk'][:3*n]==seeds[p,k] and output['pk']==output['sk'][2*n:],'native keygen seed/encoding')
            pk_set.add(output['pk']);digests.append(rowhash)
        need(offset==len(artifacts) and len(pk_set)==60,'artifact coverage/distinct keys')
        need(digests==result['output_hashes'],'output digest report')
        variants[side]={'result':result,'rows':{(r['parameter'],r['key']):r for r in rows}}
    need(all_artifacts[0]==all_artifacts[1],'cross-variant key/signature bytes differ')
    need(variants['candidate']['result']['finished_utc']<variants['baseline']['result']['started_utc'],'candidate-first ordering')
    saved=json.loads((E/'summary.json').read_text())
    saved_rows={(r['parameter'],r['operation']):r for r in saved['summary']}
    need(saved['complete'] is True and len(saved_rows)==len(saved['summary'])==18,'summary coverage')
    need(saved['keys_per_parameter']==10 and saved['matched_keys_signatures'] is True,'summary key coverage')
    for side in variants:
        for phase in ('started','finished'):
            need(saved[side+'_'+phase+'_utc']==variants[side]['result'][phase+'_utc'],'summary phase binding')
    summaries=[]
    for p in PARAMS:
        for op in ('keygen','sign','verify'):
            row={'parameter':p,'operation':op}
            for clock in ('wall','cpu'):
                key=op+'_'+clock+'_ns'
                values={s:[variants[s]['rows'][p,k][key] for k in range(10)] for s in variants}
                ratios=[b/c for b,c in zip(values['baseline'],values['candidate'])]
                expected_values={clock+'_baseline_total_ns':sum(values['baseline']),clock+'_candidate_total_ns':sum(values['candidate']),
                    clock+'_ratio_of_total_times':sum(values['baseline'])/sum(values['candidate']),clock+'_median_paired_speedup':statistics.median(ratios),
                    clock+'_min_key_speedup':min(ratios),clock+'_max_key_speedup':max(ratios),clock+'_key_losses':sum(v<1 for v in ratios)}
                for name,value in expected_values.items(): need(math.isclose(value,saved_rows[p,op][name],rel_tol=1e-12),'summary arithmetic')
                need(ratios==saved_rows[p,op][clock+'_per_key_ratios'],'per-key ratios')
                row.update(expected_values)
            summaries.append(row)
    report={'complete':True,'original_manifest_entries_verified':checked,'original_manifest_and_entries_verified':checked+1,'distinct_measured_keys':60,'distinct_disjoint_warmup_seeds':6,
            'matched_operation_pairs':180,'summaries_checked':18,'exact_key_signature_bytes_equal':True,'candidate_first':True,
            'inputs_sha256':sha(E/'inputs.bin'),'ready_sha256':sha(E/'ready.json'),'summary_sha256':sha(E/'summary.json'),
            'audit_script_sha256':sha(__file__),'result_sha256':{s:sha(E/('final-'+s)/'result.json') for s in variants},'summaries':summaries}
    target=E/'independent-check.json'
    if target.exists():
        need(json.loads(target.read_text())==report,'existing independent report differs')
    else:
        with target.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print('PASS: original seal and 303 listed files; 60 distinct matched keys; 180 wall/CPU operation pairs; 18 summary cells; exact output and source bindings.')


if __name__=='__main__':main()
